"""
Simulation Scheduler - Red vs Blue Round Manager (v2 — Enhanced)
=================================================================
Manages attack-defense simulation rounds with topology, commentary,
concurrent execution, and learning feedback.
"""

import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from django.utils import timezone

from blue_team.agent import BlueTeamAgent
from core.commentary import BattleCommentator
from core.event_bus import Event, EventType, get_event_bus
from core.models import AgentAction
from core.safety import get_safety_module
from red_team.agent import RedTeamAgent
from simulation.models import SimulationConfig, SimulationRound
from simulation.network import NetworkTopology, TOPOLOGY_TEMPLATES

logger = logging.getLogger("simulation")


class SimulationScheduler:
    """
    Manages Red vs Blue simulation rounds (v2).
    Now with network topology, battle commentary, concurrent execution,
    and cross-round learning.
    """

    def __init__(self):
        self.event_bus = get_event_bus()
        self.safety = get_safety_module()
        self.commentator = BattleCommentator(use_llm=True)

    def create_simulation(
        self,
        name: str,
        target_ips: list,
        max_rounds: int = 10,
        round_duration: int = 300,
        topology_template: str = None,
    ) -> SimulationConfig:
        """Create a new simulation configuration."""
        config = {
            "topology_template": topology_template or "corporate",
        }

        sim = SimulationConfig.objects.create(
            name=name,
            target_ips=target_ips,
            max_rounds=max_rounds,
            round_duration_seconds=round_duration,
            red_team_config=config,
            blue_team_config=config,
        )
        logger.info(f"Simulation created: {name} ({max_rounds} rounds, targets: {target_ips})")
        return sim

    def run_simulation(self, simulation_id: str, concurrent: bool = False) -> SimulationConfig:
        """
        Run a full simulation.

        Args:
            simulation_id: UUID of the simulation to run.
            concurrent: If True, Red and Blue teams operate simultaneously.
        """
        sim = SimulationConfig.objects.get(id=simulation_id)
        sim.status = SimulationConfig.Status.RUNNING
        sim.started_at = timezone.now()
        sim.save()

        self.event_bus.publish(Event(
            event_type=EventType.SIMULATION_STARTED,
            source="simulation",
            data={"simulation_id": str(sim.id), "name": sim.name},
        ))

        # v2: Setup topology
        topology_name = sim.red_team_config.get("topology_template", "corporate")
        topology_factory = TOPOLOGY_TEMPLATES.get(topology_name)
        topology = topology_factory() if topology_factory else None

        # v2: Initialize agents with topology and learning
        red_agent = RedTeamAgent()
        blue_agent = BlueTeamAgent()
        if topology:
            red_agent.set_topology(topology)
            blue_agent.set_topology(topology)

        try:
            for round_num in range(1, sim.max_rounds + 1):
                if self.safety.is_active:
                    logger.warning("Kill switch active, stopping simulation")
                    break

                target_ip = sim.target_ips[(round_num - 1) % len(sim.target_ips)]

                if concurrent:
                    round_result = self._run_round_concurrent(
                        sim, round_num, target_ip, red_agent, blue_agent
                    )
                else:
                    round_result = self._run_round(
                        sim, round_num, target_ip, red_agent, blue_agent
                    )

                sim.total_rounds_completed = round_num
                sim.save()

                # v2: Generate round commentary summary
                try:
                    round_data = {
                        "round_number": round_num,
                        "target_ip": target_ip,
                        "red_team_exploits_attempted": round_result.red_team_exploits_attempted,
                        "red_team_exploits_succeeded": round_result.red_team_exploits_succeeded,
                        "blue_team_alerts": round_result.blue_team_alerts,
                        "blue_team_blocks": round_result.blue_team_blocks,
                        "red_team_score": round_result.red_team_score,
                        "blue_team_score": round_result.blue_team_score,
                    }
                    self.commentator.generate_round_summary(round_data)
                except Exception as e:
                    logger.debug(f"Round commentary failed: {e}")

                if round_result.status == SimulationRound.Status.FAILED:
                    logger.warning(f"Round {round_num} failed, continuing...")

            sim.status = SimulationConfig.Status.COMPLETED
            sim.completed_at = timezone.now()
            sim.save()

            # v2: Persist agent learning
            red_agent.end_round()
            blue_agent.rl_policy.save_policy()
            blue_agent.memory.decay_memories()

        except Exception as e:
            logger.error(f"Simulation failed: {e}", exc_info=True)
            sim.status = SimulationConfig.Status.FAILED
            sim.save()

        self.event_bus.publish(Event(
            event_type=EventType.SIMULATION_ENDED,
            source="simulation",
            data={
                "simulation_id": str(sim.id),
                "rounds_completed": sim.total_rounds_completed,
                "status": sim.status,
            },
        ))

        return sim

    def _run_round(
        self,
        sim: SimulationConfig,
        round_number: int,
        target_ip: str,
        red_agent: RedTeamAgent,
        blue_agent: BlueTeamAgent,
    ) -> SimulationRound:
        """Execute a single simulation round (sequential)."""
        round_obj = SimulationRound.objects.create(
            simulation=sim,
            round_number=round_number,
            target_ip=target_ip,
            status=SimulationRound.Status.PENDING,
        )

        self.safety.reset_round(str(round_obj.id))

        self.event_bus.publish(Event(
            event_type=EventType.ROUND_STARTED,
            source="simulation",
            data={"round_id": str(round_obj.id), "round_number": round_number, "target": target_ip},
        ))

        round_obj.started_at = timezone.now()
        start_time = time.time()

        try:
            # Phase 1: Red Team attacks
            round_obj.status = SimulationRound.Status.RED_TEAM
            round_obj.save()

            logger.info(f"Round {round_number}: Red Team attacking {target_ip}")
            red_result = red_agent.run_full_attack(target_ip, round_id=round_obj.id)

            round_obj.red_team_scans = 1 if red_result.get("scan") else 0
            round_obj.red_team_vulns_found = len(red_result.get("vulnerabilities", []))
            round_obj.red_team_exploits_attempted = len(red_result.get("exploit_attempts", []))
            round_obj.red_team_exploits_succeeded = sum(
                1 for e in red_result.get("exploit_attempts", []) if e.get("success")
            )

            # Phase 2: Blue Team defends
            round_obj.status = SimulationRound.Status.BLUE_TEAM
            round_obj.save()

            logger.info(f"Round {round_number}: Blue Team defending")
            blue_result = blue_agent.monitor_and_defend(round_id=round_obj.id)

            round_obj.blue_team_alerts = blue_result.get("alerts_generated", 0)
            round_obj.blue_team_detections = blue_result.get("anomalies_detected", 0) + blue_result.get("signatures_matched", 0)
            round_obj.blue_team_blocks = len(blue_result.get("blocked_ips", []))

            # Phase 3: Score the round
            round_obj.red_team_score = self._score_red_team(round_obj)
            round_obj.blue_team_score = self._score_blue_team(round_obj)

            # Phase 4: Blue Team adapts
            blue_agent.adapt(round_id=round_obj.id)

            # v2: Red Team end-of-round learning
            red_agent.end_round()

            round_obj.status = SimulationRound.Status.COMPLETED
            round_obj.completed_at = timezone.now()
            round_obj.duration_seconds = time.time() - start_time
            round_obj.save()

            logger.info(
                f"Round {round_number} complete: "
                f"Red={round_obj.red_team_score:.1f} Blue={round_obj.blue_team_score:.1f}"
            )

        except Exception as e:
            logger.error(f"Round {round_number} failed: {e}", exc_info=True)
            round_obj.status = SimulationRound.Status.FAILED
            round_obj.duration_seconds = time.time() - start_time
            round_obj.save()

        self.event_bus.publish(Event(
            event_type=EventType.ROUND_ENDED,
            source="simulation",
            data={
                "round_id": str(round_obj.id),
                "red_score": round_obj.red_team_score,
                "blue_score": round_obj.blue_team_score,
            },
        ))

        return round_obj

    def _run_round_concurrent(
        self,
        sim: SimulationConfig,
        round_number: int,
        target_ip: str,
        red_agent: RedTeamAgent,
        blue_agent: BlueTeamAgent,
    ) -> SimulationRound:
        """
        Execute a simulation round with concurrent Red/Blue execution.
        Both teams operate simultaneously for more realistic battles.
        """
        round_obj = SimulationRound.objects.create(
            simulation=sim,
            round_number=round_number,
            target_ip=target_ip,
            status=SimulationRound.Status.PENDING,
        )

        self.safety.reset_round(str(round_obj.id))

        self.event_bus.publish(Event(
            event_type=EventType.ROUND_STARTED,
            source="simulation",
            data={"round_id": str(round_obj.id), "round_number": round_number, "target": target_ip},
        ))

        round_obj.started_at = timezone.now()
        start_time = time.time()

        red_result = {}
        blue_result = {}

        try:
            round_obj.status = SimulationRound.Status.RED_TEAM
            round_obj.save()

            # Run both teams concurrently
            with ThreadPoolExecutor(max_workers=2) as executor:
                red_future = executor.submit(
                    red_agent.run_full_attack, target_ip, round_obj.id
                )
                blue_future = executor.submit(
                    blue_agent.monitor_and_defend, round_obj.id
                )

                red_result = red_future.result(timeout=sim.round_duration_seconds)
                blue_result = blue_future.result(timeout=sim.round_duration_seconds)

            # Update round with results
            round_obj.red_team_scans = 1 if red_result.get("scan") else 0
            round_obj.red_team_vulns_found = len(red_result.get("vulnerabilities", []))
            round_obj.red_team_exploits_attempted = len(red_result.get("exploit_attempts", []))
            round_obj.red_team_exploits_succeeded = sum(
                1 for e in red_result.get("exploit_attempts", []) if e.get("success")
            )

            round_obj.blue_team_alerts = blue_result.get("alerts_generated", 0)
            round_obj.blue_team_detections = blue_result.get("anomalies_detected", 0) + blue_result.get("signatures_matched", 0)
            round_obj.blue_team_blocks = len(blue_result.get("blocked_ips", []))

            # Score
            round_obj.red_team_score = self._score_red_team(round_obj)
            round_obj.blue_team_score = self._score_blue_team(round_obj)

            # Adapt
            blue_agent.adapt(round_id=round_obj.id)
            red_agent.end_round()

            round_obj.status = SimulationRound.Status.COMPLETED
            round_obj.completed_at = timezone.now()
            round_obj.duration_seconds = time.time() - start_time
            round_obj.save()

            logger.info(
                f"Round {round_number} [CONCURRENT]: "
                f"Red={round_obj.red_team_score:.1f} Blue={round_obj.blue_team_score:.1f}"
            )

        except Exception as e:
            logger.error(f"Concurrent round {round_number} failed: {e}", exc_info=True)
            round_obj.status = SimulationRound.Status.FAILED
            round_obj.duration_seconds = time.time() - start_time
            round_obj.save()

        self.event_bus.publish(Event(
            event_type=EventType.ROUND_ENDED,
            source="simulation",
            data={
                "round_id": str(round_obj.id),
                "red_score": round_obj.red_team_score,
                "blue_score": round_obj.blue_team_score,
            },
        ))

        return round_obj

    def _score_red_team(self, round_obj: SimulationRound) -> float:
        """Score the Red Team's performance."""
        score = 0.0
        score += round_obj.red_team_vulns_found * 10
        score += round_obj.red_team_exploits_succeeded * 25

        if round_obj.blue_team_blocks > 0 and round_obj.red_team_exploits_succeeded > 0:
            score += 15  # Evaded defenses

        failed = round_obj.red_team_exploits_attempted - round_obj.red_team_exploits_succeeded
        score -= failed * 5

        return max(0.0, score)

    def _score_blue_team(self, round_obj: SimulationRound) -> float:
        """Score the Blue Team's performance."""
        score = 0.0
        score += round_obj.blue_team_detections * 15
        score += round_obj.blue_team_blocks * 20

        if round_obj.red_team_exploits_attempted > 0:
            prevention_rate = 1.0 - (round_obj.red_team_exploits_succeeded / round_obj.red_team_exploits_attempted)
            score += prevention_rate * 30

        score -= round_obj.blue_team_false_positives * 5

        if round_obj.red_team_exploits_succeeded > round_obj.blue_team_detections:
            score -= (round_obj.red_team_exploits_succeeded - round_obj.blue_team_detections) * 10

        return max(0.0, score)

    def get_simulation_summary(self, simulation_id: str) -> dict:
        """Get a summary of simulation results with commentary."""
        sim = SimulationConfig.objects.get(id=simulation_id)
        rounds = SimulationRound.objects.filter(simulation=sim)

        summary = {
            "simulation": {
                "id": str(sim.id),
                "name": sim.name,
                "status": sim.status,
                "rounds_completed": sim.total_rounds_completed,
                "max_rounds": sim.max_rounds,
            },
            "scores": {
                "red_team_total": sum(r.red_team_score for r in rounds),
                "blue_team_total": sum(r.blue_team_score for r in rounds),
                "red_team_avg": sum(r.red_team_score for r in rounds) / max(len(rounds), 1),
                "blue_team_avg": sum(r.blue_team_score for r in rounds) / max(len(rounds), 1),
            },
            "red_team_totals": {
                "scans": sum(r.red_team_scans for r in rounds),
                "vulns_found": sum(r.red_team_vulns_found for r in rounds),
                "exploits_attempted": sum(r.red_team_exploits_attempted for r in rounds),
                "exploits_succeeded": sum(r.red_team_exploits_succeeded for r in rounds),
            },
            "blue_team_totals": {
                "alerts": sum(r.blue_team_alerts for r in rounds),
                "detections": sum(r.blue_team_detections for r in rounds),
                "blocks": sum(r.blue_team_blocks for r in rounds),
            },
            "rounds": [
                {
                    "round": r.round_number,
                    "target": r.target_ip,
                    "red_score": r.red_team_score,
                    "blue_score": r.blue_team_score,
                    "status": r.status,
                }
                for r in rounds
            ],
            "commentary": self.commentator.get_recent_commentary(),
        }

        # v2: Generate battle report
        try:
            report_data = {
                "name": sim.name,
                "rounds_completed": sim.total_rounds_completed,
                "red_team_total": summary["scores"]["red_team_total"],
                "blue_team_total": summary["scores"]["blue_team_total"],
                "exploits_attempted": summary["red_team_totals"]["exploits_attempted"],
                "exploits_succeeded": summary["red_team_totals"]["exploits_succeeded"],
                "total_blocks": summary["blue_team_totals"]["blocks"],
                "total_detections": summary["blue_team_totals"]["detections"],
            }
            summary["battle_report"] = self.commentator.generate_battle_report(report_data)
        except Exception:
            summary["battle_report"] = None

        return summary
