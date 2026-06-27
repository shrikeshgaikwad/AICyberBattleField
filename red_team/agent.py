"""
Red Team Agent - Orchestrator (v2 — Enhanced with Memory, RL, and Topology)
=============================================================================
Implements the full attack lifecycle with learning and memory:
Recall → Recon → Detect Vulns → Plan Attack → Execute Exploits → Observe → Learn → Adapt
"""

import logging
import time
from typing import Optional

from django.utils import timezone

from core.event_bus import Event, EventType, get_event_bus
from core.logger import AgentLogger
from core.memory import AgentMemory, MemoryEntry
from core.models import AgentAction
from core.safety import SafetyError, get_safety_module
from red_team.exploitation.launcher import ExploitLauncher
from red_team.fuzzing.fuzzer import Fuzzer
from red_team.models import AttackPlan, ExploitAttempt, ScanResult, Vulnerability
from red_team.planner.planner import AttackPlanner
from red_team.recon.scanner import ReconScanner
from red_team.rl_policy import RedTeamPolicy
from red_team.vuln_detection.detector import VulnerabilityDetector

logger = logging.getLogger("red_team")


class RedTeamAgent:
    """
    Autonomous offensive AI agent (v2).
    Now with episodic memory, reinforcement learning, and topology awareness.
    """

    def __init__(self, name: str = "RedAgent-1"):
        self.name = name
        self.agent_logger = AgentLogger(name, "red_team")
        self.scanner = ReconScanner()
        self.vuln_detector = VulnerabilityDetector()
        self.exploit_launcher = ExploitLauncher()
        self.planner = AttackPlanner()
        self.fuzzer = Fuzzer()
        self.safety = get_safety_module()
        self.event_bus = get_event_bus()

        # v2: Memory and RL
        self.memory = AgentMemory(name, "red")
        self.rl_policy = RedTeamPolicy()
        self.topology = None  # Set from simulation scheduler

    def set_topology(self, topology):
        """Set the network topology for topology-aware attacks."""
        self.topology = topology

    def run_full_attack(self, target_ip: str, round_id=None) -> dict:
        """
        Execute a full attack cycle against a target.
        v2: Uses memory recall and RL for smarter decisions.
        """
        self.agent_logger.action("full_attack_start", target=target_ip)
        results = {
            "target": target_ip,
            "scan": None,
            "vulnerabilities": [],
            "attack_plan": None,
            "exploit_attempts": [],
            "success": False,
            "errors": [],
            "memory_used": False,
        }

        try:
            # Safety check
            if not self.safety.validate_target(target_ip):
                results["errors"].append(f"Target {target_ip} not in allowed scope")
                return results

            # v2: Recall past experiences with this target
            memory_context = self.memory.build_context_summary(target_ip=target_ip)
            past_strategies = self.memory.recall_for_target(target_ip, limit=5)
            if past_strategies:
                results["memory_used"] = True
                self.agent_logger.info(f"Recalled {len(past_strategies)} past experiences with {target_ip}")

            # Phase 1: Reconnaissance
            self.agent_logger.action("recon", target=target_ip, details="Starting nmap TCP scan")
            scan = self.scanner.nmap_scan(target_ip, port_range="1-10000", round_id=round_id)
            if not scan or scan.status == ScanResult.Status.FAILED:
                results["errors"].append("Scan failed")
                self.memory.remember(
                    memory_type=MemoryEntry.MemoryType.ATTACK_FAILURE,
                    action_taken="nmap_scan",
                    target_ip=target_ip,
                    success=False,
                    outcome="Scan failed",
                    reward=-5.0,
                    round_id=round_id,
                )
                return results

            results["scan"] = {
                "id": str(scan.id),
                "open_ports": len(scan.open_ports),
                "services": len(scan.services),
            }
            self._log_action("recon_scan", target_ip, True, f"Found {len(scan.open_ports)} open ports", round_id)

            # Phase 2: Vulnerability Detection
            self.agent_logger.action("vuln_detection", target=target_ip, details="Analyzing vulnerabilities")
            vulns = self.vuln_detector.detect(scan, round_id=round_id)
            results["vulnerabilities"] = [
                {"id": str(v.id), "cve": v.cve_id, "severity": v.severity, "title": v.title}
                for v in vulns
            ]
            self._log_action("vuln_detection", target_ip, True, f"Found {len(vulns)} vulnerabilities", round_id)

            # v2: Remember discovered vulnerabilities
            for v in vulns:
                self.memory.remember(
                    memory_type=MemoryEntry.MemoryType.STRATEGY,
                    action_taken="vuln_discovered",
                    target_ip=target_ip,
                    target_port=v.affected_port,
                    target_service=v.affected_service,
                    success=True,
                    outcome=f"{v.cve_id}: {v.title} ({v.severity})",
                    lesson=f"Service {v.affected_service} on port {v.affected_port} has {v.severity} vulnerability {v.cve_id}",
                    reward=10.0 if v.severity in ("critical", "high") else 5.0,
                    tags=[v.severity, v.affected_service, v.cve_id or "no-cve"],
                    round_id=round_id,
                )

            if not vulns:
                self.agent_logger.info("No vulnerabilities found, trying fuzzing")
                for port in scan.open_ports:
                    if port.get("service") in ("http", "https"):
                        scheme = "https" if port.get("service") == "https" else "http"
                        fuzz_result = self.fuzzer.fuzz_http(
                            f"{scheme}://{target_ip}:{port['port']}/",
                            iterations=50,
                        )
                        if fuzz_result.get("anomalies_found", 0) > 0:
                            results["fuzzing"] = fuzz_result
                return results

            # Phase 3: Attack Planning (v2 - with memory context)
            self.agent_logger.action("planning", target=target_ip, details="Creating attack plan with memory context")
            plan = self.planner.create_plan(scan, vulns, round_id=round_id)
            if plan:
                results["attack_plan"] = {
                    "id": str(plan.id),
                    "total_steps": plan.total_steps,
                    "plan_text": plan.plan_text[:500],
                }
                self._log_action("attack_planning", target_ip, True, f"Plan with {plan.total_steps} steps", round_id)
            else:
                self.agent_logger.warning("Failed to create attack plan, executing ad-hoc exploits")

            # Phase 4: Exploit Execution (v2 - RL-guided action selection)
            self.agent_logger.action("exploitation", target=target_ip, details="Executing RL-guided exploits")
            exploit_results = self._execute_plan(plan, vulns, target_ip, round_id)
            results["exploit_attempts"] = exploit_results

            # Update plan success metrics
            if plan:
                successful = sum(1 for e in exploit_results if e.get("success"))
                plan.completed_steps = len(exploit_results)
                plan.success_rate = successful / len(exploit_results) if exploit_results else 0
                plan.save()

            results["success"] = any(e.get("success") for e in exploit_results)

            # v2: RL update and memory storage for exploit outcomes
            for exp_result in exploit_results:
                service = exp_result.get("service", "unknown")
                port = exp_result.get("port", 80)
                action = exp_result.get("action", "exploit")
                success = exp_result.get("success", False)

                reward = self.rl_policy.compute_reward(exp_result)
                self.rl_policy.update(service, port, action, reward)

                self.memory.remember(
                    memory_type=(MemoryEntry.MemoryType.ATTACK_SUCCESS if success
                                 else MemoryEntry.MemoryType.ATTACK_FAILURE),
                    action_taken=action,
                    target_ip=target_ip,
                    target_port=port,
                    target_service=service,
                    success=success,
                    outcome=exp_result.get("output", "")[:300],
                    lesson=(f"{action} on {service}:{port} {'succeeded' if success else 'failed'}"),
                    reward=reward,
                    tags=[action, service, "success" if success else "failure"],
                    round_id=round_id,
                )

            # v2: Check for lateral movement opportunities
            if results["success"] and self.topology:
                lateral_targets = self.topology.get_lateral_targets(target_ip)
                if lateral_targets:
                    results["lateral_targets"] = [h.ip_address for h in lateral_targets[:5]]
                    self.agent_logger.info(
                        f"Lateral movement possible to {len(lateral_targets)} hosts"
                    )

            self.agent_logger.result(
                "full_attack",
                results["success"],
                f"{sum(1 for e in exploit_results if e.get('success'))}/{len(exploit_results)} exploits succeeded",
            )

        except SafetyError as e:
            results["errors"].append(f"Safety violation: {e}")
            self.agent_logger.error(f"Safety error: {e}")
        except Exception as e:
            results["errors"].append(str(e))
            self.agent_logger.error(f"Attack cycle error: {e}", exc_info=True)

        return results

    def _execute_plan(self, plan: Optional[AttackPlan], vulns: list, target_ip: str, round_id=None) -> list:
        """Execute exploit steps from a plan or ad-hoc against vulnerabilities."""
        results = []

        if plan and plan.plan_data.get("steps"):
            for step in plan.plan_data["steps"]:
                try:
                    result = self._execute_step(step, target_ip, vulns, round_id)
                    results.append(result)
                except SafetyError as e:
                    results.append({"step": step.get("step_number"), "success": False, "error": str(e)})
                    break
        else:
            # v2: RL-guided ad-hoc exploitation
            exploitable = [v for v in vulns if v.exploitable and v.severity in ("critical", "high")]
            for vuln in exploitable[:5]:
                service = vuln.affected_service or "unknown"
                port = vuln.affected_port or 80

                # v2: Use RL to pick best exploit action
                best_action = self.rl_policy.select_action(
                    service=service,
                    port=port,
                    defense_level="unknown",
                    available_actions=["exploit_metasploit", "exploit_sqlmap", "bruteforce", "fuzz"],
                )

                # Map RL action back to exploit type
                exploit_type_map = {
                    "exploit_metasploit": ExploitAttempt.ExploitType.METASPLOIT,
                    "exploit_sqlmap": ExploitAttempt.ExploitType.SQLMAP,
                    "bruteforce": ExploitAttempt.ExploitType.BRUTEFORCE,
                    "fuzz": ExploitAttempt.ExploitType.FUZZING,
                }
                exploit_type = exploit_type_map.get(best_action, ExploitAttempt.ExploitType.CUSTOM)

                attempt = self.exploit_launcher.launch(
                    target_ip=target_ip,
                    target_port=port,
                    exploit_type=exploit_type,
                    vulnerability=vuln,
                    round_id=round_id,
                )
                results.append({
                    "vuln": vuln.title,
                    "action": best_action,
                    "service": service,
                    "port": port,
                    "success": attempt.status == ExploitAttempt.Status.SUCCESS,
                    "output": attempt.output[:200],
                })

        return results

    def _execute_step(self, step: dict, target_ip: str, vulns: list, round_id=None) -> dict:
        """Execute a single plan step."""
        action = step.get("action", "")
        port = step.get("target_port", 80)
        params = step.get("parameters", {})

        self.safety.validate_action({"type": action, "target": target_ip})

        if action == "exploit_metasploit":
            module = params.get("module", "")
            attempt = self.exploit_launcher.launch(
                target_ip, port,
                ExploitAttempt.ExploitType.METASPLOIT,
                exploit_module=module,
                parameters=params,
                round_id=round_id,
            )
            return {
                "step": step.get("step_number"),
                "action": action,
                "service": step.get("target_service", "unknown"),
                "port": port,
                "success": attempt.status == ExploitAttempt.Status.SUCCESS,
                "output": attempt.output[:200],
            }

        elif action == "exploit_sqlmap":
            attempt = self.exploit_launcher.launch(
                target_ip, port,
                ExploitAttempt.ExploitType.SQLMAP,
                parameters=params,
                round_id=round_id,
            )
            return {
                "step": step.get("step_number"),
                "action": action,
                "service": step.get("target_service", "unknown"),
                "port": port,
                "success": attempt.status == ExploitAttempt.Status.SUCCESS,
                "output": attempt.output[:200],
            }

        elif action == "bruteforce":
            attempt = self.exploit_launcher.launch(
                target_ip, port,
                ExploitAttempt.ExploitType.BRUTEFORCE,
                parameters=params,
                round_id=round_id,
            )
            return {
                "step": step.get("step_number"),
                "action": action,
                "service": step.get("target_service", "unknown"),
                "port": port,
                "success": attempt.status == ExploitAttempt.Status.SUCCESS,
                "output": attempt.output[:200],
            }

        elif action == "fuzz":
            result = self.fuzzer.fuzz_http(
                f"http://{target_ip}:{port}/",
                parameters=params,
                iterations=params.get("iterations", 50),
            )
            return {
                "step": step.get("step_number"),
                "action": action,
                "service": step.get("target_service", "unknown"),
                "port": port,
                **result,
            }

        elif action in ("nmap_scan", "vuln_scan", "enumerate_service"):
            scan = self.scanner.nmap_scan(target_ip, port_range=str(port), round_id=round_id)
            return {
                "step": step.get("step_number"),
                "action": action,
                "service": step.get("target_service", "unknown"),
                "port": port,
                "success": scan and scan.status == ScanResult.Status.COMPLETED,
            }

        return {
            "step": step.get("step_number"),
            "action": action,
            "port": port,
            "success": False,
            "error": "Unknown action",
        }

    def end_round(self):
        """Called at end of round to persist learning."""
        self.rl_policy.save_policy()
        self.rl_policy.decay_exploration()
        self.memory.decay_memories(decay_factor=0.97)

    def _log_action(self, action: str, target: str, success: bool, details: str, round_id=None):
        """Log an agent action to the database."""
        AgentAction.objects.create(
            agent_type=AgentAction.AgentType.RED,
            agent_name=self.name,
            action_name=action,
            target=target,
            success=success,
            result=details,
            round_id=round_id,
        )
