"""
Battle Commentary - LLM-Powered Real-Time Narration
=====================================================
Generates human-readable play-by-play commentary of the cyber battle.
Acts as the 'sportscaster' of the AI warfare.
"""

import logging
from typing import Optional

from core.event_bus import Event, EventType, get_event_bus
from core.llm_client import LLMClient
from core.models import SystemEvent

logger = logging.getLogger("simulation.commentary")


COMMENTARY_SYSTEM_PROMPT = """You are a dramatic cybersecurity battle commentator. You narrate AI cyber warfare battles with excitement and technical accuracy.

Your style:
- Use vivid, action-oriented language
- Include technical details but make them accessible
- Build tension during attacks and relief during successful defenses
- Use metaphors from warfare, sports, or chess
- Keep each commentary to 2-3 sentences maximum
- Use emojis sparingly for visual flair

Examples:
- "🔴 Red Team launches a surgical Nmap probe against the DMZ — 47 ports scanned in under 3 seconds. They've spotted an unpatched Apache on port 8080!"
- "🔵 Blue Team's Isolation Forest lights up — anomalous traffic pattern detected from 192.168.1.105. Deploying rate limiter before the attacker can escalate!"
- "⚔️ A critical moment! Red Team deploys CVE-2024-1234 against the SSH service while Blue Team simultaneously blocks the source IP. It's a race against time!"
"""


class BattleCommentator:
    """
    Generates real-time play-by-play commentary for the cyber battle.
    Subscribes to events and produces narrative descriptions.
    """

    def __init__(self, use_llm: bool = True):
        self.llm = LLMClient() if use_llm else None
        self.use_llm = use_llm
        self.event_bus = get_event_bus()
        self.commentary_log = []
        self._subscribe_to_events()

    def _subscribe_to_events(self):
        """Subscribe to key battle events for commentary."""
        event_handlers = {
            EventType.SCAN_STARTED: self._on_scan_started,
            EventType.SCAN_COMPLETED: self._on_scan_completed,
            EventType.VULNERABILITY_FOUND: self._on_vuln_found,
            EventType.EXPLOIT_ATTEMPTED: self._on_exploit_attempted,
            EventType.EXPLOIT_SUCCEEDED: self._on_exploit_succeeded,
            EventType.EXPLOIT_FAILED: self._on_exploit_failed,
            EventType.INTRUSION_DETECTED: self._on_intrusion_detected,
            EventType.ANOMALY_DETECTED: self._on_anomaly_detected,
            EventType.IP_BLOCKED: self._on_ip_blocked,
            EventType.HONEYPOT_DEPLOYED: self._on_honeypot_deployed,
            EventType.DEFENSE_ADAPTED: self._on_defense_adapted,
            EventType.ROUND_STARTED: self._on_round_started,
            EventType.ROUND_ENDED: self._on_round_ended,
            EventType.SIMULATION_STARTED: self._on_simulation_started,
            EventType.SIMULATION_ENDED: self._on_simulation_ended,
        }

        for event_type, handler in event_handlers.items():
            self.event_bus.subscribe(event_type, handler)

    def _generate_commentary(self, event_description: str, event_data: dict) -> str:
        """Generate commentary using LLM or template fallback."""
        if self.use_llm and self.llm:
            try:
                response = self.llm.query(
                    user_prompt=f"Generate a brief, exciting commentary for this cyber battle event:\n\n{event_description}\n\nEvent details: {event_data}",
                    system_prompt=COMMENTARY_SYSTEM_PROMPT,
                    temperature=0.8,
                    max_tokens=150,
                    use_cache=False,
                )
                if response.success and response.content:
                    return response.content.strip()
            except Exception as e:
                logger.debug(f"LLM commentary failed, using template: {e}")

        # Template fallback
        return event_description

    def _log_commentary(self, commentary: str, event_type: str):
        """Store commentary in log and database."""
        self.commentary_log.append({
            "text": commentary,
            "event_type": event_type,
        })

        # Keep in-memory log bounded
        if len(self.commentary_log) > 200:
            self.commentary_log = self.commentary_log[-200:]

        # Persist to database
        SystemEvent.objects.create(
            severity="info",
            source="battle_commentary",
            event_type=event_type,
            message=commentary,
        )

        logger.info(f"📢 {commentary}")

    # ─── Event Handlers ─────────────────────────────────────────────

    def _on_simulation_started(self, event: Event):
        name = event.data.get("name", "Unknown")
        commentary = self._generate_commentary(
            f"🏟️ BATTLE BEGINS! Simulation '{name}' has started. Red Team and Blue Team agents are initializing — the digital battlefield is set!",
            event.data,
        )
        self._log_commentary(commentary, "simulation_started")

    def _on_simulation_ended(self, event: Event):
        rounds = event.data.get("rounds_completed", 0)
        status = event.data.get("status", "unknown")
        commentary = self._generate_commentary(
            f"🏁 BATTLE OVER! After {rounds} intense rounds, the simulation ends with status: {status}. Time to review the scoreboard!",
            event.data,
        )
        self._log_commentary(commentary, "simulation_ended")

    def _on_round_started(self, event: Event):
        round_num = event.data.get("round_number", "?")
        target = event.data.get("target", "unknown")
        commentary = self._generate_commentary(
            f"⚔️ ROUND {round_num} — Red Team targets {target}. Blue Team stands ready. Let the battle commence!",
            event.data,
        )
        self._log_commentary(commentary, "round_started")

    def _on_round_ended(self, event: Event):
        red_score = event.data.get("red_score", 0)
        blue_score = event.data.get("blue_score", 0)
        winner = "Red Team" if red_score > blue_score else "Blue Team" if blue_score > red_score else "Neither team"
        commentary = self._generate_commentary(
            f"🔔 ROUND COMPLETE! Red: {red_score:.1f} vs Blue: {blue_score:.1f}. {winner} takes this round!",
            event.data,
        )
        self._log_commentary(commentary, "round_ended")

    def _on_scan_started(self, event: Event):
        target = event.data.get("target", "unknown")
        scan_type = event.data.get("type", "reconnaissance")
        commentary = self._generate_commentary(
            f"🔴 Red Team initiates {scan_type} scan against {target}. The hunt begins...",
            event.data,
        )
        self._log_commentary(commentary, "scan_started")

    def _on_scan_completed(self, event: Event):
        target = event.data.get("target", "unknown")
        ports = event.data.get("open_ports", 0)
        commentary = self._generate_commentary(
            f"🔴 Scan complete on {target} — {ports} open ports discovered! Red Team is mapping the attack surface.",
            event.data,
        )
        self._log_commentary(commentary, "scan_completed")

    def _on_vuln_found(self, event: Event):
        vuln = event.data.get("title", "vulnerability")
        severity = event.data.get("severity", "unknown")
        commentary = self._generate_commentary(
            f"🔴 VULNERABILITY FOUND! [{severity.upper()}] {vuln}. Red Team's scanners have found a potential entry point!",
            event.data,
        )
        self._log_commentary(commentary, "vulnerability_found")

    def _on_exploit_attempted(self, event: Event):
        target = event.data.get("target", "unknown")
        exploit_type = event.data.get("type", "exploit")
        commentary = self._generate_commentary(
            f"🔴💥 Red Team deploys {exploit_type} against {target}! Will it breach the defenses?",
            event.data,
        )
        self._log_commentary(commentary, "exploit_attempted")

    def _on_exploit_succeeded(self, event: Event):
        target = event.data.get("target", "unknown")
        access = event.data.get("access_level", "access")
        commentary = self._generate_commentary(
            f"🔴🎯 BREACH! Red Team gains {access} on {target}! Blue Team needs to respond immediately!",
            event.data,
        )
        self._log_commentary(commentary, "exploit_succeeded")

    def _on_exploit_failed(self, event: Event):
        target = event.data.get("target", "unknown")
        reason = event.data.get("reason", "defenses held")
        commentary = self._generate_commentary(
            f"🔵🛡️ Red Team's exploit against {target} FAILS — {reason}. The defenses hold firm!",
            event.data,
        )
        self._log_commentary(commentary, "exploit_failed")

    def _on_intrusion_detected(self, event: Event):
        source = event.data.get("source_ip", "unknown")
        commentary = self._generate_commentary(
            f"🔵🚨 INTRUSION DETECTED from {source}! Blue Team's IDS is on high alert!",
            event.data,
        )
        self._log_commentary(commentary, "intrusion_detected")

    def _on_anomaly_detected(self, event: Event):
        source = event.data.get("source_ip", "unknown")
        reason = event.data.get("reason", "anomalous behavior")
        commentary = self._generate_commentary(
            f"🔵📊 Blue Team's ML model flags anomaly from {source}: {reason}. Investigating...",
            event.data,
        )
        self._log_commentary(commentary, "anomaly_detected")

    def _on_ip_blocked(self, event: Event):
        ip = event.data.get("target_ip", "unknown")
        commentary = self._generate_commentary(
            f"🔵🚫 Blue Team BLOCKS {ip}! Firewall rules deployed — the attacker is cut off!",
            event.data,
        )
        self._log_commentary(commentary, "ip_blocked")

    def _on_honeypot_deployed(self, event: Event):
        source = event.data.get("source_ip", "unknown")
        port = event.data.get("port", "unknown")
        commentary = self._generate_commentary(
            f"🔵🍯 Blue Team deploys a honeypot on port {port} targeting {source}. The trap is set!",
            event.data,
        )
        self._log_commentary(commentary, "honeypot_deployed")

    def _on_defense_adapted(self, event: Event):
        retrained = event.data.get("retrained", False)
        commentary = self._generate_commentary(
            f"🔵🧠 Blue Team ADAPTS! {'ML model retrained with new attack data.' if retrained else 'Defense rules updated.'} The AI is getting smarter!",
            event.data,
        )
        self._log_commentary(commentary, "defense_adapted")

    # ─── Public API ──────────────────────────────────────────────────

    def get_recent_commentary(self, limit: int = 20) -> list:
        """Get the most recent commentary entries."""
        return self.commentary_log[-limit:]

    def generate_round_summary(self, round_data: dict) -> str:
        """Generate a narrative summary for an entire round."""
        prompt = f"""Summarize this cyber battle round in an exciting 3-4 sentence narrative:

Round {round_data.get('round_number', '?')}:
- Target: {round_data.get('target_ip', 'unknown')}
- Red Team: {round_data.get('red_team_exploits_attempted', 0)} exploits attempted, {round_data.get('red_team_exploits_succeeded', 0)} succeeded
- Blue Team: {round_data.get('blue_team_alerts', 0)} alerts, {round_data.get('blue_team_blocks', 0)} blocks
- Red Score: {round_data.get('red_team_score', 0):.1f}
- Blue Score: {round_data.get('blue_team_score', 0):.1f}
- Winner: {'Red Team' if round_data.get('red_team_score', 0) > round_data.get('blue_team_score', 0) else 'Blue Team'}"""

        if self.use_llm and self.llm:
            response = self.llm.query(
                user_prompt=prompt,
                system_prompt=COMMENTARY_SYSTEM_PROMPT,
                temperature=0.8,
                max_tokens=200,
                use_cache=False,
            )
            if response.success:
                return response.content.strip()

        # Fallback
        winner = "Red Team" if round_data.get("red_team_score", 0) > round_data.get("blue_team_score", 0) else "Blue Team"
        return (
            f"Round {round_data.get('round_number', '?')} concludes with {winner} "
            f"taking the lead — Red: {round_data.get('red_team_score', 0):.1f} vs "
            f"Blue: {round_data.get('blue_team_score', 0):.1f}."
        )

    def generate_battle_report(self, simulation_data: dict) -> str:
        """Generate a complete battle report narrative."""
        prompt = f"""Write a dramatic 5-6 sentence battle report for this complete cyber warfare simulation:

Simulation: {simulation_data.get('name', 'Unknown')}
Total Rounds: {simulation_data.get('rounds_completed', 0)}
Red Team Total Score: {simulation_data.get('red_team_total', 0):.1f}
Blue Team Total Score: {simulation_data.get('blue_team_total', 0):.1f}
Red Team Exploits: {simulation_data.get('exploits_succeeded', 0)}/{simulation_data.get('exploits_attempted', 0)}
Blue Team Blocks: {simulation_data.get('total_blocks', 0)}
Blue Team Detections: {simulation_data.get('total_detections', 0)}

Write it like a post-game analysis — who dominated, key turning points, and final verdict."""

        if self.use_llm and self.llm:
            response = self.llm.query(
                user_prompt=prompt,
                system_prompt=COMMENTARY_SYSTEM_PROMPT,
                temperature=0.8,
                max_tokens=300,
                use_cache=False,
            )
            if response.success:
                return response.content.strip()

        # Fallback
        overall_winner = (
            "Red Team" if simulation_data.get("red_team_total", 0) > simulation_data.get("blue_team_total", 0)
            else "Blue Team"
        )
        return (
            f"After {simulation_data.get('rounds_completed', 0)} rounds of intense cyber warfare, "
            f"{overall_winner} emerges victorious."
        )
