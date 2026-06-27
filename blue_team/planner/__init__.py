"""
Defense Planner - LLM-Powered Strategic Defense Planning
==========================================================
Analyzes attack patterns and generates adaptive defense strategies.
The Blue Team's counterpart to Red Team's AttackPlanner.
"""

import json
import logging
from typing import Optional

from core.llm_client import LLMClient
from core.models import AIDecision
from blue_team.models import Alert, DefenseAction

logger = logging.getLogger("blue_team.planner")

DEFENSE_PLANNER_SYSTEM_PROMPT = """You are an expert cybersecurity defense AI. You analyze attack patterns and create strategic defense plans.

Given recent alerts, attack patterns, and the current security posture, produce a JSON defense plan:

{
  "threat_assessment": "Brief summary of the current threat landscape",
  "attack_pattern": "Identified attack pattern or campaign type (e.g., 'port scan followed by SSH brute force')",
  "risk_level": "critical/high/medium/low",
  "immediate_actions": [
    {
      "priority": 1,
      "action_type": "One of: block_ip, rate_limit, honeypot, isolate, patch, update_rules, quarantine, alert_admin",
      "target": "What to apply this to",
      "reason": "Why this action is recommended",
      "confidence": 0.85
    }
  ],
  "strategic_recommendations": [
    {
      "recommendation": "What to do proactively",
      "timeframe": "immediate/short_term/long_term",
      "impact": "Expected improvement"
    }
  ],
  "predicted_next_attack": "What the attacker is likely to try next based on patterns",
  "defense_gaps": ["Current weaknesses that need addressing"],
  "reasoning": "Chain-of-thought explanation of the analysis"
}

Rules:
1. Prioritize actions by severity and urgency
2. Consider false positive rates — don't over-block
3. Look for multi-stage attack patterns (recon → exploit chains)
4. Recommend proactive measures, not just reactive responses
5. When unsure, recommend monitoring over blocking
"""


class DefensePlanner:
    """
    LLM-powered defense strategist for the Blue Team.
    Analyzes attack patterns and recommends adaptive responses.
    """

    def __init__(self):
        self.llm = LLMClient()

    def analyze_and_plan(self, round_id=None, memory_context: str = "") -> Optional[dict]:
        """
        Analyze recent threats and create a defense plan.

        Args:
            round_id: Current simulation round ID.
            memory_context: Past experience summary from AgentMemory.

        Returns:
            Defense plan dict or None on failure.
        """
        context = self._build_threat_context(round_id, memory_context)

        plan_data = self.llm.query_json(
            user_prompt=context,
            system_prompt=DEFENSE_PLANNER_SYSTEM_PROMPT,
            temperature=0.3,
        )

        if not plan_data:
            logger.warning("LLM failed to generate defense plan")
            return None

        # Log the AI decision
        AIDecision.objects.create(
            agent_type="blue",
            agent_name="defense_planner",
            decision=f"Defense plan: {plan_data.get('threat_assessment', 'N/A')[:200]}",
            reasoning=plan_data.get("reasoning", ""),
            confidence=0.7,
            context={
                "risk_level": plan_data.get("risk_level", "unknown"),
                "actions_count": len(plan_data.get("immediate_actions", [])),
            },
            llm_model=self.llm.model,
            round_id=round_id,
        )

        logger.info(
            f"Defense plan created: {plan_data.get('risk_level', 'unknown')} risk, "
            f"{len(plan_data.get('immediate_actions', []))} actions recommended"
        )
        return plan_data

    def predict_next_attack(self, round_id=None) -> Optional[dict]:
        """
        Predict what the Red Team will try next based on observed patterns.

        Returns:
            Dict with prediction details or None.
        """
        recent_attacks = self._get_recent_attack_summary(round_id)
        if not recent_attacks:
            return None

        prompt = f"""Based on the following observed attack sequence, predict the attacker's next move:

{recent_attacks}

Respond with JSON:
{{
  "predicted_action": "What the attacker will likely try next",
  "confidence": 0.7,
  "reasoning": "Why you predict this",
  "recommended_preemptive_defense": "What to do before the attack happens",
  "target_likely_port": 80,
  "target_likely_service": "http"
}}"""

        prediction = self.llm.query_json(
            user_prompt=prompt,
            system_prompt="You are a threat intelligence AI that predicts attacker behavior based on observed patterns.",
            temperature=0.4,
        )

        if prediction:
            logger.info(f"Attack prediction: {prediction.get('predicted_action', 'unknown')}")

        return prediction

    def analyze_false_positives(self, round_id=None) -> dict:
        """
        Analyze alerts for likely false positives and recommend rule adjustments.
        """
        alerts = Alert.objects.filter(
            status__in=[Alert.Status.NEW, Alert.Status.CONFIRMED],
        ).order_by("-created_at")[:30]

        if not alerts:
            return {"false_positive_candidates": [], "rule_adjustments": []}

        alert_summary = []
        for alert in alerts:
            alert_summary.append(
                f"- [{alert.severity}] {alert.title} from {alert.source_ip} "
                f"(source: {alert.source}, confidence: {alert.confidence:.2f})"
            )

        prompt = f"""Analyze these security alerts for potential false positives:

{chr(10).join(alert_summary)}

Identify which alerts are likely false positives and suggest rule adjustments.
Respond with JSON:
{{
  "false_positive_candidates": [
    {{"alert_title": "...", "reason": "Why this is likely false", "confidence": 0.8}}
  ],
  "rule_adjustments": [
    {{"current_rule": "...", "suggested_change": "...", "reason": "..."}}
  ],
  "overall_false_positive_rate_estimate": 0.15
}}"""

        return self.llm.query_json(
            user_prompt=prompt,
            system_prompt="You are a security analyst specializing in alert triage and false positive reduction.",
            temperature=0.3,
        ) or {"false_positive_candidates": [], "rule_adjustments": []}

    def _build_threat_context(self, round_id=None, memory_context: str = "") -> str:
        """Build context for LLM analysis."""
        lines = ["=== CURRENT THREAT LANDSCAPE ==="]

        # Recent alerts
        alerts = Alert.objects.order_by("-created_at")[:20]
        if alerts:
            lines.append(f"\n--- RECENT ALERTS ({len(alerts)}) ---")
            severity_counts = {}
            for alert in alerts:
                severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
                lines.append(
                    f"  [{alert.severity.upper()}] {alert.title} "
                    f"from {alert.source_ip} -> :{alert.destination_port} "
                    f"(confidence: {alert.confidence:.2f}, source: {alert.source})"
                )
            lines.append(f"\n  Severity distribution: {severity_counts}")

        # Recent defense actions
        actions = DefenseAction.objects.order_by("-created_at")[:10]
        if actions:
            lines.append(f"\n--- RECENT DEFENSE ACTIONS ({len(actions)}) ---")
            for action in actions:
                lines.append(
                    f"  {action.action_type}: {action.target_ip} [{action.status}] "
                    f"(confidence: {action.confidence:.2f})"
                )

        # Blocked IPs count
        blocked = DefenseAction.objects.filter(
            action_type="block_ip", status="active"
        ).count()
        lines.append(f"\n  Currently blocked IPs: {blocked}")

        # Add memory context if available
        if memory_context:
            lines.append(f"\n{memory_context}")

        lines.append("\n--- INSTRUCTIONS ---")
        lines.append("Analyze the above threat data and create a comprehensive defense plan.")
        lines.append("Focus on identifying attack patterns and recommending proactive defenses.")

        return "\n".join(lines)

    def _get_recent_attack_summary(self, round_id=None) -> str:
        """Get summary of recent attack patterns for prediction."""
        from red_team.models import ScanResult, ExploitAttempt

        lines = []

        scans = ScanResult.objects.order_by("-created_at")[:5]
        for scan in scans:
            lines.append(
                f"SCAN: {scan.scan_type} on {scan.target_ip} "
                f"({len(scan.open_ports)} open ports) [{scan.status}]"
            )

        exploits = ExploitAttempt.objects.order_by("-created_at")[:10]
        for exp in exploits:
            lines.append(
                f"EXPLOIT: {exp.exploit_type} on {exp.target_ip}:{exp.target_port} "
                f"[{exp.status}] module={exp.exploit_module}"
            )

        return "\n".join(lines) if lines else ""

    def format_plan_text(self, plan_data: dict) -> str:
        """Format a defense plan into readable text."""
        lines = [
            f"# Defense Plan — Risk Level: {plan_data.get('risk_level', 'unknown').upper()}",
            f"\nThreat Assessment: {plan_data.get('threat_assessment', 'N/A')}",
            f"Attack Pattern: {plan_data.get('attack_pattern', 'N/A')}",
            f"\nPredicted Next Attack: {plan_data.get('predicted_next_attack', 'Unknown')}",
            "\n## Immediate Actions:",
        ]

        for action in plan_data.get("immediate_actions", []):
            lines.append(
                f"  {action.get('priority', '?')}. [{action.get('action_type', 'unknown')}] "
                f"{action.get('reason', '')} (confidence: {action.get('confidence', 0):.0%})"
            )

        if plan_data.get("strategic_recommendations"):
            lines.append("\n## Strategic Recommendations:")
            for rec in plan_data["strategic_recommendations"]:
                lines.append(
                    f"  - [{rec.get('timeframe', 'N/A')}] {rec.get('recommendation', '')}"
                )

        if plan_data.get("defense_gaps"):
            lines.append("\n## Defense Gaps:")
            for gap in plan_data["defense_gaps"]:
                lines.append(f"  ⚠ {gap}")

        return "\n".join(lines)
