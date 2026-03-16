"""
Attack Planner - LLM-Powered Structured Attack Planning
=========================================================
Generates validated, structured attack plans from scan + vuln data.
"""

import json
import logging
from typing import Optional

from core.llm_client import LLMClient
from core.models import AIDecision
from red_team.models import AttackPlan, ScanResult, Vulnerability

logger = logging.getLogger("red_team.planner")

ATTACK_PLANNER_SYSTEM_PROMPT = """You are an expert penetration testing AI. You create structured, methodical attack plans based on reconnaissance and vulnerability data.

Given scan results and discovered vulnerabilities, produce a JSON attack plan with ordered steps. Each step must follow this exact structure:

{
  "plan_name": "Descriptive name for the attack plan",
  "target": "IP address",
  "priority_summary": "Brief assessment of most promising attack vectors",
  "steps": [
    {
      "step_number": 1,
      "action": "One of: nmap_scan, vuln_scan, exploit_metasploit, exploit_sqlmap, bruteforce, fuzz, custom_script, enumerate_service",
      "target_port": 80,
      "target_service": "http",
      "description": "What this step does and why",
      "parameters": {
        "key": "value pairs specific to the action"
      },
      "expected_outcome": "What we expect to achieve",
      "risk_level": "low/medium/high",
      "fallback": "What to try if this step fails"
    }
  ],
  "estimated_success_probability": 0.65,
  "reasoning": "Why this plan was chosen over alternatives"
}

Rules:
1. Order steps from least intrusive to most intrusive
2. Start with information gathering, then move to exploitation
3. Include fallback strategies for failed steps
4. Assign realistic success probabilities
5. Never include steps that target systems outside the given scope
6. For each exploit step, specify the exact tool and parameters needed
"""


class AttackPlanner:
    """
    Creates structured attack plans using LLM analysis.
    Plans are stored in the database and validated before execution.
    """

    def __init__(self):
        self.llm = LLMClient()

    def create_plan(
        self,
        scan: ScanResult,
        vulnerabilities: list = None,
        round_id=None,
    ) -> Optional[AttackPlan]:
        """
        Generate an attack plan based on scan results and vulnerabilities.

        Args:
            scan: The ScanResult to base the plan on.
            vulnerabilities: List of Vulnerability objects. If None, fetches from scan.
            round_id: Simulation round ID.

        Returns:
            AttackPlan instance or None on failure.
        """
        if vulnerabilities is None:
            vulnerabilities = list(Vulnerability.objects.filter(scan=scan))

        # Build context for LLM
        context = self._build_context(scan, vulnerabilities)

        # Get plan from LLM
        plan_data = self.llm.query_json(
            user_prompt=context,
            system_prompt=ATTACK_PLANNER_SYSTEM_PROMPT,
            temperature=0.4,
        )

        if not plan_data or "steps" not in plan_data:
            logger.warning("LLM failed to generate a valid attack plan")
            return None

        # Create the plan record
        steps = plan_data.get("steps", [])
        plan = AttackPlan.objects.create(
            target_ip=scan.target_ip,
            scan=scan,
            plan_data=plan_data,
            plan_text=self._format_plan_text(plan_data),
            total_steps=len(steps),
            completed_steps=0,
            llm_model=self.llm.model,
            llm_reasoning=plan_data.get("reasoning", ""),
            round_id=round_id,
        )

        # Log AI decision
        AIDecision.objects.create(
            agent_type="red",
            agent_name="attack_planner",
            decision=f"Created attack plan with {len(steps)} steps",
            reasoning=plan_data.get("reasoning", ""),
            confidence=plan_data.get("estimated_success_probability", 0.5),
            context={"scan_id": str(scan.id), "vuln_count": len(vulnerabilities)},
            llm_model=self.llm.model,
            round_id=round_id,
        )

        logger.info(f"Attack plan created: {len(steps)} steps for {scan.target_ip}")
        return plan

    def _build_context(self, scan: ScanResult, vulnerabilities: list) -> str:
        """Build the context prompt for the LLM."""
        lines = [
            f"=== TARGET: {scan.target_ip} ===",
            f"\n--- SCAN RESULTS ({scan.scan_type}) ---",
        ]

        if scan.open_ports:
            lines.append(f"\nOpen Ports ({len(scan.open_ports)}):")
            for port in scan.open_ports:
                lines.append(
                    f"  Port {port['port']}/{port.get('protocol', 'tcp')}: "
                    f"{port.get('service', 'unknown')} ({port.get('product', '')} {port.get('version', '')})"
                )

        if vulnerabilities:
            lines.append(f"\n--- DISCOVERED VULNERABILITIES ({len(vulnerabilities)}) ---")
            for vuln in vulnerabilities:
                lines.append(
                    f"\n  [{vuln.severity.upper()}] {vuln.title}"
                    f"\n    CVE: {vuln.cve_id or 'N/A'}"
                    f"\n    Service: {vuln.affected_service} (port {vuln.affected_port})"
                    f"\n    CVSS: {vuln.cvss_score}"
                    f"\n    Exploitable: {vuln.exploitable}"
                )

        lines.append("\n--- INSTRUCTIONS ---")
        lines.append("Create an attack plan for the above target prioritizing the highest-severity, most exploitable vulnerabilities.")

        return "\n".join(lines)

    def _format_plan_text(self, plan_data: dict) -> str:
        """Format plan data into human-readable text."""
        lines = [
            f"# {plan_data.get('plan_name', 'Attack Plan')}",
            f"Target: {plan_data.get('target', 'Unknown')}",
            f"Priority: {plan_data.get('priority_summary', 'N/A')}",
            f"Success Probability: {plan_data.get('estimated_success_probability', 0):.0%}",
            "",
        ]

        for step in plan_data.get("steps", []):
            lines.append(
                f"Step {step.get('step_number', '?')}: [{step.get('risk_level', 'unknown').upper()}] "
                f"{step.get('description', 'No description')}"
            )
            lines.append(f"  Action: {step.get('action', 'unknown')}")
            lines.append(f"  Target: port {step.get('target_port', 'N/A')} ({step.get('target_service', 'unknown')})")
            if step.get("fallback"):
                lines.append(f"  Fallback: {step['fallback']}")
            lines.append("")

        return "\n".join(lines)
