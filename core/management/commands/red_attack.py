"""
Management command: Run a full attack cycle
Usage: python manage.py red_attack <target_ip>
"""

from django.core.management.base import BaseCommand, CommandError

from red_team.agent import RedTeamAgent


class Command(BaseCommand):
    help = "Launch a Red Team attack cycle against a target IP"

    def add_arguments(self, parser):
        parser.add_argument("target_ip", type=str, help="Target IP address to attack")
        parser.add_argument("--port-range", type=str, default="1-10000", help="Port range to scan")

    def handle(self, *args, **options):
        target_ip = options["target_ip"]
        self.stdout.write(self.style.WARNING(f"\n⚔️  Red Team Attack: {target_ip}"))
        self.stdout.write("=" * 50)

        agent = RedTeamAgent()
        result = agent.run_full_attack(target_ip)

        # Display results
        self.stdout.write(f"\n📡 Scan: {result.get('scan', 'No scan')}")

        vulns = result.get("vulnerabilities", [])
        self.stdout.write(f"\n🔍 Vulnerabilities Found: {len(vulns)}")
        for v in vulns:
            self.stdout.write(f"  [{v['severity'].upper()}] {v['title']} (CVE: {v.get('cve', 'N/A')})")

        plan = result.get("attack_plan")
        if plan:
            self.stdout.write(f"\n📋 Attack Plan: {plan.get('total_steps', 0)} steps")

        exploits = result.get("exploit_attempts", [])
        self.stdout.write(f"\n💥 Exploit Attempts: {len(exploits)}")
        for e in exploits:
            status = "✅" if e.get("success") else "❌"
            self.stdout.write(f"  {status} {e.get('action', e.get('vuln', 'unknown'))}")

        if result.get("errors"):
            for err in result["errors"]:
                self.stdout.write(self.style.ERROR(f"  ⚠️  {err}"))

        if result.get("success"):
            self.stdout.write(self.style.SUCCESS("\n✅ Attack cycle completed with successful exploits!"))
        else:
            self.stdout.write(self.style.WARNING("\n⚠️  Attack cycle completed, no successful exploits."))
