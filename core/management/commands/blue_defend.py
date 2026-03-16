"""
Management command: Run Blue Team defense cycle
Usage: python manage.py blue_defend
"""

from django.core.management.base import BaseCommand

from blue_team.agent import BlueTeamAgent


class Command(BaseCommand):
    help = "Run a Blue Team defense monitoring cycle"

    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO("\n🛡️  Blue Team Defense Cycle"))
        self.stdout.write("=" * 50)

        agent = BlueTeamAgent()
        result = agent.monitor_and_defend()

        self.stdout.write(f"\n🚨 Alerts Generated: {result.get('alerts_generated', 0)}")
        self.stdout.write(f"🔍 Anomalies Detected: {result.get('anomalies_detected', 0)}")
        self.stdout.write(f"📝 Signatures Matched: {result.get('signatures_matched', 0)}")
        self.stdout.write(f"⚡ Actions Taken: {result.get('actions_taken', 0)}")

        blocked = result.get("blocked_ips", [])
        if blocked:
            self.stdout.write(f"🚫 Blocked IPs: {', '.join(blocked)}")

        if result.get("error"):
            self.stdout.write(self.style.ERROR(f"⚠️  Error: {result['error']}"))

        self.stdout.write(self.style.SUCCESS("\n✅ Defense cycle complete."))
