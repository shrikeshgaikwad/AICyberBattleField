"""
Management command: Run a Red vs Blue simulation
Usage: python manage.py simulate --targets 192.168.1.1 --rounds 5
"""

from django.core.management.base import BaseCommand

from simulation.scheduler import SimulationScheduler


class Command(BaseCommand):
    help = "Run a Red vs Blue adversarial simulation"

    def add_arguments(self, parser):
        parser.add_argument("--name", type=str, default="CLI Simulation", help="Simulation name")
        parser.add_argument("--targets", nargs="+", type=str, required=True, help="Target IP addresses")
        parser.add_argument("--rounds", type=int, default=5, help="Number of rounds")

    def handle(self, *args, **options):
        name = options["name"]
        targets = options["targets"]
        max_rounds = options["rounds"]

        self.stdout.write(self.style.WARNING(f"\n⚔️  Starting Simulation: {name}"))
        self.stdout.write(f"   Targets: {', '.join(targets)}")
        self.stdout.write(f"   Rounds: {max_rounds}")
        self.stdout.write("=" * 60)

        scheduler = SimulationScheduler()
        sim = scheduler.create_simulation(name, targets, max_rounds)

        self.stdout.write(f"\n   Simulation ID: {sim.id}")
        self.stdout.write("   Running...\n")

        sim = scheduler.run_simulation(str(sim.id))

        # Display results
        summary = scheduler.get_simulation_summary(str(sim.id))

        self.stdout.write(self.style.WARNING("\n" + "=" * 60))
        self.stdout.write(self.style.WARNING("   SIMULATION RESULTS"))
        self.stdout.write("=" * 60)

        scores = summary["scores"]
        self.stdout.write(f"\n   🔴 Red Team Total Score:  {scores['red_team_total']:.0f} (avg: {scores['red_team_avg']:.1f})")
        self.stdout.write(f"   🔵 Blue Team Total Score: {scores['blue_team_total']:.0f} (avg: {scores['blue_team_avg']:.1f})")

        if scores["red_team_total"] > scores["blue_team_total"]:
            self.stdout.write(self.style.ERROR("\n   🏆 WINNER: Red Team (Offensive AI)"))
        elif scores["blue_team_total"] > scores["red_team_total"]:
            self.stdout.write(self.style.SUCCESS("\n   🏆 WINNER: Blue Team (Defensive AI)"))
        else:
            self.stdout.write(self.style.WARNING("\n   🤝 TIE"))

        rt = summary["red_team_totals"]
        self.stdout.write(f"\n   Red Team Stats:")
        self.stdout.write(f"     Scans: {rt['scans']} | Vulns: {rt['vulns_found']} | Exploits: {rt['exploits_succeeded']}/{rt['exploits_attempted']}")

        bt = summary["blue_team_totals"]
        self.stdout.write(f"\n   Blue Team Stats:")
        self.stdout.write(f"     Alerts: {bt['alerts']} | Detections: {bt['detections']} | Blocks: {bt['blocks']}")

        self.stdout.write(f"\n   Rounds:")
        for r in summary["rounds"]:
            winner = "🔴" if r["red_score"] > r["blue_score"] else "🔵" if r["blue_score"] > r["red_score"] else "🤝"
            self.stdout.write(
                f"     #{r['round']:2d} | {r['target']:15s} | "
                f"Red: {r['red_score']:5.0f} | Blue: {r['blue_score']:5.0f} | {winner}"
            )

        self.stdout.write(self.style.SUCCESS(f"\n✅ Simulation '{name}' complete ({sim.status})."))
