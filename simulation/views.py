"""
Simulation API Views
"""

import json
import threading

from django.http import JsonResponse
from django.views import View

from simulation.models import SimulationConfig, SimulationRound
from simulation.scheduler import SimulationScheduler


class CreateSimulationView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            data = {}

        name = data.get("name", "Simulation")
        target_ips = data.get("target_ips", [])
        max_rounds = data.get("max_rounds", 10)

        if not target_ips:
            return JsonResponse({"error": "target_ips is required"}, status=400)

        scheduler = SimulationScheduler()
        sim = scheduler.create_simulation(name, target_ips, max_rounds)

        return JsonResponse({
            "id": str(sim.id),
            "name": sim.name,
            "status": sim.status,
            "target_ips": sim.target_ips,
            "max_rounds": sim.max_rounds,
        })


class RunSimulationView(View):
    def post(self, request, sim_id):
        try:
            sim = SimulationConfig.objects.get(id=sim_id)
        except SimulationConfig.DoesNotExist:
            return JsonResponse({"error": "Simulation not found"}, status=404)

        scheduler = SimulationScheduler()

        def run():
            scheduler.run_simulation(str(sim_id))

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

        return JsonResponse({"status": "simulation_started", "id": str(sim.id)})


class SimulationListView(View):
    def get(self, request):
        sims = SimulationConfig.objects.all()[:50]
        return JsonResponse({
            "simulations": [
                {
                    "id": str(s.id),
                    "name": s.name,
                    "status": s.status,
                    "rounds_completed": s.total_rounds_completed,
                    "max_rounds": s.max_rounds,
                    "created_at": s.created_at.isoformat(),
                }
                for s in sims
            ]
        })


class SimulationDetailView(View):
    def get(self, request, sim_id):
        scheduler = SimulationScheduler()
        try:
            summary = scheduler.get_simulation_summary(str(sim_id))
            return JsonResponse(summary)
        except SimulationConfig.DoesNotExist:
            return JsonResponse({"error": "Simulation not found"}, status=404)


class RoundListView(View):
    def get(self, request, sim_id):
        rounds = SimulationRound.objects.filter(simulation_id=sim_id)
        return JsonResponse({
            "rounds": [
                {
                    "id": str(r.id),
                    "round_number": r.round_number,
                    "status": r.status,
                    "target_ip": r.target_ip,
                    "red_team_score": r.red_team_score,
                    "blue_team_score": r.blue_team_score,
                    "red_vulns": r.red_team_vulns_found,
                    "red_exploits": r.red_team_exploits_succeeded,
                    "blue_detections": r.blue_team_detections,
                    "blue_blocks": r.blue_team_blocks,
                    "duration": r.duration_seconds,
                }
                for r in rounds
            ]
        })
