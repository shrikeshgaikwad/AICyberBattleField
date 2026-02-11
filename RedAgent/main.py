from .planner import plan
from .executor import execute
from .safety import emergency_stop
from PythonScripts.VulnerabilityDetector import text

print(text)

def runRedAgent():
    # emergency_stop()
    # task = input("🧠 What should I do? > ")

    steps = plan(text)

    print("\n🔹 Plan:")
    for s in steps:
        print(s)

    # confirm = input("\nExecute? (y/n): ")
    # if confirm.lower() != "y":
    #     return

    # for step in steps:
    #     execute(step)

if __name__ == "__main__":
    runRedAgent()
