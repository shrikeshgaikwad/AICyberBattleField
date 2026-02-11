from planner import plan
from executor import execute
from safety import emergency_stop

def run():
    # emergency_stop()
    task = input("🧠 What should I do? > ")

    steps = plan(task)

    print("\n🔹 Plan:")
    for s in steps:
        print(s)

    confirm = input("\nExecute? (y/n): ")
    if confirm.lower() != "y":
        return

    for step in steps:
        execute(step)

if __name__ == "__main__":
    run()
