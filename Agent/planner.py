import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1:8b"

SYSTEM_PROMPT = """
You are a planning AI that controls a computer.

Convert the user's command into ordered desktop actions.

Allowed actions ONLY:
- OPEN_APP(name)
- CLICK(x,y)
- TYPE(text)
- PRESS(key)
- WAIT(seconds)

Rules:
- Do NOT explain anything
- Do NOT add extra text
- Return ONLY a numbered list
"""

def plan(task: str):
    prompt = f"{SYSTEM_PROMPT}\nUser command: {task}\nPlan:"
    print("Got input and planning started")
    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        },
        timeout=120000
    )

    response.raise_for_status()
    text = response.json()["response"]
    print("planning completed")
    return [s.strip() for s in text.split("\n") if s.strip()]
