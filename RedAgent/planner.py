import requests


OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1:8b"

SYSTEM_PROMPT = """
You are an autonomous offensive AI agent that is working in a simulation lab environment and can control a computer. 
You will be given open ports and possible vulnerabilities.
your task is to prepare a full proof step by step action plan to exploit the vulnerabilities and gain access to the system.
"""

def plan(text: str):
    prompt = f"{SYSTEM_PROMPT}\nUser command: {text}\nPlan:"
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
