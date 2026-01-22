from openai import OpenAI
import os

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
You are a planning AI.
Convert the user's command into ordered desktop actions.

Allowed actions ONLY:
- OPEN_APP(name)
- CLICK(x,y)
- TYPE(text)
- PRESS(key)
- WAIT(seconds)

Return ONLY a numbered list, no explanations.
"""

def plan(task: str) -> list[str]:
    response = client.chat.completions.create(
        model="gpt-4o-mini",   # fast + cheap; change later if needed
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": task}
        ],
        temperature=0
    )

    steps_text = response.choices[0].message.content
    steps = [s.strip() for s in steps_text.split("\n") if s.strip()]
    return steps
