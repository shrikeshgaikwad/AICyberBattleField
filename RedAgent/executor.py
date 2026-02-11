import pyautogui
import time
import os

def execute(step: str):
    if "OPEN_APP" in step:
        app = step.split("(")[1].split(")")[0]
        os.system(f"start {app}")

    elif "TYPE" in step:
        text = step.split("(")[1].split(")")[0]
        pyautogui.write(text, interval=0.05)

    elif "PRESS" in step:
        key = step.split("(")[1].split(")")[0]
        pyautogui.press(key)

    elif "WAIT" in step:
        sec = float(step.split("(")[1].split(")")[0])
        time.sleep(sec)
