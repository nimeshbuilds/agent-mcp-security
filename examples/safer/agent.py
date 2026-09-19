"""Limited safer comparison fixture; not proof of system security."""
import json
import subprocess


def version():
    return subprocess.run(["python3", "--version"], shell=False, timeout=2, check=True, capture_output=True)


def parse_message(text):
    if len(text) > 1024:
        raise ValueError("message too large")
    data = json.loads(text)
    if not isinstance(data, dict) or set(data) != {"message"}:
        raise ValueError("unexpected shape")
    return data
