"""Offline, standard-library agent entrypoint; it does not call an LLM.

Accept a task over stdin, inspect the explicitly mounted workspace and emit a
structured result. Replace the task logic with your own reviewed application.
"""
import json
import sys
from pathlib import Path


def main():
    task = json.loads(sys.stdin.read(4097))
    if not isinstance(task, dict) or task.get("action") != "inventory":
        raise ValueError('expected {"action":"inventory"}')
    # Do not include file contents, hidden state or absolute host paths.
    names = sorted(p.name for p in Path(".").iterdir() if not p.name.startswith("."))
    print(json.dumps({"status": "completed", "files": names}))


if __name__ == "__main__":
    main()
