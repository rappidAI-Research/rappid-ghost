"""Actual local inference through Ghost, using only Python's standard library.

The tiny qualification model proves transport/inference, not useful clinical or
administrative reasoning. Input is synthetic and never contains personal data.
"""
import json
import os
import socket
import sys
import urllib.request

assert "GHOST_LOCAL_MODEL_TOKEN" not in os.environ
assert "GHOST_FIXTURE_UPSTREAM_TOKEN" not in os.environ
# Neither the host model endpoint nor another internal/external service can be
# reached through the agent network. Only the guest bridge is available.
for host, port in [(sys.argv[1], int(sys.argv[2])), ("1.1.1.1", 443)]:
    with socket.socket() as connection:
        connection.settimeout(0.3)
        try:
            connection.connect((host, port))
        except OSError:
            pass
        else:
            raise AssertionError("direct network bypass")

payload = {
    "model": os.environ["GHOST_MODEL"],
    "messages": [{"role": "user", "content": "Continue this synthetic story: Once upon a time"}],
    "max_tokens": 24,
    "temperature": 0,
}
request = urllib.request.Request(
    os.environ["OPENAI_BASE_URL"] + "/chat/completions",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(request, timeout=30) as response:
    result = json.load(response)
text = result["choices"][0]["message"]["content"]
assert isinstance(text, str) and text.strip(), "model returned no generated text"
assert result["usage"]["completion_tokens"] > 0, "no actual inference tokens"
print(json.dumps({"status": "LOCAL_INFERENCE_OK", "generated_tokens": result["usage"]["completion_tokens"], "text": text}))
