"""Actual local native Ollama chat; synthetic inputs, no host credentials."""
import json
import os
import socket
import sys
import urllib.error
import urllib.request


def denied_connection(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.4):
            raise AssertionError("direct-service bypass")
    except OSError:
        pass


def infer(text):
    assert os.environ["GHOST_MODEL_PROTOCOL"] == "ollama-chat-v1"
    assert "GHOST_OLLAMA_EDGE_TOKEN" not in os.environ
    call = {"model": os.environ["GHOST_MODEL"], "messages": [{"role": "user", "content": text}],
            "stream": False, "options": {"num_predict": 24, "num_ctx": 1024}}
    request = urllib.request.Request(os.environ["OLLAMA_HOST"] + "/api/chat",
                                     data=json.dumps(call).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        # Ghost emits a static closed reason here, never the upstream body.
        reason = error.read(512).decode("utf-8", "replace")
        raise RuntimeError(f"Ghost denied local inference ({error.code}): {reason}") from None
    assert result["done"] and 0 < result["eval_count"] <= 24
    assert result["message"]["role"] == "assistant" and result["message"]["content"]
    return result


if __name__ == "__main__":
    denied_connection(sys.argv[1], 11434)
    denied_connection("198.51.100.1", 443)
    # A registered model route never grants administration or another model.
    for route, body in [("/api/pull", {"model": "foreign"}),
                        ("/api/chat", {"model": "foreign", "messages": [{"role": "user", "content": "x"}], "stream": False})]:
        try:
            req = urllib.request.Request(os.environ["OLLAMA_HOST"] + route, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("ungranted model operation succeeded")
        except urllib.error.HTTPError as error:
            assert error.code in (400, 403, 404)
    result = infer("SYNTHETIC_OLLAMA_PROMPT: Continue this fictional story: Once upon a time, a")
    print(json.dumps({"status": "OLLAMA_INFERENCE_OK", "generated_tokens": result["eval_count"],
                      "text": result["message"]["content"]}))
