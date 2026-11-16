"""A real StateGraph using native local inference through Ghost's broker."""
import importlib.metadata
import json
import sys
from typing import TypedDict
from langgraph.graph import StateGraph, START, END
from agent import infer, denied_connection

assert importlib.metadata.version("langgraph") == "1.2.22"
denied_connection(sys.argv[1], 11434)
denied_connection("198.51.100.1", 443)


class State(TypedDict):
    prompt: str
    result: dict


def model_node(state):
    return {"result": infer(state["prompt"])}


graph = StateGraph(State)
graph.add_node("local_model", model_node)
graph.add_edge(START, "local_model")
graph.add_edge("local_model", END)
result = graph.compile().invoke({"prompt": "SYNTHETIC_OLLAMA_PROMPT: Continue this fictional story: Once upon a time, a", "result": {}})["result"]
print(json.dumps({"status": "LANGGRAPH_OLLAMA_INFERENCE_OK", "generated_tokens": result["eval_count"],
                  "text": result["message"]["content"]}))
