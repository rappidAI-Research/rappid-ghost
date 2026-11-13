# Offline Python integration

Requires the v0.4 source/binary and Linux Docker Engine with supported cgroups
and default seccomp. No Python installation on the host is required.

From this directory:

```sh
ghost init
ghost doctor
printf '%s\n' '{"action":"inventory"}' | ghost run agent.py
```

`init` keeps the supplied policy. The adapter selects Python only because this
configuration explicitly names both the Python environment and adapter. The
example consumes a bounded task on stdin, lists visible project file names and
prints JSON. It is an executable application integration, not an LLM or AI model.
The real Docker CLI regression separately checks child processes, argument
preservation, read-only enforcement, SHADOW, containment and host-secret exclusion.

The project is read-only; outputs go to stdout. No network, API key, host Python,
package installation, MCP service or model server is made available. Third-party
frameworks are not installed. Python's own code remains untrusted inside Ghost.
