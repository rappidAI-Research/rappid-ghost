# Closed dependency environments (v0.6 candidate)

A bare Python interpreter does not qualify an agent framework. The additional
`python-langgraph` catalog environment is a separate explicit choice:

```sh
ghost init --integration langgraph
ghost run agent.py
```

The alias selects the existing Python source adapter and the fixed environment;
it grants no model, tool, network or filesystem permission. Existing projects
are never overwritten. Review both fields explicitly when upgrading a policy.
The reviewed closure is in `internal/compat/bundles/langgraph.lock.json`:
LangGraph 1.2.22, Python 3.13.18, native Linux amd64/musl only. It does not accept
project requirements, arbitrary wheels/images, npm scripts, sdists or host packages.

Each binary wheel has a fixed PyPI artifact URL and SHA-256; BuildKit verifies
those bytes before offline installation. `pip --no-index --no-deps --require-hashes`
and `pip check` enforce the complete fixed closure. Pip and ensurepip are removed
from the final read-only runtime. The source image is the existing pinned Python
catalog input; all confinement, IPC restrictions, quotas and broker grants still
apply. LangSmith tracing defaults off; no host tracing credentials are inherited.
Network isolation, not an SDK setting, enforces the egress boundary.

Updating a bundle is a reviewed source change: binary-only resolution for the
exact CPython/musl platform, immutable artifact hashes, archive/metadata review,
license/source inventory, offline dependency verification, final image scan,
real framework execution/inference and all regression/security gates. PyPI
registry assertions/checksums are not independently verified publisher provenance.
Malicious or vulnerable dependencies may still exist inside an isolated runtime;
no claim that a library is trustworthy follows from a version pin alone.

`sh scripts/test-ollama.sh` exercises both standard Python and a real StateGraph
against actual local inference. A separate Docker graph test uses deterministic
model/application fixtures to prove registered reads, foreign-resource/schema
rejection, replay/call budgets, immutable dependency files and broker IPC limits.
No checkpoint database or hosted LangSmith service is required. Arbitrary
LangChain provider packages and every optional framework feature are unqualified.
