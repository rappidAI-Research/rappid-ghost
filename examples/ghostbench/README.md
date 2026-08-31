# Canonical GhostBench demonstration

This example demonstrates Ghost's central end-to-end sequence without an AI model, real credential, public target, paid API, or attacker infrastructure.

From the repository root:

```sh
make build
./bin/ghost bench --scenario dynamic-containment
```

With Docker available, the scenario must observe:

1. a request to the controlled `allowed.test` fixture is allowed;
2. the guest opens Ghost's synthetic `~/.aws/credentials`;
3. `DECOY_ACCESS` activates deterministic session containment;
4. a later request to `allowed.test` is denied;
5. the stored events reconstruct a containment provenance edge and a `DECOY_ACCESS_WITH_NETWORK_ACTIVITY` incident.

Run the machine-readable form with:

```sh
./bin/ghost bench --scenario dynamic-containment --json
```

If Docker is unavailable, the scenario reports `SKIP`. It must never report `PASS` without executing the assertions. The demonstration establishes observed ordering and enforcement only; it does not prove that decoy content entered a request or infer why the process acted.

For a release gate that rejects both `FAIL` and `SKIP`, run:

```sh
./bin/ghost bench --require-all
```
