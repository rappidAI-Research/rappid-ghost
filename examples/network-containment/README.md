# Local network-containment demonstration

The opt-in Docker integration test is a reproducible local demonstration. It creates a harmless Alpine HTTP fixture on a temporary local Docker network; it needs no internet service, account, credential, or API key.

From the repository root:

```sh
GHOST_DOCKER_INTEGRATION=1 go test ./internal/runtime -run TestDockerNetworkBoundaryIntegration -v
```

The suite demonstrates:

1. an exact allowlisted request receives `ALLOW`;
2. a non-allowlisted hostname and raw IP receive `DENY`;
3. unsetting proxy variables and spawning a child process do not bypass the internal network;
4. an allowlisted request succeeds;
5. the agent reads a synthetic `.env` decoy;
6. the live sentinel activates containment;
7. the immediate next allowlisted request receives `DENY`;
8. temporary agent, gateway, and network resources are absent after the run.

The assertion is intentionally limited to observed ordering and enforcement. It does not claim that any decoy content was placed in a request.
