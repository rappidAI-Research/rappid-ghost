# Synthetic enterprise authorization example

This is a local proof of concept with fictional records. It is not a childcare
application, privacy certification or a production user/tenant identity system.

The application in `app.go` authenticates an employee token and authorizes record
reads. Employee A in tenant A may read case_A; case_B belongs to another employee
and tenant_B_case_C to another tenant. Agent-supplied tenant/identity fields are
rejected. `Application.Revoke` is callable only by trusted application code, not
through an HTTP tool. The example service maps host SIGHUP to revocation of
employee A only. `NewForEmployees` accepts trusted application-provisioned
employee/tenant/role labels and explicit record assignments, copies them, and
rejects assignments to another tenant's record. Role labels grant no rights.

## Complete local reference workflow

From the repository, with native Linux amd64 Docker Engine/BuildKit, Go 1.26.11,
Python 3, curl, OpenSSL and GNU timeout:

```sh
make build
sh scripts/test-ollama.sh
```

The orchestrator provisions the pinned patched CPU Ollama service and authenticated
TLS edge, then calls `scripts/test-enterprise-local.sh` with that exact origin,
certificate and synthetic credential. The reference creates two fresh projects,
source-reviewed JSON/YAML policy, a separate loopback-TLS application, and distinct
random model/employee credentials. `ghost init` validates each existing policy;
`ghost doctor --json` diagnoses it; `ghost run workflow.py ...` executes the real
LangGraph read -> native local model graph in two concurrent Docker sessions.
The agent has a read-only workspace, no host credential and no direct service or
external route. Drafts go to stdout for human review, not back into a record.

The example deliberately gives Ghost a broader resource ceiling than each
employee's application assignment to prove **both** boundaries independently:
an unassigned same-tenant record, a different tenant, forged tool, extra tenant
argument, ungranted resource and replay all deny. A document includes malicious
instructions; the test explicitly attempts the requested forbidden reads. This
does not claim that the small model reliably resists instructions.

After both real model workflows finish, trusted SIGHUP revokes employee A in the
application. A's next Ghost session must deny its formerly assigned read; B's
independent session must still complete real inference. Raw SQLite/WAL and service
logs are checked for credential/document markers, every session must have clean
completion, and the orchestrator verifies model cleanup. The combined gate requires
`ENTERPRISE_LOCAL_OK` and `OLLAMA_QUALIFICATION_OK`; a missing marker is a failure.
Separate Docker tests cover broker death during a call and crash recovery.

Use only synthetic data. The tiny pinned model qualifies data flow and isolation,
not summary quality. No database writes, record updates, legal authorization,
employee login, production retention policy or privacy certification is provided.
Real deployments must narrow both Ghost and application grants and replace the
fixture identities. Model/service administrators and host operators remain trusted.

## Connect an existing application

Build and run the trusted application outside the agent workspace with a TLS
certificate/key for localhost and a randomly generated synthetic token:

```sh
go build -o bin/enterprise-example ./examples/enterprise/cmd/service
export GHOST_DEMO_EMPLOYEE_TOKEN="$(openssl rand -hex 32)"
./bin/enterprise-example --listen 127.0.0.1:9443 --cert /trusted/cert.pem --key /trusted/key.pem
```

The application is a trusted host service, analogous to an existing company
backend. The untrusted agent still runs only in Ghost Docker. Provision its
explicit policy (complete defaults can be created with `ghost init`):

```yaml
version: 1
profile: sensitive-enterprise
agent: {adapter: command}
runtime: {provider: docker, environment: alpine}
workspace: {mode: read-only}
network: {mode: deny}
policy: {home: deny}
broker:
  ttl_seconds: 600
  max_requests: 64
  application:
    url: https://127.0.0.1:9443
    credential_env: GHOST_DEMO_EMPLOYEE_TOKEN
    # For a self-signed certificate: explicitly set its lowercase SHA-256 here.
  tools:
    - name: documents.read
      effect: read
      parameters: {record_id: string}
      resource_argument: record_id
      resources: [case_A]
```

Use system-trusted TLS or an exact `certificate_sha256` fingerprint obtained
outside the agent. The Ghost controller must receive the synthetic token in its
own environment; never put its value into YAML, argv or the workspace. Build and
run [the MCP example](../mcp-agent/README.md), then `ghost inspect`.

The automated Docker enterprise workflow uses this same application authorizer
and deliberately configures broader Ghost grants to prove the application also
rejects case_B and the other tenant. It proves a second authorized read still
works before a trusted revocation, then denies a subsequent read. A malicious
instruction embedded in the synthetic document cannot grant a tool or resource;
the test explicitly attempts the requested unauthorized operations. This proves
deterministic enforcement, not universal prompt-injection recognition or an LLM's
ability to ignore the instruction. Direct external networking is also denied.

Real deployments must replace this token fixture with authenticated employees,
short-lived application-bound capabilities, tenant/row authorization at each data
operation, output review, retention and host admission controls. The model must
receive only application-approved information. Ghost adds isolation and a scoped
mediation ceiling; it does not supply those business controls or legal compliance.
