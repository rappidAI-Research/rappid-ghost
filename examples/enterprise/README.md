# Synthetic enterprise authorization example

This is a local proof of concept with fictional records. It is not a childcare
application, privacy certification or a production user/tenant identity system.

The application in `app.go` authenticates an employee token and authorizes record
reads. Employee A in tenant A may read case_A; case_B belongs to another employee
and tenant_B_case_C to another tenant. Agent-supplied tenant/identity fields are
rejected. `Application.Revoke` is callable only by trusted application code, not
through an HTTP tool. The example service maps host SIGHUP to revocation.

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
