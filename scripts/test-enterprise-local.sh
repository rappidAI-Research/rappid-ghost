#!/bin/sh
# Called by test-ollama.sh with its fixed authenticated real local model.
set -eu
umask 077
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${GHOST_BIN:?absolute Ghost binary required}"
: "${GHOST_DEMO_MODEL_URL:?explicit authenticated native-model TLS origin required}"
: "${GHOST_DEMO_MODEL_PIN:?exact model-edge certificate pin required}"
: "${GHOST_DEMO_MODEL_IP:?private model-service address for bypass test required}"
: "${GHOST_OLLAMA_EDGE_TOKEN:?synthetic host model credential required}"
enterprise_dir=$(mktemp -d)
application_pid=''
worker_a=''
worker_b=''
cleanup() {
 for worker in "$worker_a" "$worker_b"; do if test -n "$worker"; then kill "$worker" 2>/dev/null || true; wait "$worker" 2>/dev/null || true; fi; done
 if test -n "$application_pid"; then kill "$application_pid" 2>/dev/null || true; wait "$application_pid" 2>/dev/null || true; fi
 rm -rf -- "$enterprise_dir"
}
trap 'enterprise_status=$?; if test "$enterprise_status" != 0; then for diagnostic in result-A result-B revoked-A after-B application.log; do if test -f "$enterprise_dir/$diagnostic"; then tail -n 20 "$enterprise_dir/$diagnostic" >&2; fi; done; fi; cleanup; exit "$enterprise_status"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
GHOST_DEMO_EMPLOYEE_TOKEN=$(openssl rand -hex 32)
GHOST_DEMO_SECOND_TOKEN=$(openssl rand -hex 32)
export GHOST_DEMO_EMPLOYEE_TOKEN GHOST_DEMO_SECOND_TOKEN
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj '/CN=localhost' -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' -keyout "$enterprise_dir/key.pem" -out "$enterprise_dir/cert.pem" >/dev/null 2>&1
(cd "$repo_dir" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$enterprise_dir/application" ./examples/enterprise/cmd/service)
"$enterprise_dir/application" --listen 127.0.0.1:0 --cert "$enterprise_dir/cert.pem" --key "$enterprise_dir/key.pem" --ready "$enterprise_dir/ready.json" > "$enterprise_dir/application.log" 2>&1 &
application_pid=$!
for attempt in $(seq 1 100); do
 if test -s "$enterprise_dir/ready.json"; then break; fi
 kill -0 "$application_pid"
 sleep 0.1
done
application_url=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["url"])' "$enterprise_dir/ready.json")
application_pin=$(openssl x509 -in "$enterprise_dir/cert.pem" -outform DER | sha256sum | cut -d ' ' -f 1)
python3 - "$enterprise_dir" "$application_url" "$application_pin" <<'CONFIG'
import json,os,pathlib,sys
root=pathlib.Path(sys.argv[1])
for employee,credential in (('A','GHOST_DEMO_EMPLOYEE_TOKEN'),('B','GHOST_DEMO_SECOND_TOKEN')):
    project=root/employee;project.mkdir(mode=0o700)
    # Deliberately broad Ghost resource ceiling proves the application's own
    # independent employee/tenant checks. Real deployments should narrow both.
    cfg={'version':1,'profile':'sensitive-enterprise','agent':{'adapter':'python'},
         'runtime':{'provider':'docker','environment':'python-langgraph'},
         'workspace':{'mode':'read-only'},'network':{'mode':'deny'},'policy':{'home':'deny'},
         'broker':{'version':1,'ttl_seconds':120,'max_requests':32,
           'model':{'url':os.environ['GHOST_DEMO_MODEL_URL'],'certificate_sha256':os.environ['GHOST_DEMO_MODEL_PIN'],
                    'credential_env':'GHOST_OLLAMA_EDGE_TOKEN','protocol':'ollama-chat-v1','name':'ghost-smollm:qualified','max_output_tokens':24},
           'application':{'url':sys.argv[2],'certificate_sha256':sys.argv[3],'credential_env':credential},
           'tools':[{'name':'documents.read','effect':'read','parameters':{'record_id':'string'},
                     'resource_argument':'record_id','resources':['case_A','case_B','tenant_B_case_C'],
                     'max_calls':6,'timeout_millis':2000,'max_result_bytes':4096}]}}
    with (project/'ghost.yaml').open('x') as stream:json.dump(cfg,stream,indent=2)
CONFIG
for employee in A B; do
 cp "$repo_dir/examples/enterprise/workflow.py" "$enterprise_dir/$employee/workflow.py"
 cp "$repo_dir/examples/ollama-agent/agent.py" "$enterprise_dir/$employee/agent.py"
 (cd "$enterprise_dir/$employee" && "$GHOST_BIN" init >/dev/null && "$GHOST_BIN" doctor --json) > "$enterprise_dir/doctor-$employee.json"
done
(cd "$enterprise_dir/A" && exec "$GHOST_BIN" run workflow.py case_A case_B tenant_B_case_C "$GHOST_DEMO_MODEL_IP") > "$enterprise_dir/result-A" 2>&1 &
worker_a=$!
(cd "$enterprise_dir/B" && exec "$GHOST_BIN" run workflow.py tenant_B_case_C case_B case_A "$GHOST_DEMO_MODEL_IP") > "$enterprise_dir/result-B" 2>&1 &
worker_b=$!
status_a=0;wait "$worker_a" || status_a=$?;worker_a=''
status_b=0;wait "$worker_b" || status_b=$?;worker_b=''
cat "$enterprise_dir/result-A" "$enterprise_dir/result-B"
test "$status_a" = 0 && test "$status_b" = 0
grep -q ENTERPRISE_LOCAL_INFERENCE_OK "$enterprise_dir/result-A"
grep -q ENTERPRISE_LOCAL_INFERENCE_OK "$enterprise_dir/result-B"
kill -HUP "$application_pid"
for attempt in $(seq 1 100); do
 if grep -q '^SYNTHETIC_PRIMARY_REVOKED$' "$enterprise_dir/application.log"; then break; fi
 kill -0 "$application_pid"
 sleep 0.1
done
grep -q '^SYNTHETIC_PRIMARY_REVOKED$' "$enterprise_dir/application.log"
(cd "$enterprise_dir/A" && "$GHOST_BIN" run workflow.py case_A case_B tenant_B_case_C "$GHOST_DEMO_MODEL_IP" --expect-revoked) > "$enterprise_dir/revoked-A" 2>&1
grep -q ENTERPRISE_REVOKED_OK "$enterprise_dir/revoked-A"
# A's revocation must not revoke B's independent capability.
(cd "$enterprise_dir/B" && "$GHOST_BIN" run workflow.py tenant_B_case_C case_B case_A "$GHOST_DEMO_MODEL_IP") > "$enterprise_dir/after-B" 2>&1
grep -q ENTERPRISE_LOCAL_INFERENCE_OK "$enterprise_dir/after-B"
python3 - "$enterprise_dir" <<'AUDIT'
import os,pathlib,sqlite3,sys
root=pathlib.Path(sys.argv[1])
secrets=[os.environ[key].encode() for key in ('GHOST_DEMO_EMPLOYEE_TOKEN','GHOST_DEMO_SECOND_TOKEN','GHOST_OLLAMA_EDGE_TOKEN')]
for employee in ('A','B'):
    for file in (root/employee/'.ghost').glob('ghost.db*'):
        content=file.read_bytes()
        assert all(value not in content for value in secrets)
        assert b'SYNTHETIC CASE' not in content and b'ignore all rules' not in content
    db=sqlite3.connect(root/employee/'.ghost/ghost.db')
    assert db.execute("select count(*) from events where type='BROKER_DENIED'").fetchone()[0]>=6
    assert db.execute("select count(*) from sessions where cleanup_pending!=0 or status!='completed'").fetchone()[0]==0
    db.close()
assert all(value not in (root/'application.log').read_bytes() for value in secrets)
AUDIT
printf 'ENTERPRISE_LOCAL_OK (two employees/tenants, real local graph inference, negative authorization, independent revocation, minimal evidence).\n'
