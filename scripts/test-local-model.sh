#!/bin/sh
# Reproducible CPU inference qualification/demo. No real personal data or paid
# model API is used. All downloads happen before any untrusted agent starts.
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ghost_bin=${GHOST_BIN:-"$repo_dir/bin/ghost"}
case "$ghost_bin" in /*) ;; *) echo 'GHOST_BIN must be absolute' >&2; exit 1;; esac
test -x "$ghost_bin"
command -v docker >/dev/null
command -v openssl >/dev/null
model_image='ghcr.io/ggml-org/llama.cpp:server@sha256:e3032ea0712da96dec820c770626385de4322dd06619fb5829256a504bbc9375'
model_url='https://huggingface.co/ggml-org/SmolLM2-135M-GGUF/resolve/1076b85d135017971845b19b8d07df1479155988/SmolLM2-135M-Q4_K_M.gguf'
model_sha='e3131339bf4e8065265593d4fd8f7bb7ff2d3abff1edb5618aa1197b89cad9f5'
demo_dir=$(mktemp -d)
model_container=''
model_network=''
cleanup() {
 if [ -n "$model_container" ]; then docker rm --force "$model_container" >/dev/null 2>&1 || true; fi
 if [ -n "$model_network" ]; then docker network rm "$model_network" >/dev/null 2>&1 || true; fi
 rm -rf -- "$demo_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$demo_dir/service" "$demo_dir/project"
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' --tlsv1.2 --max-time 180 --max-filesize 110000000 "$model_url" -o "$demo_dir/service/model.gguf"
printf '%s  %s\n' "$model_sha" "$demo_dir/service/model.gguf" | sha256sum --check
GHOST_LOCAL_MODEL_TOKEN=$(openssl rand -hex 32)
export GHOST_LOCAL_MODEL_TOKEN
printf '%s\n' "$GHOST_LOCAL_MODEL_TOKEN" > "$demo_dir/service/token"
chmod 600 "$demo_dir/service/token"
model_network=$(docker network create --internal "ghost-local-demo-$(basename "$demo_dir")")
# Start only a bounded waiting shell so Docker can assign its own unused IPAM
# address before the TLS certificate is generated for that exact address.
model_container=$(docker run --detach --rm --network "$model_network" --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --read-only --pids-limit 128 --memory 1g --memory-swap 1g --cpus 2 --log-driver none --tmpfs /tmp:rw,nosuid,nodev,size=32m --mount "type=bind,src=$demo_dir/service,dst=/model,readonly" --entrypoint /bin/sh "$model_image" -c 'for i in $(seq 1 240); do if [ -f /model/ready ]; then exec /app/llama-server "$@"; fi; sleep 0.25; done; exit 1' ghost-local-model --model /model/model.gguf --alias ghost-local-test --host 0.0.0.0 --port 8443 --ctx-size 1024 --parallel 1 --threads 2 --n-predict 64 --chat-template chatml --api-key-file /model/token --ssl-key-file /model/key.pem --ssl-cert-file /model/cert.pem --timeout 30)
model_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$model_container")
python3 -c 'import ipaddress,sys; assert ipaddress.ip_address(sys.argv[1]).version==4' "$model_ip"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj '/CN=localhost' -addext "subjectAltName=IP:$model_ip,DNS:localhost" -keyout "$demo_dir/service/key.pem" -out "$demo_dir/service/cert.pem" >/dev/null 2>&1
chmod 600 "$demo_dir/service/key.pem"
touch "$demo_dir/service/ready"
model_address="$model_ip:8443"
ready=0
for attempt in $(seq 1 120); do
 if curl --fail --silent --cacert "$demo_dir/service/cert.pem" --max-time 1 "https://$model_address/health" >/dev/null; then ready=1; break; fi
 test "$(docker inspect --format '{{.State.Running}}' "$model_container")" = true
 sleep 0.25
done
test "$ready" = 1
cert_pin=$(openssl x509 -in "$demo_dir/service/cert.pem" -outform DER | sha256sum | cut -d ' ' -f 1)
cp "$repo_dir/examples/local-model/agent.py" "$demo_dir/project/agent.py"
cd "$demo_dir/project"
"$ghost_bin" init --integration python --profile document-processing --model-url "https://$model_address" --model-name ghost-local-test --credential-env GHOST_LOCAL_MODEL_TOKEN --certificate-sha256 "$cert_pin"
"$ghost_bin" doctor --json
"$ghost_bin" run agent.py "$model_ip" 8443 > "$demo_dir/result.txt"
cat "$demo_dir/result.txt"
grep -q 'LOCAL_INFERENCE_OK' "$demo_dir/result.txt"
# Credentials/prompt/document content must not enter the durable event store.
"$ghost_bin" graph --json > "$demo_dir/graph.json"
if grep -q "$GHOST_LOCAL_MODEL_TOKEN" "$demo_dir/graph.json"; then echo 'Credential leaked into audit' >&2;exit 1;fi
printf 'Local model qualification passed (real llama.cpp inference; synthetic text only).\n'
