#!/bin/sh
# Real native Ollama inference. All data and credentials are synthetic.
set -eu
umask 077
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ghost_bin=${GHOST_BIN:-"$repo_dir/bin/ghost"}
case "$ghost_bin" in /*) ;; *) echo 'GHOST_BIN must be absolute' >&2; exit 1;; esac
test -x "$ghost_bin"
demo_dir=$(mktemp -d)
model_container=''
model_network=''
edge_pid=''
cleanup() {
 demo_cleanup_failed=0
 if [ -n "$edge_pid" ]; then kill "$edge_pid" 2>/dev/null || true; wait "$edge_pid" 2>/dev/null || true; edge_pid=''; fi
 if [ -n "$model_container" ]; then
  if docker rm --force "$model_container" >/dev/null; then model_container=''; else demo_cleanup_failed=1; fi
 fi
 if [ -n "$model_network" ]; then
  if docker network rm "$model_network" >/dev/null; then model_network=''; else demo_cleanup_failed=1; fi
 fi
 if [ "$demo_cleanup_failed" = 0 ]; then rm -rf -- "$demo_dir"; else echo 'Ollama demo cleanup could not be verified; retain the reported Docker IDs for reconciliation.' >&2; fi
 return "$demo_cleanup_failed"
}
trap 'demo_exit_status=$?; if [ "$demo_exit_status" != 0 ] && [ -n "$model_container" ]; then docker logs --tail 35 "$model_container" >&2 || true; fi; cleanup || demo_exit_status=1; exit "$demo_exit_status"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
mkdir "$demo_dir/input" "$demo_dir/cache" "$demo_dir/project" "$demo_dir/edge"
model_image=$(sh "$repo_dir/scripts/build-ollama-service.sh")
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' --tlsv1.2 --max-time 180 --max-filesize 110000000 'https://huggingface.co/ggml-org/SmolLM2-135M-GGUF/resolve/1076b85d135017971845b19b8d07df1479155988/SmolLM2-135M-Q4_K_M.gguf' -o "$demo_dir/input/model.gguf"
printf '%s  %s\n' e3131339bf4e8065265593d4fd8f7bb7ff2d3abff1edb5618aa1197b89cad9f5 "$demo_dir/input/model.gguf" | sha256sum --check
cat > "$demo_dir/input/Modelfile" <<'MODEL'
FROM /input/model.gguf
TEMPLATE """{{ if .System }}<|im_start|>system
{{ .System }}<|im_end|>
{{ end }}{{ if .Prompt }}<|im_start|>user
{{ .Prompt }}<|im_end|>
{{ end }}<|im_start|>assistant
{{ .Response }}"""
PARAMETER num_ctx 1024
PARAMETER num_predict 24
PARAMETER num_thread 2
PARAMETER temperature 0
MODEL
model_network=$(docker network create --internal "ghost-ollama-demo-$(basename "$demo_dir")")
model_container=$(docker create --network "$model_network" --label ghost.demo=ollama-v06 --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --read-only --pids-limit 256 --memory 2g --memory-swap 2g --cpus 2 --log-driver json-file --log-opt max-size=1m --log-opt max-file=1 --tmpfs /tmp:rw,nosuid,nodev,size=128m --mount "type=bind,src=$demo_dir/input,dst=/input,readonly" --mount "type=bind,src=$demo_dir/cache,dst=/models" -e HOME=/tmp -e OLLAMA_MODELS=/models -e OLLAMA_NO_CLOUD=1 -e OLLAMA_DEBUG=false -e OLLAMA_DEBUG_LOG_REQUESTS=false -e OLLAMA_NUM_PARALLEL=1 -e OLLAMA_MAX_LOADED_MODELS=1 -e OLLAMA_KEEP_ALIVE=0 "$model_image")
docker start "$model_container" >/dev/null
model_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$model_container")
python3 -c 'import ipaddress,sys; assert ipaddress.ip_address(sys.argv[1]).is_private' "$model_ip"
ready=0
for attempt in $(seq 1 100); do
 if curl --noproxy '*' --fail --silent --max-time 1 "http://$model_ip:11434/api/version" > "$demo_dir/version.json"; then ready=1; break; fi
 test "$(docker inspect --format '{{.State.Running}}' "$model_container")" = true
 sleep 0.25
done
test "$ready" = 1
python3 -c 'import json,sys;assert json.load(open(sys.argv[1]))["version"]=="0.40.16-ghost.1"' "$demo_dir/version.json"
timeout 90 docker exec -e OLLAMA_HOST=http://127.0.0.1:11434 "$model_container" /usr/bin/ollama create ghost-smollm:qualified -f /input/Modelfile
GHOST_OLLAMA_EDGE_TOKEN=$(openssl rand -hex 32)
export GHOST_OLLAMA_EDGE_TOKEN
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj '/CN=localhost' -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' -keyout "$demo_dir/edge/key.pem" -out "$demo_dir/edge/cert.pem" >/dev/null 2>&1
(cd "$repo_dir" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$demo_dir/edge/service" ./examples/ollamaedge/cmd/service)
"$demo_dir/edge/service" --upstream "http://$model_ip:11434" --model ghost-smollm:qualified --cert "$demo_dir/edge/cert.pem" --key "$demo_dir/edge/key.pem" --ready "$demo_dir/edge/ready.json" > "$demo_dir/edge/service.log" 2>&1 &
edge_pid=$!
for attempt in $(seq 1 100); do
 if test -s "$demo_dir/edge/ready.json"; then break; fi
 kill -0 "$edge_pid"
 sleep 0.1
done
model_url=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["url"])' "$demo_dir/edge/ready.json")
cert_pin=$(openssl x509 -in "$demo_dir/edge/cert.pem" -outform DER | sha256sum | cut -d ' ' -f 1)
# Even the host-side edge refuses unauthenticated inference.
test "$(curl --noproxy '*' --silent --cacert "$demo_dir/edge/cert.pem" --max-time 3 --output /dev/null --write-out '%{http_code}' "$model_url/api/chat")" = 401
cp "$repo_dir/examples/ollama-agent/agent.py" "$demo_dir/project/agent.py"
cd "$demo_dir/project"
"$ghost_bin" init --integration python --profile document-processing --model-protocol ollama-chat-v1 --model-url "$model_url" --model-name ghost-smollm:qualified --max-output-tokens 24 --credential-env GHOST_OLLAMA_EDGE_TOKEN --certificate-sha256 "$cert_pin"
"$ghost_bin" doctor --json
"$ghost_bin" run agent.py "$model_ip" > "$demo_dir/result.json"
cat "$demo_dir/result.json"
grep -q OLLAMA_INFERENCE_OK "$demo_dir/result.json"
"$ghost_bin" graph --json > "$demo_dir/graph.json"
# The same real local service also exercises the exact closed framework bundle.
mkdir "$demo_dir/framework"
cp "$repo_dir/examples/ollama-agent/agent.py" "$demo_dir/framework/agent.py"
cp "$repo_dir/examples/ollama-agent/graph.py" "$demo_dir/framework/graph.py"
cd "$demo_dir/framework"
"$ghost_bin" init --integration langgraph --profile document-processing --model-protocol ollama-chat-v1 --model-url "$model_url" --model-name ghost-smollm:qualified --max-output-tokens 24 --credential-env GHOST_OLLAMA_EDGE_TOKEN --certificate-sha256 "$cert_pin"
"$ghost_bin" run graph.py "$model_ip" > "$demo_dir/framework-result.json"
cat "$demo_dir/framework-result.json"
grep -q LANGGRAPH_OLLAMA_INFERENCE_OK "$demo_dir/framework-result.json"
python3 - "$demo_dir" <<'CHECK'
import os,pathlib,sys
root=pathlib.Path(sys.argv[1])
for project in ('project','framework'):
    for database in (root/project/'.ghost').glob('ghost.db*'):
        content=database.read_bytes()
        assert os.environ['GHOST_OLLAMA_EDGE_TOKEN'].encode() not in content
        assert b'SYNTHETIC_OLLAMA_PROMPT' not in content
CHECK
if grep -Fq -e "$GHOST_OLLAMA_EDGE_TOKEN" -e SYNTHETIC_OLLAMA_PROMPT "$demo_dir/graph.json"; then echo 'Sensitive payload reached audit export' >&2; exit 1; fi
GHOST_BIN="$ghost_bin" GHOST_DEMO_MODEL_URL="$model_url" GHOST_DEMO_MODEL_PIN="$cert_pin" GHOST_DEMO_MODEL_IP="$model_ip" sh "$repo_dir/scripts/test-enterprise-local.sh"
cleanup
printf 'OLLAMA_QUALIFICATION_OK (real local native inference; synthetic data; cleanup verified).\n'
