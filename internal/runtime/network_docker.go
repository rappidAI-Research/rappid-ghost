package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
)

const gatewayHandler = `#!/bin/sh
deny() {
  decision=DENY
  record
  printf 'HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'
  exit 0
}
record() {
  contained=false
  [ -e /run/ghost-observation/contained ] && contained=true
  host=$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')
  case "$host" in ''|*[!a-z0-9.:-]*) host=invalid ;; esac
  case "$method" in ''|*[!A-Z]*) method=INVALID ;; esac
  case "$scheme" in http|https) ;; *) scheme=unknown ;; esac
  case "$port" in ''|*[!0-9]*) port=0 ;; esac
  printf '{"kind":"network","scheme":"%s","host":"%s","port":%s,"method":"%s","decision":"%s","contained":%s,"unix":%s}\n' \
    "$scheme" "$host" "$port" "$method" "$decision" "$contained" "$(date +%s)" >> /run/ghost-observation/events.jsonl
}
normalize_host() {
  host=$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')
  host=${host%.}
  case "$host" in
    ''|*[!a-z0-9.-]*|.*|*..*|*-.*|*.-*) return 1 ;;
  esac
  return 0
}
allowed() {
  [ ! -e /run/ghost-observation/contained ] || return 1
  if [ -e /run/ghost-observation/contain-on-access ]; then
    sleep 0.01
    [ ! -e /run/ghost-observation/contained ] || return 1
  fi
  grep -F -x -q "$host" /run/ghost-policy/allowlist
}

IFS= read -r request_line || exit 0
request_line=$(printf '%s' "$request_line" | tr -d '\r')
set -- $request_line
[ "$#" -eq 3 ] || exit 0
method=$1
target=$2
version=$3
scheme=
host=invalid
port=0

if [ "$method" = CONNECT ]; then
  scheme=https
  case "$target" in
    \[*\]:*) host=${target#\[}; host=${host%%\]*}; port=${target##*:} ;;
    *:*:*) host=$target; port=0; deny ;;
    *:*) host=${target%:*}; port=${target##*:} ;;
    *) deny ;;
  esac
  [ "$port" = 443 ] || deny
else
  scheme=http
  case "$method" in GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) ;; *) deny ;; esac
  case "$target" in http://*) ;; *) deny ;; esac
  rest=${target#http://}
  authority=${rest%%/*}
  case "$authority" in ''|*@*|*:*:*) deny ;; esac
  if [ "${authority#*:}" != "$authority" ]; then
    host=${authority%:*}
    port=${authority##*:}
  else
    host=$authority
    port=80
  fi
  [ "$port" = 80 ] || deny
  path=${rest#"$authority"}
  [ -n "$path" ] || path=/
fi

normalize_host || deny
case "$host" in
  *[!0-9.]* ) ;;
  * ) deny ;;
esac
if ! allowed; then
  deny
fi

decision=ALLOW
record
if [ "$method" = CONNECT ]; then
  while IFS= read -r header; do
    header=$(printf '%s' "$header" | tr -d '\r')
    [ -n "$header" ] || break
  done
  printf 'HTTP/1.1 200 Connection Established\r\n\r\n'
  exec nc -w 30 "$host" "$port"
fi

fifo=/tmp/ghost-proxy.$$
mkfifo "$fifo" || deny
{
  printf '%s %s %s\r\n' "$method" "$path" "$version"
  while IFS= read -r header; do
    header=$(printf '%s' "$header" | tr -d '\r')
    [ -n "$header" ] || break
    header_name=${header%%:*}
    header_name=$(printf '%s' "$header_name" | tr '[:upper:]' '[:lower:]')
    case "$header_name" in host|proxy-authorization|proxy-connection) continue ;; esac
    printf '%s\r\n' "$header"
  done
  printf 'Host: %s\r\n' "$host"
  printf '\r\n'
  cat
} > "$fifo" &
producer=$!
nc -w 30 "$host" "$port" < "$fifo"
status=$?
kill "$producer" 2>/dev/null || true
rm -f "$fifo"
exit "$status"
`

type observationPaths struct {
	dir         string
	events      string
	control     string
	contained   string
	sentinelBin string
}

func prepareObservation(request RunRequest) (observationPaths, error) {
	if request.SessionID == "" || request.SessionDir == "" {
		return observationPaths{}, errors.New("session identity is required for runtime observation")
	}
	if !safeContainerComponent.MatchString(request.SessionID) {
		return observationPaths{}, errors.New("invalid session identity for runtime observation")
	}
	dir := filepath.Join(request.SessionDir, "observation")
	if err := os.Mkdir(dir, 0o700); err != nil {
		return observationPaths{}, fmt.Errorf("create observation directory: %w", err)
	}
	paths := observationPaths{
		dir: dir, events: filepath.Join(dir, "events.jsonl"),
		control: filepath.Join(dir, "control"), contained: filepath.Join(dir, "contained"),
		sentinelBin: filepath.Join(request.SessionDir, "sentinel-handler"),
	}
	if err := writeExclusive(paths.events, nil, 0o600); err != nil {
		return observationPaths{}, fmt.Errorf("create observation log: %w", err)
	}
	if err := writeExclusive(paths.control, nil, 0o600); err != nil {
		return observationPaths{}, fmt.Errorf("create sentinel control: %w", err)
	}
	if err := writeExclusive(paths.sentinelBin, []byte(sentinelHandler), 0o700); err != nil {
		return observationPaths{}, fmt.Errorf("create sentinel handler: %w", err)
	}
	if request.ContainOnDecoy && len(request.ShadowResources) > 0 {
		if err := writeExclusive(filepath.Join(dir, "contain-on-access"), nil, 0o600); err != nil {
			return observationPaths{}, fmt.Errorf("create containment policy marker: %w", err)
		}
	}
	return paths, nil
}

type networkBoundary struct {
	binary        string
	agentNetwork  string
	egressNetwork string
	gatewayName   string
	gatewayIP     string
}

func (d *DockerRuntime) startNetworkBoundary(ctx context.Context, request RunRequest, observation observationPaths) (*networkBoundary, error) {
	if request.NetworkPolicy.Mode != ghostnetwork.Allowlist {
		return nil, nil
	}
	suffix := strings.ToLower(request.SessionID)
	boundary := &networkBoundary{
		binary: d.binary, agentNetwork: "ghost-agent-" + suffix,
		egressNetwork: "ghost-egress-" + suffix, gatewayName: "ghost-gateway-" + suffix,
	}
	cleanup := func(cause error) (*networkBoundary, error) {
		_ = boundary.stop()
		return nil, cause
	}
	if err := d.createNetwork(ctx, boundary.agentNetwork, request.SessionID, true); err != nil {
		return cleanup(err)
	}
	if err := d.createNetwork(ctx, boundary.egressNetwork, request.SessionID, false); err != nil {
		return cleanup(err)
	}

	networkDir := filepath.Join(request.SessionDir, "network")
	if err := os.Mkdir(networkDir, 0o700); err != nil {
		return cleanup(fmt.Errorf("create gateway directory: %w", err))
	}
	handler := filepath.Join(networkDir, "gateway-handler")
	allowlist := filepath.Join(networkDir, "allowlist")
	if err := writeExclusive(handler, []byte(gatewayHandler), 0o700); err != nil {
		return cleanup(fmt.Errorf("create gateway handler: %w", err))
	}
	if err := writeExclusive(allowlist, []byte(strings.Join(request.NetworkPolicy.Allow, "\n")+"\n"), 0o600); err != nil {
		return cleanup(fmt.Errorf("create gateway allowlist: %w", err))
	}

	args := d.gatewayArguments(boundary, request, handler, allowlist, observation.dir)
	if output, err := exec.CommandContext(ctx, d.binary, args...).CombinedOutput(); err != nil {
		return cleanup(fmt.Errorf("start egress gateway: %s", lastMessage(string(output))))
	}
	if output, err := exec.CommandContext(ctx, d.binary, "network", "connect", boundary.agentNetwork, boundary.gatewayName).CombinedOutput(); err != nil {
		return cleanup(fmt.Errorf("connect egress gateway to agent network: %s", lastMessage(string(output))))
	}
	if d.gatewayUpstreamNetwork != "" {
		if output, err := exec.CommandContext(ctx, d.binary, "network", "connect", d.gatewayUpstreamNetwork, boundary.gatewayName).CombinedOutput(); err != nil {
			return cleanup(fmt.Errorf("connect controlled upstream network: %s", lastMessage(string(output))))
		}
	}
	format := "{{(index .NetworkSettings.Networks " + fmt.Sprintf("%q", boundary.agentNetwork) + ").IPAddress}}"
	output, err := exec.CommandContext(ctx, d.binary, "inspect", "--format", format, boundary.gatewayName).CombinedOutput()
	if err != nil {
		return cleanup(fmt.Errorf("inspect egress gateway address: %s", lastMessage(string(output))))
	}
	boundary.gatewayIP = strings.TrimSpace(string(output))
	if boundary.gatewayIP == "" {
		return cleanup(errors.New("egress gateway has no agent-network address"))
	}
	if err := boundary.waitReady(ctx); err != nil {
		return cleanup(err)
	}
	return boundary, nil
}

func (d *DockerRuntime) createNetwork(ctx context.Context, name, sessionID string, internal bool) error {
	args := []string{"network", "create", "--driver", "bridge", "--label", "ghost.component=network", "--label", "ghost.session=" + sessionID}
	if internal {
		args = append(args, "--internal")
	}
	args = append(args, name)
	if output, err := exec.CommandContext(ctx, d.binary, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("create per-session network: %s", lastMessage(string(output)))
	}
	return nil
}

func (d *DockerRuntime) gatewayArguments(boundary *networkBoundary, request RunRequest, handler, allowlist, observation string) []string {
	args := []string{
		"run", "--detach", "--name", boundary.gatewayName,
		"--label", "ghost.component=gateway", "--label", "ghost.session=" + request.SessionID,
		"--network", boundary.egressNetwork,
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--pids-limit", "64", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m",
		"--mount", "type=bind,src=" + handler + ",dst=/run/ghost-policy/gateway-handler,readonly",
		"--mount", "type=bind,src=" + allowlist + ",dst=/run/ghost-policy/allowlist,readonly",
		"--mount", "type=bind,src=" + observation + ",dst=/run/ghost-observation",
		"--env", "PATH=" + guestPath,
	}
	if identity := numericUser(); identity != "" {
		args = append(args, "--user", identity)
	}
	args = append(args, d.image, "nc", "-ll", "-p", "8080", "-e", "/run/ghost-policy/gateway-handler")
	return args
}

func (n *networkBoundary) waitReady(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		output, err := exec.CommandContext(ctx, n.binary, "exec", n.gatewayName, "netstat", "-ltn").CombinedOutput()
		if err == nil && strings.Contains(string(output), ":8080") {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("egress gateway readiness: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (n *networkBoundary) proxyURL() string {
	return "http://" + n.gatewayIP + ":8080"
}

func (n *networkBoundary) stop() error {
	var result error
	if n.gatewayName != "" {
		if output, err := dockerCleanup(n.binary, "rm", "--force", n.gatewayName); err != nil && !strings.Contains(string(output), "No such container") {
			result = errors.Join(result, fmt.Errorf("remove egress gateway: %s", lastMessage(string(output))))
		}
	}
	for _, name := range []string{n.agentNetwork, n.egressNetwork} {
		if name == "" {
			continue
		}
		if output, err := dockerCleanup(n.binary, "network", "rm", name); err != nil && !strings.Contains(string(output), "not found") {
			result = errors.Join(result, fmt.Errorf("remove per-session network: %s", lastMessage(string(output))))
		}
	}
	return result
}
