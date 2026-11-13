package cli

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rappidAI-research/rappid-ghost/internal/broker"
	"github.com/rappidAI-research/rappid-ghost/internal/config"
)

func TestDockerBrokerAgentCannotConnectWorkspaceHostSocket(t *testing.T) {
	binary := integrationBinary(t)
	t.Setenv("GHOST_FIXTURE_UPSTREAM_TOKEN", "synthetic-ipc")
	var requests atomic.Int64
	_, endpoint := brokerFixtureEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	cfg := config.Default()
	cfg.Agent.Adapter = "python"
	cfg.Runtime.Environment = "python"
	cfg.Policy.Home = "deny"
	cfg.Broker.Model = &broker.Model{Endpoint: endpoint, Name: "ghost-fixture"}
	root := integrationProject(t, cfg)
	listener, err := net.Listen("unix", filepath.Join(root, "forbidden.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepts atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_, _ = conn.Write([]byte("READY"))
			conn.Close()
		}
	}()
	defer func() { listener.Close(); <-done }()
	// A real unmediated control demonstrates the live workspace IPC exposure.
	controlCfg := cfg
	controlCfg.Broker = broker.Config{}
	writeIntegrationConfig(t, root, controlCfg)
	control := `import socket
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
 s.connect('/workspace/forbidden.sock')
 assert s.recv(5)==b'READY'
print('LEGACY_IPC_CONTROL_REACHED')
`
	if err = os.WriteFile(filepath.Join(root, "control.py"), []byte(control), 0600); err != nil {
		t.Fatal(err)
	}
	controlOut, controlErr := runIntegrationCLI(t, binary, root, "run", "control.py")
	if controlErr != nil || !strings.Contains(controlOut, "LEGACY_IPC_CONTROL_REACHED") || accepts.Load() != 1 {
		t.Fatalf("IPC positive control %v %s", controlErr, controlOut)
	}
	writeIntegrationConfig(t, root, cfg)
	script := `import os,socket,json,urllib.request,errno
# Live bind exposure of a host socket must not become an unmediated capability.
for family in [socket.AF_UNIX,getattr(socket,'AF_VSOCK',40),socket.AF_NETLINK]:
 try:s=socket.socket(family,socket.SOCK_STREAM)
 except PermissionError:pass
 else:s.close();raise AssertionError('prohibited socket family')
try:socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
except PermissionError:pass
else:raise AssertionError('retargetable datagram pair')
a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
for shutdown in [False,True]:
 if shutdown:a.shutdown(socket.SHUT_RDWR)
 try:a.connect('/workspace/forbidden.sock')
 except OSError:pass
 else:raise AssertionError('anonymous stream pair retargeted')
a.close();b.close()
try:open('/proc/'+str(os.getppid())+'/mem','rb')
except PermissionError:pass
else:raise AssertionError('trusted bridge memory exposed')
try:os.listdir('/proc/'+str(os.getppid())+'/fd')
except PermissionError:pass
else:raise AssertionError('trusted bridge descriptors exposed')
# The permitted loopback/broker route remains usable after the extra filter.
request=urllib.request.Request(os.environ['OPENAI_BASE_URL']+'/responses',data=json.dumps({'model':os.environ['GHOST_MODEL'],'input':'synthetic IPC test'}).encode(),headers={'Content-Type':'application/json'})
with urllib.request.urlopen(request,timeout=5) as response:assert json.load(response)['ok']
print('HOST_IPC_BOUNDARY_OK')
`
	if err = os.WriteFile(filepath.Join(root, "agent.py"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := runIntegrationCLI(t, binary, root, "run", "agent.py")
	if err != nil || !strings.Contains(out, "HOST_IPC_BOUNDARY_OK") || accepts.Load() != 1 || requests.Load() != 1 {
		t.Fatalf("IPC bypass err=%v accepted=%d model=%d\n%s", err, accepts.Load(), requests.Load(), out)
	}
}
