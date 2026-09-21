"""Instrument a verified, disposable containerd source checkout in CI only."""
import sys
from pathlib import Path

root = Path(sys.argv[1])
path = root / "internal/oom/watcher.go"
s = path.read_text()
s = s.replace('"errors"', '"errors"\n "context"\n "github.com/containerd/log"')
s = s.replace('eventFD, err := memoryEventNonBlockFD(cgroupPath)',
    'log.G(context.Background()).WithFields(log.Fields{"cid": cid, "path": cgroupPath, "pid": pid}).Info("GHOST_DIAG add watcher")\n eventFD, err := memoryEventNonBlockFD(cgroupPath)')
s = s.replace('bytesRead, err := w.eventFD.Read(buffer)',
    'bytesRead, err := w.eventFD.Read(buffer)\n log.G(context.Background()).WithFields(log.Fields{"cid": w.cid, "n": bytesRead, "error": err}).Info("GHOST_DIAG wake")')
s = s.replace('if err := readKVStatsFile(w.cgroupPath, "memory.events", out); err != nil {',
    'readErr := readKVStatsFile(w.cgroupPath, "memory.events", out)\n log.G(context.Background()).WithFields(log.Fields{"cid": w.cid, "path": w.cgroupPath, "out": out, "error": readErr, "stopping": shouldExit}).Info("GHOST_DIAG counters")\n if err := readErr; err != nil {')
s = s.replace('w.eventFn(w.cid)',
    'log.G(context.Background()).WithField("cid", w.cid).Info("GHOST_DIAG publish OOM")\n w.eventFn(w.cid)')
s = s.replace('cerr := w.eventFD.Close()',
    'log.G(context.Background()).WithField("cid", w.cid).Info("GHOST_DIAG stop")\n cerr := w.eventFD.Close()')
assert s.count('GHOST_DIAG') == 5
path.write_text(s)
