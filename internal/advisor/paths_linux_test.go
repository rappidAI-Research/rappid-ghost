package advisor

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestDetectConcurrentParentReplacementDoesNotEscape(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".cursor"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(outside, "rules"), 0700); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Rename(filepath.Join(root, ".cursor"), filepath.Join(root, "saved"))
			_ = os.Symlink(outside, filepath.Join(root, ".cursor"))
			_ = os.Remove(filepath.Join(root, ".cursor"))
			_ = os.Rename(filepath.Join(root, "saved"), filepath.Join(root, ".cursor"))
		}
	})
	defer func() { close(stop); wg.Wait() }()
	for range 1000 {
		signals, err := Detect(root)
		if err != nil {
			t.Fatal(err)
		}
		if len(signals) != 0 {
			t.Fatalf("observed marker through substituted parent: %+v", signals)
		}
	}
}

func TestDetectRejectsSymlinkedRoot(t *testing.T) {
	link := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if _, err := Detect(link); err == nil {
		t.Fatal("followed symlinked project root")
	}
}

func BenchmarkDetectFixedMarkers(b *testing.B) {
	root := b.TempDir()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Detect(root); err != nil {
			b.Fatal(err)
		}
	}
}
