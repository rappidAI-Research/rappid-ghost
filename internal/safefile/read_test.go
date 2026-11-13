package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadRejectsSymlinksDevicesAndOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegular(file, 4); err == nil {
		t.Fatal("accepted oversized file")
	}
	if data, err := ReadRegular(file, 5); err != nil || string(data) != "12345" {
		t.Fatalf("%q %v", data, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegular(link, 5); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatal(err)
	}
	if _, err := ReadRegular(dir, 10); err == nil {
		t.Fatal("accepted directory")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadRegular(fifo, 10); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO blocked bounded read")
	}
}
