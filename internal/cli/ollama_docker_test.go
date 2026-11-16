package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerRealNativeOllamaInference(t *testing.T) {
	binary := integrationBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 16*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "sh", "scripts/test-ollama.sh")
	command.Dir = filepath.Join("..", "..")
	command.Env = append(os.Environ(), "GHOST_BIN="+binary)
	data, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(data), "OLLAMA_QUALIFICATION_OK") || !strings.Contains(string(data), "OLLAMA_INFERENCE_OK") || !strings.Contains(string(data), "LANGGRAPH_OLLAMA_INFERENCE_OK") {
		t.Fatalf("real native Ollama qualification failed: %v\n%s", err, data)
	}
	// Keep the actual generated-token result, not thousands of cached build lines.
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "OLLAMA_INFERENCE_OK") || strings.Contains(line, "OLLAMA_QUALIFICATION_OK") {
			t.Log(line)
		}
	}
}
