// Command images prepares the final source-reviewed images for release scanning.
package main

import (
	"context"
	"fmt"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

func main() {
	images, err := ghruntime.PreparedCatalogImages(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, image := range images {
		fmt.Println(image)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 13*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "sh", "scripts/build-ollama-service.sh")
	command.Stderr = os.Stderr
	output, err := command.Output()
	image := strings.TrimSpace(string(output))
	if err != nil || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(image) {
		fmt.Fprintln(os.Stderr, "prepare patched Ollama CPU service failed", err)
		os.Exit(1)
	}
	fmt.Println(image)
}
