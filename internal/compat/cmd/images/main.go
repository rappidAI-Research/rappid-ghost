// Command images prepares the final source-reviewed images for release scanning.
package main

import (
	"context"
	"fmt"
	"github.com/rappidAI-research/rappid-ghost/internal/compat"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"os"
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
	fmt.Println(compat.OllamaImage)
}
