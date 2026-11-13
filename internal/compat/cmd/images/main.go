// Command images emits the source-reviewed image catalog for release tooling.
package main

import (
	"fmt"
	"github.com/rappidAI-research/rappid-ghost/internal/compat"
)

func main() {
	for _, name := range []string{"alpine", "python"} {
		environment, err := compat.ResolveEnvironment(name)
		if err != nil {
			panic(err)
		}
		fmt.Println(environment.Image)
	}
}
