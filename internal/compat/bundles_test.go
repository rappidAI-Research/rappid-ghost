package compat

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReviewedDependencyBundleCannotSelectAnIndexOrInstallAtRunTime(t *testing.T) {
	environment, err := ResolveEnvironment("python-langgraph")
	if err != nil {
		t.Fatal(err)
	}
	if environment.Architecture != "amd64" || environment.Image != PythonImage {
		t.Fatal("bundle changed platform/base identity")
	}
	if strings.Count(environment.BuildRecipe, "ADD --checksum=sha256:") != 38 || !strings.Contains(environment.BuildRecipe, "--no-index --no-deps --require-hashes") || !strings.Contains(environment.BuildRecipe, "python3 -m pip check") || strings.Contains(environment.BuildRecipe, "apt-get") || strings.Contains(environment.BuildRecipe, "setup.py") {
		t.Fatal("bundle is not a closed offline wheel installation")
	}
	argv, err := Prepare("python", "python-langgraph", []string{"agent.py", "argument"})
	if err != nil || strings.Join(argv, " ") != "/usr/local/bin/python3 -B /workspace/agent.py argument" {
		t.Fatal("bundle bypassed the existing source adapter")
	}
	if ValidateAdapter("langgraph", "python") == nil || ValidateAdapter("node", "python-langgraph") == nil {
		t.Fatal("bundle implicitly changed the selected adapter")
	}
}

func TestBundleManifestRejectsMutableOriginsAndRecipeInjection(t *testing.T) {
	var original bundleManifest
	if json.Unmarshal(langGraphLock, &original) != nil {
		t.Fatal("bad reviewed manifest")
	}
	for _, mutate := range []func(*bundleManifest){
		func(b *bundleManifest) { b.Wheels[0].URL = "https://unreviewed.invalid/packages/x.whl" },
		func(b *bundleManifest) { b.Wheels[0].SHA256 = "mutable" },
		func(b *bundleManifest) { b.Wheels[0].Name = "package'; curl bad" },
		func(b *bundleManifest) { b.Wheels[0].Filename = "../outside.whl" },
		func(b *bundleManifest) { b.Wheels[0].Version = "1\nRUN arbitrary" },
		func(b *bundleManifest) { b.Platform = "host" },
	} {
		var b bundleManifest
		_ = json.Unmarshal(langGraphLock, &b)
		mutate(&b)
		data, _ := json.Marshal(b)
		if _, err := langGraphRecipe(data); err == nil {
			t.Fatal("unsafe manifest created a recipe")
		}
	}
}
