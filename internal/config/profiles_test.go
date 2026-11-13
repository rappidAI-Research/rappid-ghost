package config

import (
	"reflect"
	"testing"
)

func TestProfilesConstrainWithoutMutatingPermissions(t *testing.T) {
	c := Default()
	c.Profile = "document-processing"
	before := c
	if c.Validate() == nil {
		t.Fatal("document profile accepted writable workspace and shadow home")
	}
	if !reflect.DeepEqual(before, c) {
		t.Fatal("profile rewrote security policy")
	}
	c.Workspace.Mode = "read-only"
	c.Policy.Home = "deny"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Profile = "restricted"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Runtime.Limits.MemoryMiB = 4096
	if c.Validate() == nil {
		t.Fatal("restricted profile accepted raised ceiling")
	}
	c = Default()
	c.Profile = "coding"
	c.OnDecoyAccess.Network = "unchanged"
	if c.Validate() == nil {
		t.Fatal("coding profile accepted missing decoy containment")
	}
	c.Profile = "automatic"
	if c.Validate() == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestRuntimeAndAdapterValidationCannotAuthorizeImages(t *testing.T) {
	c := Default()
	c.Agent.Adapter = "python"
	if c.Validate() == nil {
		t.Fatal("Python adapter accepted Alpine")
	}
	c.Runtime.Environment = "python"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Runtime.Environment = "ubuntu:latest"
	if c.Validate() == nil {
		t.Fatal("arbitrary image accepted")
	}
}
