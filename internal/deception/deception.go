// Package deception owns Ghost-controlled synthetic resources. It never reads
// the corresponding host resources; all decoy material is generated from fresh
// cryptographic randomness.
package deception

import "time"

const GuestHome = "/home/ghost"

type Type string

const (
	AWSCredentials Type = "aws_credentials"
	SSHPrivateKey  Type = "ssh_private_key"
	EnvFile        Type = "env_file"
)

type Resource struct {
	Type      Type
	GuestPath string
	Enabled   bool
}

func KnownResources() []Resource {
	return []Resource{
		{Type: AWSCredentials, GuestPath: GuestHome + "/.aws/credentials"},
		{Type: SSHPrivateKey, GuestPath: GuestHome + "/.ssh/id_rsa"},
		{Type: EnvFile, GuestPath: GuestHome + "/.env"},
	}
}

type Decoy struct {
	ID          string     `json:"id"`
	SessionID   string     `json:"session_id"`
	Type        Type       `json:"type"`
	GuestPath   string     `json:"guest_path"`
	CreatedAt   time.Time  `json:"created_at"`
	Marker      string     `json:"marker"`
	Triggered   bool       `json:"triggered"`
	TriggeredAt *time.Time `json:"triggered_at,omitempty"`
}

type Manifest struct {
	SessionID     string
	SessionDir    string
	SyntheticHome string
	GuestHome     string
	Decoys        []Decoy
}

func (t Type) DisplayName() string {
	switch t {
	case AWSCredentials:
		return "AWS credentials"
	case SSHPrivateKey:
		return "SSH private key"
	case EnvFile:
		return "Environment file"
	default:
		return string(t)
	}
}
