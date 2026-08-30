package deception

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var safeSessionID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type Generator struct {
	now func() time.Time
}

func NewGenerator() *Generator {
	return &Generator{now: func() time.Time { return time.Now().UTC() }}
}

// Prepare creates a fresh, private synthetic home. resources contains only
// paths for which deterministic policy evaluation returned SHADOW.
func (g *Generator) Prepare(sessionID, sessionsRoot string, resources []Resource) (manifest Manifest, err error) {
	if !safeSessionID.MatchString(sessionID) {
		return Manifest{}, errors.New("invalid session ID for synthetic home")
	}
	rootInfo, err := os.Lstat(sessionsRoot)
	if err != nil {
		return Manifest{}, fmt.Errorf("inspect sessions directory: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return Manifest{}, errors.New("sessions path must be a real directory")
	}

	sessionDir := filepath.Join(sessionsRoot, sessionID)
	if err := os.Mkdir(sessionDir, 0o700); err != nil {
		return Manifest{}, fmt.Errorf("create session directory: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(sessionDir)
		}
	}()

	home := filepath.Join(sessionDir, "shadow-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		return Manifest{}, fmt.Errorf("create synthetic home: %w", err)
	}
	manifest = Manifest{
		SessionID:     sessionID,
		SessionDir:    sessionDir,
		SyntheticHome: home,
		GuestHome:     GuestHome,
	}

	for _, resource := range resources {
		if !resource.Enabled {
			continue
		}
		decoy, generateErr := g.generate(sessionID, resource)
		if generateErr != nil {
			return Manifest{}, generateErr
		}
		relative, pathErr := guestRelativePath(resource.GuestPath)
		if pathErr != nil {
			return Manifest{}, pathErr
		}
		hostPath := filepath.Join(home, relative)
		if err := os.MkdirAll(filepath.Dir(hostPath), 0o700); err != nil {
			return Manifest{}, fmt.Errorf("create decoy directory: %w", err)
		}
		content, contentErr := contentFor(decoy)
		if contentErr != nil {
			return Manifest{}, contentErr
		}
		file, openErr := os.OpenFile(hostPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if openErr != nil {
			return Manifest{}, fmt.Errorf("create decoy %s: %w", resource.Type, openErr)
		}
		if _, writeErr := file.WriteString(content); writeErr != nil {
			_ = file.Close()
			return Manifest{}, fmt.Errorf("write decoy %s: %w", resource.Type, writeErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return Manifest{}, fmt.Errorf("close decoy %s: %w", resource.Type, closeErr)
		}
		manifest.Decoys = append(manifest.Decoys, decoy)
	}
	return manifest, nil
}

func (g *Generator) generate(sessionID string, resource Resource) (Decoy, error) {
	idBytes, err := randomBytes(16)
	if err != nil {
		return Decoy{}, fmt.Errorf("generate decoy ID: %w", err)
	}
	markerBytes, err := randomBytes(24)
	if err != nil {
		return Decoy{}, fmt.Errorf("generate decoy marker: %w", err)
	}
	return Decoy{
		ID:        "dcy_" + hex.EncodeToString(idBytes),
		SessionID: sessionID,
		Type:      resource.Type,
		GuestPath: resource.GuestPath,
		CreatedAt: g.now(),
		Marker:    base64.RawURLEncoding.EncodeToString(markerBytes),
	}, nil
}

func randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	return value, nil
}

func guestRelativePath(guestPath string) (string, error) {
	relative, err := filepath.Rel(GuestHome, filepath.Clean(guestPath))
	if err != nil || relative == "." || relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("decoy path escapes synthetic home: %q", guestPath)
	}
	return relative, nil
}

func contentFor(decoy Decoy) (string, error) {
	switch decoy.Type {
	case AWSCredentials:
		return fmt.Sprintf("# Ghost synthetic credential; cannot authenticate to AWS.\n[default]\naws_access_key_id = GHOST_AWS_%s\naws_secret_access_key = GHOST_SECRET_%s\n", decoy.Marker, decoy.Marker), nil
	case SSHPrivateKey:
		payload := base64.StdEncoding.EncodeToString([]byte("GHOST SYNTHETIC NONFUNCTIONAL SSH KEY " + decoy.Marker))
		return fmt.Sprintf("-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n", payload), nil
	case EnvFile:
		return fmt.Sprintf("# Ghost synthetic values; no external service accepts them.\nDATABASE_URL=ghost://decoy/%s\nAPI_KEY=GHOST_API_%s\nINTERNAL_TOKEN=GHOST_TOKEN_%s\n", decoy.Marker, decoy.Marker, decoy.Marker), nil
	default:
		return "", fmt.Errorf("unsupported decoy type %q", decoy.Type)
	}
}
