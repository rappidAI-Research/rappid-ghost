package compat

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

const LangGraphVersion = "1.2.22"

//go:embed bundles/langgraph.lock.json
var langGraphLock []byte

type bundleWheel struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Filename string   `json:"filename"`
	SHA256   string   `json:"sha256"`
	URL      string   `json:"url"`
	Requires []string `json:"requires"`
	License  string   `json:"license"`
}
type bundleManifest struct {
	SchemaVersion int           `json:"schema_version"`
	Python        string        `json:"python"`
	Platform      string        `json:"platform"`
	Root          string        `json:"root"`
	Wheels        []bundleWheel `json:"wheels"`
}

// This manifest is embedded reviewed source, never project-supplied lock data.
// Each ADD authenticates fixed bytes. Offline pip only unpacks binary wheels;
// no index resolution, sdist build, project setup hook or RUN network exists.
func langGraphRecipe(data []byte) (string, error) {
	var bundle bundleManifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&bundle) != nil || bundle.SchemaVersion != 1 || bundle.Python != "3.13" || bundle.Platform != "linux_amd64_musl" || bundle.Root != "langgraph=="+LangGraphVersion || len(bundle.Wheels) == 0 || len(bundle.Wheels) > 64 {
		return "", errors.New("invalid source-reviewed LangGraph bundle")
	}
	namePattern := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	versionPattern := regexp.MustCompile(`^[0-9][A-Za-z0-9.+_-]{0,63}$`)
	filePattern := regexp.MustCompile(`^[A-Za-z0-9_.+-]+\.whl$`)
	digestPattern := regexp.MustCompile(`^[a-f0-9]{64}$`)
	var recipe strings.Builder
	fmt.Fprintf(&recipe, "FROM %s\nARG SOURCE_DATE_EPOCH=0\n", PythonImage)
	requirements := []string{}
	seen := map[string]bool{}
	for _, wheel := range bundle.Wheels {
		normal := strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(wheel.Name))
		u, err := url.Parse(wheel.URL)
		if !namePattern.MatchString(wheel.Name) || !versionPattern.MatchString(wheel.Version) || !filePattern.MatchString(wheel.Filename) || !digestPattern.MatchString(wheel.SHA256) || err != nil || u.Scheme != "https" || u.Host != "files.pythonhosted.org" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/packages/") || path.Base(u.Path) != wheel.Filename || seen[normal] {
			return "", errors.New("invalid wheel identity in reviewed LangGraph bundle")
		}
		seen[normal] = true
		fmt.Fprintf(&recipe, "ADD --checksum=sha256:%s %s /tmp/ghost-wheels/%s\n", wheel.SHA256, wheel.URL, wheel.Filename)
		requirements = append(requirements, "'"+wheel.Name+"=="+wheel.Version+" --hash=sha256:"+wheel.SHA256+"'")
	}
	if !seen["langgraph"] {
		return "", errors.New("LangGraph root wheel missing")
	}
	fmt.Fprintf(&recipe, "RUN printf '%%s\\n' %s > /tmp/ghost-wheels/requirements.txt && python3 -m pip install --no-index --no-deps --require-hashes --find-links /tmp/ghost-wheels -r /tmp/ghost-wheels/requirements.txt && python3 -m pip check && rm -rf /tmp/ghost-wheels /usr/local/lib/python3.13/site-packages/pip* /usr/local/lib/python3.13/ensurepip /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13\nENV LANGSMITH_TRACING=false\n", strings.Join(requirements, " "))
	return recipe.String(), nil
}
