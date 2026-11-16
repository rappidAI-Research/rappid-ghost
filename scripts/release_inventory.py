#!/usr/bin/env python3
"""SPDX module inventories from actual Go binary build-info, not go.mod guesses."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.parse


def inventory(binary, version, commit, created):
    info = json.loads(subprocess.check_output(["go", "version", "-m", "-json", str(binary)]))
    if info["Path"] != "github.com/rappidAI-research/rappid-ghost/cmd/ghost":
        raise ValueError("unexpected binary module identity")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    packages = [{"SPDXID": "SPDXRef-Ghost", "name": "ghost", "versionInfo": version,
                 "downloadLocation": "https://github.com/rappidAI-Research/rappid-ghost/releases/download/v" + version + "/" + binary.name,
                 "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": "Apache-2.0",
                 "copyrightText": "NOASSERTION", "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                 "sourceInfo": "Source commit " + commit + "; compiled Go module inventory only. Runtime images have separate CycloneDX inventories."}]
    modules = [{"Path": "golang.org/toolchain", "Version": info["GoVersion"]}] + info.get("Deps", [])
    relations = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Ghost"}]
    for index, module in enumerate(modules):
        if module.get("Replace"):
            raise ValueError("unreviewed module replacement in release binary")
        identity = "SPDXRef-Module-" + str(index)
        packages.append({"SPDXID": identity, "name": module["Path"], "versionInfo": module["Version"],
                         "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                         "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
                         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                           "referenceLocator": "pkg:golang/" + urllib.parse.quote(module["Path"], safe="/") + "@" + urllib.parse.quote(module["Version"], safe="")} ]})
        relations.append({"spdxElementId": "SPDXRef-Ghost", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": identity})
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": binary.name + " compiled Go modules", "documentNamespace": "https://github.com/rappidAI-Research/rappid-ghost/spdx/" + commit + "/" + digest,
            "creationInfo": {"creators": ["Tool: Ghost release_inventory.py"], "created": created},
            "packages": packages, "relationships": relations}


def main():
    version = sys.argv[1]
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        raise ValueError("release inventory requires a stable version")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    epoch = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], text=True))
    created = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for architecture in ("amd64", "arm64"):
        binary = Path("dist") / ("ghost_" + version + "_linux_" + architecture)
        result = inventory(binary, version, commit, created)
        (Path(str(binary) + ".spdx.json")).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
