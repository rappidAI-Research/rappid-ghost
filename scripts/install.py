#!/usr/bin/env python3
"""Explicit official-release install/update; never changes project policy."""
import argparse
import hashlib
import hmac
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

REPOSITORY = "rappidAI-Research/rappid-ghost"
VERSION = "v0.6.0"
VERSION_PATTERN = r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
DOWNLOAD_HOSTS = {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}


def release_version(value):
    if len(value) > 45 or re.fullmatch(VERSION_PATTERN, value) is None:
        raise ValueError("version must be a fixed stable tag, for example v0.6.0")
    return value


def check_download_url(value):
    url = urllib.parse.urlsplit(value)
    if (url.scheme != "https" or url.hostname not in DOWNLOAD_HOSTS
            or url.port not in (None, 443) or url.username or url.password or url.fragment):
        raise ValueError("release download left the allowed GitHub HTTPS origins")


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        check_download_url(new_url)
        return super().redirect_request(request, file, code, message, headers, new_url)


def download(url, limit):
    check_download_url(url)
    # No host proxy credentials or environment proxy discovery.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                                        ReleaseRedirect())
    deadline = time.monotonic() + 120
    with opener.open(urllib.request.Request(url, headers={"User-Agent": "ghost-release-installer"}), timeout=20) as response:
        check_download_url(response.url)
        if int(response.headers.get("Content-Length", "0")) > limit:
            raise ValueError("release asset exceeds the download limit")
        data = bytearray()
        while True:
            block = response.read(min(65536, limit + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            if len(data) > limit or time.monotonic() > deadline:
                raise ValueError("release download exceeded its size/time budget")
    return bytes(data)


def expected_checksum(manifest, asset):
    matches = []
    for line in manifest.decode("ascii").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1] == asset:
            if re.fullmatch(r"[a-fA-F0-9]{64}", fields[0]) is None:
                raise ValueError("invalid asset checksum")
            matches.append(fields[0].lower())
    if len(matches) != 1:
        raise ValueError("checksum manifest must identify exactly the expected release asset")
    return matches[0]


def open_install_directory(prefix):
    """Pin each real path component; never traverse a destination symlink."""
    path = Path(prefix).expanduser().absolute() / "bin"
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            if component in (".", ".."):
                raise ValueError("installation prefix must not contain parent components")
            try:
                os.mkdir(component, 0o755, dir_fd=directory)
            except FileExistsError:
                pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        return path, directory
    except BaseException:
        os.close(directory)
        raise


def install(version, prefix, verify_attestation=False, fetch=download):
    release_version(version)
    asset = "ghost_" + version[1:] + "_linux_amd64"
    base = "https://github.com/" + REPOSITORY + "/releases/download/" + version + "/"
    manifest = fetch(base + "SHA256SUMS", 1024 * 1024)
    wanted = expected_checksum(manifest, asset)
    binary = fetch(base + asset, 64 * 1024 * 1024)
    if not hmac.compare_digest(hashlib.sha256(binary).hexdigest(), wanted):
        raise ValueError("release checksum mismatch; existing installation preserved")
    if verify_attestation:
        gh = shutil.which("gh")
        if gh is None:
            raise ValueError("--verify-attestation requires the official GitHub CLI (gh)")
        with tempfile.TemporaryDirectory(prefix="ghost-attestation-") as temporary:
            staged = Path(temporary) / asset
            staged.write_bytes(binary)
            subprocess.run([gh, "attestation", "verify", str(staged), "--repo", REPOSITORY,
                            "--signer-workflow", REPOSITORY + "/.github/workflows/release.yml",
                            "--deny-self-hosted-runners"], check=True, timeout=120,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    path, directory = open_install_directory(prefix)
    temporary = ".ghost-install-" + secrets.token_hex(16)
    try:
        try:
            target = os.stat("ghost", dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            target = None
        if target is not None and not stat.S_ISREG(target.st_mode):
            raise ValueError("refusing a symlink or non-regular ghost installation target")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(descriptor, "wb") as output:
            output.write(binary)
            output.flush()
            os.fchmod(output.fileno(), 0o755)
            os.fsync(output.fileno())
        # Atomic entry replacement does not follow a raced target symlink.
        os.replace(temporary, "ghost", src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)
    return path / "ghost"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=VERSION, help="fixed stable release tag")
    parser.add_argument("--prefix", default=str(Path.home() / ".local"))
    parser.add_argument("--verify-attestation", action="store_true", help="also require the release workflow's signed build provenance (gh required)")
    args = parser.parse_args()
    try:
        if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
            raise ValueError("installer qualifies native Linux amd64 only; other platforms need separate execution qualification")
        if os.geteuid() == 0:
            raise ValueError("install as your non-root Ghost operator account; do not use sudo")
        target = install(args.version, args.prefix, args.verify_attestation)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("Ghost installation stopped: " + str(error), file=sys.stderr)
        return 1
    print("Installed " + args.version + " at " + str(target))
    print("Add its bin directory to PATH, then run ghost version and ghost doctor in your project.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
