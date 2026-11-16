import hashlib
import os
from pathlib import Path
import tempfile
import unittest
import install


class InstallerSecurityTests(unittest.TestCase):
    def assets(self, binary=b"synthetic checked executable", checksum=None):
        digest = checksum or hashlib.sha256(binary).hexdigest()
        def fetch(url, limit):
            self.assertTrue(url.startswith("https://github.com/rappidAI-Research/rappid-ghost/releases/download/v0.6.0/"))
            if url.endswith("SHA256SUMS"):
                return (digest + "  ghost_0.6.0_linux_amd64\n" + "f" * 64 + "  ../../foreign\n").encode()
            return binary
        return fetch

    def test_verified_atomic_install_preserves_project_and_external_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "ghost.yaml").write_text("trusted policy")
            install.install("v0.6.0", root, fetch=self.assets())
            target = root / "bin/ghost"
            self.assertEqual(target.read_bytes(), b"synthetic checked executable")
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)
            external = root / "external"
            os.link(target, external)
            install.install("v0.6.0", root, fetch=self.assets(b"replacement"))
            self.assertEqual(external.read_bytes(), b"synthetic checked executable")
            self.assertEqual((root / "ghost.yaml").read_text(), "trusted policy")
            self.assertFalse(any((root / "bin").glob(".ghost-install-*")))

    def test_bad_checksum_and_target_symlink_preserve_existing_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            external = root / "external"
            external.write_text("must remain")
            (root / "bin/ghost").symlink_to(external)
            with self.assertRaises(ValueError):
                install.install("v0.6.0", root, fetch=self.assets())
            self.assertEqual(external.read_text(), "must remain")
            (root / "bin/ghost").unlink()
            (root / "bin/ghost").write_text("previous binary")
            with self.assertRaises(ValueError):
                install.install("v0.6.0", root, fetch=self.assets(checksum="0" * 64))
            self.assertEqual((root / "bin/ghost").read_text(), "previous binary")

    def test_symlink_prefix_and_parent_traversal_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "external").mkdir()
            (root / "prefix").symlink_to(root / "external", target_is_directory=True)
            with self.assertRaises(OSError):
                install.install("v0.6.0", root / "prefix", fetch=self.assets())
            self.assertFalse((root / "external/bin").exists())
            with self.assertRaises(ValueError):
                install.open_install_directory(root / ".." / "outside")

    def test_release_identity_manifest_and_redirect_validation(self):
        for version in ("latest", "v0.06.0", "v0.6.0-dev", "v0.6.0/other", "$(id)", "v1.2.3\n"):
            with self.assertRaises(ValueError):
                install.release_version(version)
        for url in ("http://github.com/a", "https://github.com.evil/a", "https://localhost/a", "https://user:pass@github.com/a", "https://github.com:444/a"):
            with self.assertRaises(ValueError):
                install.check_download_url(url)
        for manifest in (b"", b"0  ghost_0.6.0_linux_amd64", (("f" * 64 + "  ghost_0.6.0_linux_amd64\n") * 2).encode(), ("f" * 64 + "  ghost_0.5.0_linux_amd64\n").encode()):
            with self.assertRaises(ValueError):
                install.expected_checksum(manifest, "ghost_0.6.0_linux_amd64")


if __name__ == "__main__":
    unittest.main()
