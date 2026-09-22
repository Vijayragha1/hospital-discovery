import tempfile
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from bundle import (checksum_manifest, compose_image_overrides, inspect_image, registry_digest,
                    repository_name, runtime_identity, verify)


class BundleIntegrityTests(unittest.TestCase):
    def fixture(self, directory):
        for name in ("images.tar.gz", "images.lock.json", "release.json", "deploy/compose.yaml", "deploy/compose.images.yaml"):
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture artifact")
        checksum_manifest(directory)

    def test_tampered_archive_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            (root / "images.tar.gz").write_text("tampered")
            with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
                verify(root)

    def test_missing_required_artifact_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "SHA256SUMS").write_text("")
            with self.assertRaisesRegex(ValueError, "Missing required"):
                verify(root)

    def test_checksum_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "SHA256SUMS").write_text("a" * 64 + "  ../outside\n")
            with self.assertRaisesRegex(ValueError, "Unsafe path"):
                verify(root)

    def test_valid_artifacts_pass(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            verify(root)

    def test_digest_selection_ignores_local_retag_alias(self):
        values = ["hospital-discovery-postgres@sha256:local", "postgres@sha256:upstream"]
        self.assertEqual(registry_digest("postgres:17-alpine", values), values[1])

    def test_immutable_reference_is_preserved(self):
        supplied = "docker.io/library/postgres@sha256:original"
        self.assertEqual(registry_digest(supplied, ["hospital-discovery-postgres@sha256:local"]), supplied)

    def test_digest_requires_correct_registry_repository(self):
        with self.assertRaises(ValueError):
            registry_digest("postgres:17-alpine", ["hospital-discovery-postgres@sha256:local"])
        self.assertEqual(repository_name("registry.example:5000/team/app:1"), "registry.example:5000/team/app")
        self.assertEqual(repository_name("python:3.12-slim"), repository_name("docker.io/library/python@sha256:abc"))

    def test_inspection_requests_platform_configuration(self):
        payload = '[{"Id":"sha256:config", "Architecture":"amd64", "Os":"linux", "RepoDigests":[]}]'
        with patch("bundle.run", return_value=SimpleNamespace(stdout=payload)) as invoke:
            actual = inspect_image("fixture:1", "linux/amd64")
            invoke.assert_called_once_with("docker", "image", "inspect", "--platform", "linux/amd64", "fixture:1", capture=True)
        self.assertEqual(actual["id"], "sha256:config")
        self.assertEqual(actual["platform"], "linux/amd64")

    def test_oci_index_without_platform_metadata_rejected(self):
        with patch("bundle.run", return_value=SimpleNamespace(stdout='[{"Id":"sha256:index"}]')):
            with self.assertRaises(ValueError):
                inspect_image("fixture:1", "linux/amd64")


class ProcessingRuntimeIdentityTests(unittest.TestCase):
    def setUp(self):
        self.records = {name: {"name": f"hospital-discovery-{name}:fixture", "id": "sha256:" + digit * 64,
                               "platform": "linux/amd64", "os": "linux", "architecture": "amd64"}
                        for name, digit in zip(("api", "tika", "web", "postgres"), "abcd")}

    def test_api_and_parser_image_changes_change_identity(self):
        baseline = runtime_identity(self.records)
        self.assertRegex(baseline, r"^[0-9a-f]{64}$")
        for component in ("api", "tika"):
            with self.subTest(component=component):
                changed = copy.deepcopy(self.records)
                changed[component]["id"] = "sha256:" + "e" * 64
                self.assertNotEqual(runtime_identity(changed), baseline)

    def test_web_catalogue_tags_and_record_order_do_not_change_identity(self):
        baseline = runtime_identity(self.records)
        changed = copy.deepcopy(self.records)
        changed["web"]["id"] = "sha256:" + "e" * 64
        changed["postgres"]["id"] = "sha256:" + "f" * 64
        changed["api"]["name"] = "hospital-discovery-api:renamed-release"
        changed["tika"]["name"] = "hospital-discovery-tika:renamed-release"
        self.assertEqual(runtime_identity(changed), baseline)
        self.assertEqual(runtime_identity(dict(reversed(list(changed.items())))), baseline)

    def test_identity_rejects_missing_or_mutable_image_references(self):
        for component in ("api", "tika"):
            for invalid in (None, "latest", "sha256:short", "sha256:" + "A" * 64,
                            "sha256:" + "g" * 64, "sha256:" + "a" * 64 + "\n", 42):
                with self.subTest(component=component, invalid=invalid):
                    changed = copy.deepcopy(self.records)
                    changed[component]["id"] = invalid
                    with self.assertRaisesRegex(ValueError, "immutable API and Tika image IDs"):
                        runtime_identity(changed)
            changed = copy.deepcopy(self.records)
            del changed[component]
            with self.assertRaisesRegex(ValueError, "immutable API and Tika image IDs"):
                runtime_identity(changed)
        for invalid in (None, [], "not-records"):
            with self.assertRaisesRegex(ValueError, "immutable API and Tika image IDs"):
                runtime_identity(invalid)

    def test_compose_stamps_same_runtime_identity_on_api_and_worker_only(self):
        import yaml

        config = yaml.safe_load(compose_image_overrides(self.records))
        services = config["services"]
        self.assertEqual(set(services), {"postgres", "api", "worker", "tika", "ingress_guard", "web"})
        expected_identity = runtime_identity(self.records)
        for service in ("api", "worker"):
            self.assertEqual(services[service]["environment"], {"DISCOVERY_RUNTIME_ID": expected_identity})
            self.assertEqual(services[service]["image"], self.records["api"]["name"])
        for service in ("postgres", "tika", "ingress_guard", "web"):
            self.assertNotIn("environment", services[service])
            component = "web" if service == "ingress_guard" else service
            self.assertEqual(services[service]["image"], self.records[component]["name"])
        self.assertTrue(all(service["pull_policy"] == "never" for service in services.values()))
        self.assertTrue(all(service["platform"] == "linux/amd64" for service in services.values()))

    def test_compose_rejects_missing_unsafe_or_inconsistent_platforms(self):
        for component in ("api", "tika", "web", "postgres"):
            for invalid in (None, "", "${PLATFORM}", "linux/amd64\nmalformed: yaml", "linux amd64", 42):
                with self.subTest(component=component, invalid=invalid):
                    changed = copy.deepcopy(self.records)
                    changed[component]["platform"] = invalid
                    with self.assertRaisesRegex(ValueError, "fixed platform"):
                        compose_image_overrides(changed)
            changed = copy.deepcopy(self.records)
            del changed[component]["platform"]
            with self.assertRaisesRegex(ValueError, "fixed platform"):
                compose_image_overrides(changed)
            changed = copy.deepcopy(self.records)
            changed[component]["platform"] = "linux/arm64"
            with self.assertRaisesRegex(ValueError, "platforms must match"):
                compose_image_overrides(changed)

    def test_compose_rejects_interpolated_or_incomplete_image_names(self):
        for invalid in ("${UNPINNED_IMAGE}", "fixture\nmalformed: yaml", "", None):
            with self.subTest(invalid=invalid):
                changed = copy.deepcopy(self.records)
                changed["web"]["name"] = invalid
                with self.assertRaisesRegex(ValueError, "fixed image names"):
                    compose_image_overrides(changed)


if __name__ == "__main__":
    unittest.main()
