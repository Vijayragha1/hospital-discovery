from types import SimpleNamespace

import pytest

from app.provenance import processing_runtime_identity, provenance_is_known


def distribution(name, version):
    return SimpleNamespace(metadata={"Name": name}, version=version)


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    monkeypatch.delenv("DISCOVERY_RUNTIME_ID", raising=False)
    monkeypatch.delenv("TIKA_URL", raising=False)
    monkeypatch.delenv("PAGE_OCR_URL", raising=False)
    monkeypatch.setattr("app.provenance.importlib.metadata.distributions",
                        lambda: [distribution("Example", "1.0"), distribution("Other", "2.0")])


def test_bundled_runtime_is_used_with_external_parser(monkeypatch):
    monkeypatch.setenv("DISCOVERY_RUNTIME_ID", "a" * 64)
    monkeypatch.setenv("TIKA_URL", "http://parser.private:9998")
    marker = processing_runtime_identity()
    assert marker == "runtime-bundle-" + "a" * 64
    assert provenance_is_known("detector/" + marker)
    assert "parser.private" not in marker


@pytest.mark.parametrize("value", ["not-a-digest", "a" * 63, "a" * 65, "A" * 64])
def test_invalid_packaged_identity_cannot_fall_back_to_local(monkeypatch, value):
    monkeypatch.setenv("DISCOVERY_RUNTIME_ID", value)
    assert processing_runtime_identity() == "runtime-unverified"


@pytest.mark.parametrize("endpoint", ["TIKA_URL", "PAGE_OCR_URL"])
def test_remote_parser_without_recorded_identity_is_not_comparable(monkeypatch, endpoint):
    monkeypatch.setenv(endpoint, "http://parser.private:9998")
    marker = processing_runtime_identity()
    assert marker == "runtime-unverified"
    assert not provenance_is_known("detector/" + marker)
    assert not provenance_is_known("hospital-rules/1.0+sha256-" + "b" * 64)


def test_native_runtime_version_is_stable_but_dependency_changes_are_not(monkeypatch):
    baseline = processing_runtime_identity()
    monkeypatch.setattr("app.provenance.importlib.metadata.distributions",
                        lambda: [distribution("Other", "2.0"), distribution("example", "1.0")])
    assert processing_runtime_identity() == baseline
    monkeypatch.setattr("app.provenance.importlib.metadata.distributions",
                        lambda: [distribution("Other", "2.1"), distribution("example", "1.0")])
    assert processing_runtime_identity() != baseline
    assert provenance_is_known("detector/" + baseline)


def test_failed_local_inventory_is_not_comparable(monkeypatch):
    def unavailable():
        raise RuntimeError("synthetic dependency metadata failure")
    monkeypatch.setattr("app.provenance.importlib.metadata.distributions", unavailable)
    assert processing_runtime_identity() == "runtime-unverified"


def test_detector_records_runtime_for_rules_and_flags_unknown_parser(monkeypatch):
    from app.detection import Detector
    local = Detector(mode="rules")
    assert local.capabilities["processing_runtime_recorded"]
    assert provenance_is_known(local.version)
    monkeypatch.setenv("TIKA_URL", "http://parser.private:9998")
    unknown = Detector(mode="rules")
    assert not unknown.capabilities["processing_runtime_recorded"]
    assert "processing_runtime_identity_unverified" in unknown.capabilities["limitations"]
