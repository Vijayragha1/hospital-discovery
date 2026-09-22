"""Original-byte PDF fixtures for the isolated Java feature inspector.

Run with PDF_FEATURES_COMMAND='["java","-Xmx128m","-cp","/jar:/classes","PdfFeatures"]'.
Alternatively PDF_FEATURES_IMAGE names a built parser image; each fixture runs in
an isolated Docker invocation. No third-party PDF generation library is needed.
Without a supplied runtime these integration tests explicitly skip.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import zlib

import pytest


SENSITIVE = b"PATIENT_SECRET_SHOULD_NEVER_LEAK"


def pdf(objects, trailer=b""):
    """A complete, valid xref PDF, with optional deliberately unsupported objects."""
    data = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(data))
        data.extend(str(number).encode() + b" 0 obj\n" + obj + b"\nendobj\n")
    start = len(data)
    data.extend(b"xref\n0 " + str(len(objects) + 1).encode() + b"\n0000000000 65535 f \n")
    for offset in offsets[1:]:
        data.extend(f"{offset:010d} 00000 n \n".encode())
    data.extend(b"trailer\n<< /Size " + str(len(objects) + 1).encode() + b" /Root 1 0 R " + trailer
                + b" >>\nstartxref\n" + str(start).encode() + b"\n%%EOF\n")
    return bytes(data)


def stream(content, attrs=b""):
    return b"<< /Length " + str(len(content)).encode() + b" " + attrs + b" >>\nstream\n" + content + b"\nendstream"


def basic(*, catalog=b"", page=b"", content=b"", extras=(), trailer=b"", resources=b"", count=1):
    return pdf([
        b"<< /Type /Catalog /Pages 2 0 R " + catalog + b" >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count " + str(count).encode() + b" >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << " + resources
        + b" >> /Contents 4 0 R " + page + b" >>",
        stream(content), *extras,
    ], trailer)


def image_pdf(*, content=b"q 100 0 0 100 0 0 cm /Im1 Do Q", unused=False, attrs=b"", page=b""):
    return basic(content=content, resources=b"/XObject << /Im1 5 0 R >>", page=page,
                 extras=[stream(b"\x00\x00\x00", b"/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceRGB /BitsPerComponent 8 " + attrs)]
                 + ([stream(b"\xff\xff\xff", b"/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceRGB /BitsPerComponent 8")] if unused else []))


def rc4(key, data):
    state, j = list(range(256)), 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) % 256
        state[i], state[j] = state[j], state[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        out.append(byte ^ state[(state[i] + state[j]) % 256])
    return bytes(out)


def encrypted_pdf():
    # Standard Security Handler revision 2 fixture, intentionally inaccessible
    # without its user password. This is only test-data generation, never crypto
    # for app credentials/evidence.
    padding = bytes.fromhex("28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a")
    user = (b"synthetic-user-password" + padding)[:32]
    owner = (b"synthetic-owner-password" + padding)[:32]
    identifier = b"fixture-pdf-id-01"
    owner_value = rc4(hashlib.md5(owner).digest()[:5], user)
    key = hashlib.md5(user + owner_value + struct.pack("<i", -4) + identifier).digest()[:5]
    user_value = rc4(key, padding)
    dictionary = (b"<< /Filter /Standard /V 1 /R 2 /Length 40 /P -4 /O <" + owner_value.hex().encode()
                  + b"> /U <" + user_value.hex().encode() + b"> >>")
    return basic(extras=[dictionary], trailer=b"/Encrypt 5 0 R /ID [<" + identifier.hex().encode()
                 + b"><" + identifier.hex().encode() + b">]")


@pytest.fixture(scope="session")
def invoke():
    supplied = os.environ.get("PDF_FEATURES_COMMAND")
    image = os.environ.get("PDF_FEATURES_IMAGE")
    if not supplied and not image:
        pytest.skip("Set PDF_FEATURES_COMMAND or PDF_FEATURES_IMAGE to run the real PDFBox integration")
    command = json.loads(supplied) if supplied else None
    if command is not None:
        assert isinstance(command, list) and command and all(isinstance(part, str) for part in command)

    def run(path):
        if command:
            argv = [*command, str(path)]
        else:
            argv = ["docker", "run", "--rm", "--platform", os.environ.get("PDF_FEATURES_PLATFORM", "linux/amd64"),
                    "--network", "none", "--read-only", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges:true", "--memory", "256m", "--pids-limit", "32",
                    "--mount", f"type=bind,source={path.parent},target=/fixture,readonly", "--entrypoint", "env", image,
                    "-u", "JAVA_TOOL_OPTIONS", "-u", "JDK_JAVA_OPTIONS", "-u", "_JAVA_OPTIONS", "java",
                    "-Xmx128m", "-Xss256k", "-XX:+UseSerialGC", "-XX:ReservedCodeCacheSize=32m", "-XX:-UseCompressedClassPointers",
                    "-cp", "/opt/tika/server.jar:/opt/parser", "PdfFeatures", "/fixture/" + path.name]
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=True)
        assert result.stderr == b"", result.stderr.decode(errors="replace")
        assert SENSITIVE not in result.stdout
        assert str(path).encode() not in result.stdout
        data = json.loads(result.stdout)
        assert data["protocol"] == "pdf-features/v1"
        assert len(result.stdout) < 4096
        assert all(isinstance(value, int) and 0 <= value <= 200000 for value in data["feature_counts"].values())
        return data

    return run


def inspect(invoke, tmp_path, data):
    # The parser image deliberately runs as unprivileged UID 10001.
    tmp_path.chmod(0o755)
    source = tmp_path / "PATIENT_SECRET_SHOULD_NEVER_LEAK.pdf"
    source.write_bytes(data)
    source.chmod(0o444)
    return invoke(source)


@pytest.mark.parametrize("data", [basic(), basic(content=b"BT /F1 12 Tf 10 10 Td (ordinary) Tj ET",
    resources=b"/Font << /F1 5 0 R >>", extras=[b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]), image_pdf()],
    ids=["blank-page", "native-text", "visible-scan"])
def test_simple_blank_text_and_visible_scan_can_be_eligible(invoke, tmp_path, data):
    result = inspect(invoke, tmp_path, data)
    assert result["status"] == "completed"
    assert result["inventory_complete"] and result["original_page_count"] == 1
    assert result["encrypted"] is False and result["can_extract"]
    assert result["ancillary_absent"], result
    assert result["reason_codes"] == []
    assert result["feature_counts"]["native_text_operations"] == (1 if b"(ordinary) Tj" in data else 0)


@pytest.mark.parametrize("operation", [
    b"(ordinary) Tj", b"[(ordinary)] TJ", b"(ordinary) '", b'0 0 (ordinary) "',
    b"() Tj", b"[] TJ", b"() '", b'0 0 () "',
])
def test_native_text_show_operations_are_counted_even_if_empty(invoke, tmp_path, operation):
    result = inspect(invoke, tmp_path, basic(content=b"BT /F1 12 Tf 10 10 Td " + operation + b" ET",
        resources=b"/Font << /F1 5 0 R >>", extras=[b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]))
    assert result["status"] == "completed"
    assert result["feature_counts"]["native_text_operations"] == 1
    assert result["ancillary_absent"], "Native operation count is informational, not ancillary content"


def test_native_text_operation_count_preserves_repeated_draws(invoke, tmp_path):
    content = b"BT /F1 12 Tf 10 10 Td (ordinary) Tj ET\n" * 3
    result = inspect(invoke, tmp_path, basic(content=content, resources=b"/Font << /F1 5 0 R >>",
        extras=[b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]))
    assert result["status"] == "completed"
    assert result["feature_counts"]["native_text_operations"] == 3


def test_operator_names_in_comments_or_strings_do_not_count_as_native_operations(invoke, tmp_path):
    content = b'% Tj TJ apostrophe double-quote\nBT /F1 12 Tf 10 10 Td (Tj TJ) Tj ET'
    result = inspect(invoke, tmp_path, basic(content=content, resources=b"/Font << /F1 5 0 R >>",
        extras=[b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]))
    assert result["status"] == "completed"
    assert result["feature_counts"]["native_text_operations"] == 1


@pytest.mark.parametrize("filters", [b"/DCTDecode", b"/JPXDecode", b"/JBIG2Decode", b"[/ASCII85Decode /DCTDecode]",
                                     b"/Unknown", b"[]", b"[null]", b"123"])
def test_encoded_image_metadata_or_unknown_filters_prevent_full_eligibility(invoke, tmp_path, filters):
    # The feature inventory does not decode these payloads. It must flag the
    # codec itself until its nonvisual content is independently inspected.
    result = inspect(invoke, tmp_path, image_pdf(attrs=b"/Filter " + filters))
    assert result["status"] == "completed"
    assert result["feature_counts"]["unverified_image_uses"] >= 1
    assert not result["ancillary_absent"]


def test_lossless_raw_pixel_image_can_remain_eligible(invoke, tmp_path):
    data = basic(content=b"q 100 0 0 100 0 0 cm /Im1 Do Q", resources=b"/XObject << /Im1 5 0 R >>",
        extras=[stream(zlib.compress(b"\xff\xff\xff"), b"/Type /XObject /Subtype /Image /Width 1 /Height 1 "
                       b"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode")])
    result = inspect(invoke, tmp_path, data)
    assert result["status"] == "completed"
    assert result["feature_counts"]["native_text_operations"] == 0
    assert result["ancillary_absent"]


@pytest.mark.parametrize("declaration", [b"1", b"1.0"])
def test_explicit_default_user_unit_remains_eligible(invoke, tmp_path, declaration):
    result = inspect(invoke, tmp_path, basic(page=b"/UserUnit " + declaration))
    assert result["status"] == "completed"
    assert result["feature_counts"]["nondefault_user_units"] == 0
    assert result["ancillary_absent"]


@pytest.mark.parametrize("declaration", [b"2", b"0.5", b"0", b"-1", b"null", b"/Invalid", b"[1]", b"(1)"])
def test_nondefault_or_malformed_user_unit_is_not_eligible(invoke, tmp_path, declaration):
    result = inspect(invoke, tmp_path, basic(page=b"/UserUnit " + declaration))
    assert result["status"] == "completed"
    assert result["feature_counts"]["nondefault_user_units"] == 1
    assert not result["ancillary_absent"]


@pytest.mark.parametrize("declaration", [b"1", b"2", b"null"])
def test_misplaced_parent_user_unit_cannot_silently_supply_page_geometry(invoke, tmp_path, declaration):
    data = pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 /UserUnit " + declaration + b" >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> /Contents 4 0 R >>",
        stream(b""),
    ])
    result = inspect(invoke, tmp_path, data)
    assert result["status"] == "completed"
    assert result["feature_counts"]["nondefault_user_units"] == 1
    assert not result["ancillary_absent"]


@pytest.mark.parametrize("data,field", [
    (basic(page=b"/Annots [5 0 R]", extras=[b"<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents ("+SENSITIVE+b") >>"]), "annotations"),
    (basic(page=b"/Annots [null 27]"), "unknown_annotations"),
    (basic(catalog=b"/AcroForm << /Fields [] /XFA ("+SENSITIVE+b") >>"), "forms"),
    (basic(catalog=b"/AcroForm << /Fields [] /XFA ("+SENSITIVE+b") >>"), "xfa"),
    (basic(catalog=b"/OCProperties << /OCGs [] >>"), "layers"),
    (basic(catalog=b"/Names << /EmbeddedFiles << /Kids [5 0 R] >> >>", extras=[b"<< /Names [(private.txt) 6 0 R] >>",
        b"<< /Type /Filespec /F (private.txt) /EF << /F 7 0 R >> >>", stream(SENSITIVE,b"/Type /EmbeddedFile")]), "embedded_name_trees"),
    (basic(catalog=b"/AF [5 0 R]", extras=[b"<< /Type /Filespec /F (private.txt) /EF << /F 6 0 R >> >>", stream(SENSITIVE,b"/Type /EmbeddedFile")]), "associated_files"),
    (basic(page=b"/Annots [5 0 R]", extras=[b"<< /Type /Annot /Subtype /FileAttachment /FS 6 0 R /Rect [0 0 10 10] >>",
        b"<< /Type /Filespec /EF << /F 7 0 R >> >>", stream(SENSITIVE,b"/Type /EmbeddedFile")]), "file_specifications"),
    (basic(catalog=b"/OpenAction << /S /JavaScript /JS ("+SENSITIVE+b") >>"), "actions"),
    (basic(catalog=b"/Metadata 5 0 R", extras=[stream(SENSITIVE,b"/Type /Metadata /Subtype /XML")]), "metadata"),
    (basic(extras=[b"<< /Author ("+SENSITIVE+b") >>"],trailer=b"/Info 5 0 R"), "other_text"),
    (basic(extras=[stream(SENSITIVE)]), "unknown_streams"),
    (basic(catalog=b"/Collection << >>"), "interactive_features"),
    (image_pdf(unused=True), "unused_images"),
    (image_pdf(content=b"q 100 0 0 100 20 0 cm /Im1 Do Q"), "unverified_image_uses"),
    (image_pdf(page=b"/CropBox [0 0 50 50]"), "unverified_image_uses"),
    (image_pdf(content=b"0 0 10 10 re W n q 100 0 0 100 0 0 cm /Im1 Do Q"), "unverified_image_uses"),
    (image_pdf(content=b"q 100 0 0 100 0 0 cm /Im1 Do Q 0 0 100 100 re f"), "unverified_image_uses"),
    (image_pdf(attrs=b"/SMask 5 0 R"), "unverified_image_uses"),
    (basic(content=b"BX UNKNOWN_OPERATOR EX"), "unsupported_operators"),
], ids=["annotation", "invalid-annotations", "form", "xfa", "layers", "nested-attachment-tree",
        "associated-file", "attachment-annotation", "javascript", "xmp", "document-info", "unused-stream",
        "portfolio", "unused-image", "off-page-image", "cropped-image", "clipped-image", "covered-image",
        "image-soft-mask", "unknown-operator"])
def test_ancillary_or_unaccounted_content_is_never_eligible(invoke, tmp_path, data, field):
    result = inspect(invoke, tmp_path, data)
    assert not result["ancillary_absent"]
    assert result["feature_counts"][field] > 0, result
    assert "pdf_ancillary_content_unverified" in result["reason_codes"]


def test_encrypted_input_is_not_eligible_and_no_password_is_attempted(invoke, tmp_path):
    result = inspect(invoke, tmp_path, encrypted_pdf())
    assert result["encrypted"] is True
    assert not result["ancillary_absent"] and not result["inventory_complete"]
    assert result["reason_codes"] == ["encrypted_pdf"]


def test_unknown_annotation_subtype_is_counted_without_echoing_it(invoke, tmp_path):
    result = inspect(invoke, tmp_path, basic(page=b"/Annots [5 0 R]", extras=[
        b"<< /Type /Annot /Subtype /" + SENSITIVE + b" /Rect [0 0 10 10] >>"]))
    assert result["feature_counts"]["annotations"] == 1
    assert result["feature_counts"]["unknown_annotations"] == 1
    assert not result["ancillary_absent"]


@pytest.mark.parametrize("data", [b"not a PDF "+SENSITIVE, basic()[:-60], basic(content=b"Q")],
                         ids=["not-pdf", "truncated-xref", "unbalanced-state"])
def test_malformed_input_is_not_eligible(invoke, tmp_path, data):
    result = inspect(invoke, tmp_path, data)
    assert not result["ancillary_absent"]
    assert result["reason_codes"]


def test_structural_depth_limit_is_reported(invoke, tmp_path):
    deep = b"[" * 70 + b"0" + b"]" * 70
    result = inspect(invoke, tmp_path, basic(catalog=b"/Unsupported " + deep))
    assert not result["ancillary_absent"] and not result["inventory_complete"]
    assert result["status"] in {"limited", "failed"}


def test_original_two_page_inventory_is_independent_of_text(invoke, tmp_path):
    data = pdf([b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> >>",
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> >>"])
    result = inspect(invoke, tmp_path, data)
    assert result["original_page_count"] == 2 and result["inventory_complete"]
    assert result["ancillary_absent"]


def test_page_limit_does_not_certify_the_first_hundred_pages(invoke, tmp_path):
    kids = b" ".join(f"{index} 0 R".encode() for index in range(3, 104))
    data = pdf([b"<< /Type /Catalog /Pages 2 0 R >>",
                b"<< /Type /Pages /Kids [" + kids + b"] /Count 101 >>",
                *[b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>"] * 101])
    result = inspect(invoke, tmp_path, data)
    assert result["status"] == "limited" and not result["inventory_complete"]
    assert not result["ancillary_absent"]
    assert result["reason_codes"] == ["pdf_feature_limit"]


def test_decoded_content_budget_is_enforced(invoke, tmp_path):
    result = inspect(invoke, tmp_path, basic(content=b" " * (4 * 1024 * 1024 + 1)))
    assert result["status"] == "limited" and not result["inventory_complete"]
    assert not result["ancillary_absent"]
    assert result["reason_codes"] == ["pdf_feature_limit"]


def test_stream_parser_warning_is_not_silently_treated_as_eof(invoke, tmp_path):
    # PDFBox can warn and return EOF for malformed array operands instead of throwing.
    result = inspect(invoke, tmp_path, basic(content=b"BT [ (" + SENSITIVE + b")"))
    assert not result["ancillary_absent"]
    assert result["reason_codes"]
