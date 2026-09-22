"""Synthetic bounded-worker checks; real Tesseract/Pillow cases run when installed."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import time
from types import SimpleNamespace
from xml.sax.saxutils import escape

import pytest

DIRECTORY = Path(__file__).resolve().parents[1] / "deploy" / "parser"
sys.path.insert(0, str(DIRECTORY))


def module(name):
    spec = importlib.util.spec_from_file_location(name, DIRECTORY / (name + ".py"))
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[name] = loaded
    spec.loader.exec_module(loaded)
    return loaded


worker = module("page_ocr")
images = module("image_units")
sandbox = module("sandbox_exec")


def test_only_java_receives_additional_virtual_address_reservation():
    assert sandbox.address_space_limit("/usr/bin/java") == 2 * 1024 ** 3
    for binary in ("/usr/bin/python3", "/usr/bin/tesseract", "/usr/bin/pdftoppm", "/usr/bin/pdfinfo", "/tmp/java-wrapper"):
        assert sandbox.address_space_limit(binary) == 1024 ** 3


def pdf_bytes(page_count=1, texts=None):
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b""]
    kids = []
    for index in range(page_count):
        page, contents = len(objects) + 1, len(objects) + 2
        kids.append(f"{page} 0 R")
        content = b"0 0 20 20 re f\n"
        if texts and texts[index]:
            content = f"BT /F1 7 Tf 1 50 Td ({texts[index]}) Tj ET\n".encode()
        resources = "/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >>"
        objects += [f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] {resources} /Contents {contents} 0 R >>".encode(),
                    f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"endstream"]
    objects[1] = f"<< /Type /Pages /Count {page_count} /Kids [{' '.join(kids)}] >>".encode()
    output, offsets = bytearray(b"%PDF-1.4\n"), []
    for index, body in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode() + body + b"\nendobj\n")
    start = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n".encode())
    return bytes(output)


def bbox_bytes(text):
    words = "".join(f'<word xMin="{1 + index * 12}" yMin="1" xMax="{11 + index * 12}" yMax="11">{escape(word)}</word>'
                    for index, word in enumerate(text.split()))
    return f'<html><body><doc><page width="72" height="72"><flow><block><line>{words}</line></block></flow></page></doc></body></html>'.encode()


def tsv_bytes(text):
    result = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n"
    result += "1\t1\t0\t0\t0\t0\t0\t0\t200\t200\t-1\t\n"
    for index, word in enumerate(text.split()):
        result += f"5\t1\t1\t1\t1\t{index + 1}\t{1 + index * 30}\t1\t25\t25\t90\t{word}\n"
    return result.encode()


class FakeRunner:
    count = 2
    ocr = b"synthetic printed text"
    native = b"synthetic native text"
    failing = None
    image_metadata = False

    def __init__(self, directory, deadline):
        self.directory, self.deadline = Path(directory), deadline
        self.commands = []

    def close(self):
        pass

    def run(self, command, **kwargs):
        self.commands.append(command)
        command = [str(item) for item in command]
        name = Path(command[0]).name
        if name == self.failing:
            return worker.Outcome("process_failed", b"private filename and raw diagnostic must not escape")
        if name == "pdfinfo":
            if "-box" in command:
                page = int(command[command.index("-f") + 1])
                return worker.Outcome("completed", f"Page {page} MediaBox: 0 0 72 72\nPage {page} CropBox: 0 0 72 72\nPage {page} rot: 0\n".encode())
            return worker.Outcome("completed", f"Pages: {self.count}\nEncrypted: no\nTitle: private metadata not returned\n".encode())
        if name == "pdftoppm":
            (self.directory / "unit.png").write_bytes(b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", 200, 200))
            return worker.Outcome("completed")
        if name == "tesseract":
            if command[2] != "stdout":
                (self.directory / "ocr.txt").write_bytes(self.ocr)
                (self.directory / "ocr.tsv").write_bytes(tsv_bytes(self.ocr.decode("utf-8", errors="replace")))
                return worker.Outcome("completed")
            return worker.Outcome("completed", self.ocr)
        if name == "pdftotext":
            first, last = command[command.index("-f") + 1], command[command.index("-l") + 1]
            assert first == last
            value = self.native if isinstance(self.native, bytes) else self.native[int(first) - 1]
            if "-bbox-layout" in command:
                value = bbox_bytes(value.decode("utf-8", errors="replace"))
            return worker.Outcome("completed", value)
        if name == "java":
            return worker.Outcome("completed", json.dumps({"protocol": "pdf-features/v1", "status": "completed",
                "inventory_complete": True, "original_page_count": self.count, "encrypted": False,
                "can_extract": True, "ancillary_absent": True,
                "feature_counts": dict.fromkeys(worker.PDF_FEATURE_COUNTS, 0), "reason_codes": []}).encode())
        if "image_units.py" in command[1]:
            operation = command[2]
            if operation == "render":
                (self.directory / "unit.png").write_bytes(b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", 10, 10))
            return worker.Outcome("completed", json.dumps({"ok": True, "unit_count": self.count, "original_format": "TIFF",
                                                          "nonvisual_content_present": self.image_metadata}).encode())
        raise AssertionError("unexpected command")


@pytest.fixture
def source(tmp_path):
    path = tmp_path / "synthetic-private-filename.pdf"
    path.write_bytes(pdf_bytes(2))
    return path


def test_original_pdf_units_are_counted_and_each_is_rendered_and_ocr_attempted(source, tmp_path):
    result = worker.process_file(source, "pdf", temp_parent=tmp_path, runner_factory=FakeRunner)
    assert result["protocol"] == "parser-accounting/v1"
    assert result["original_unit_count"] == 2
    assert [unit["ordinal"] for unit in result["units"]] == [1, 2]
    assert all(unit["render_status"] == unit["ocr_status"] == "completed" for unit in result["units"])
    assert all(unit["native_status"] == "completed" and unit["native_text"] == FakeRunner.native.decode() for unit in result["units"])
    assert all(unit["geometry_verified"] and unit["native_words"] and unit["ocr_words"] for unit in result["units"])
    assert result["text_characters"] == sum(len(unit["text"]) + len(unit["native_text"]) for unit in result["units"])
    assert result["page_accounting_complete"] is True
    assert result["embedded_annotation_coverage"] == "unverified"
    assert result["legibility_verified"] is False
    assert "private" not in json.dumps(result)
    assert not list(tmp_path.glob("page-ocr-*"))


def test_empty_successful_ocr_is_processed_but_not_proven_legible(source):
    class Empty(FakeRunner):
        ocr = b""
    result = worker.process_file(source, "pdf", runner_factory=Empty)
    assert result["page_accounting_complete"] is True
    assert all(unit["text"] == "" and unit["ocr_status"] == "completed" for unit in result["units"])
    assert result["legibility_verified"] is False


def test_page_and_text_limits_never_claim_complete(source):
    pages = worker.process_file(source, "pdf", worker.Limits.bounded(pages=1), runner_factory=FakeRunner)
    assert pages["original_unit_count"] == 2 and pages["units_omitted"] == 1
    assert pages["limited"] and not pages["page_accounting_complete"]
    text = worker.process_file(source, "pdf", worker.Limits.bounded(text_chars=4), runner_factory=FakeRunner)
    assert text["text_characters"] == 4
    assert text["units"][0]["ocr_status"] == "limited"
    assert text["units"][0]["text"] == "synt"
    assert not text["page_accounting_complete"]


@pytest.mark.parametrize("program", ["pdfinfo", "pdftoppm", "tesseract", "pdftotext"])
def test_stage_failures_are_sanitized_and_incomplete(source, program):
    class Failed(FakeRunner):
        failing = program
    result = worker.process_file(source, "pdf", runner_factory=Failed)
    assert result["page_accounting_complete"] is False
    assert "private filename" not in json.dumps(result)
    if program == "pdfinfo":
        assert result["original_unit_count"] is None


def test_native_pages_and_blank_pages_keep_original_ordinals_and_both_channels(source):
    class NativePages(FakeRunner):
        native = [b"patient page one", b""]
    result = worker.process_file(source, "pdf", runner_factory=NativePages)
    assert [unit["ordinal"] for unit in result["units"]] == [1, 2]
    assert [unit["native_text"] for unit in result["units"]] == ["patient page one", ""]
    assert all(unit["native_status"] == unit["ocr_status"] == "completed" for unit in result["units"])
    assert result["page_accounting_complete"]


def test_native_and_ocr_share_one_budget_without_changing_ocr_text(source):
    class Channels(FakeRunner):
        ocr = b"OCR"
        native = b"NATIVE"
    result = worker.process_file(source, "pdf", worker.Limits.bounded(text_chars=5), runner_factory=Channels)
    page = result["units"][0]
    assert page["text"] == "OCR" and page["ocr_status"] == "completed" and not page["truncated"]
    assert page["native_text"] == "NA" and page["native_status"] == "limited" and page["native_text_truncated"]
    assert result["text_characters"] == 5 and result["units_omitted"] == 1
    assert result["limited"] and not result["page_accounting_complete"]


def test_geometry_failures_do_not_hide_plain_channel_text_or_invent_processing_failure(source):
    class Mismatch(FakeRunner):
        def run(self, command, **kwargs):
            outcome = super().run(command, **kwargs)
            if command[0] == "pdftotext" and "-bbox-layout" in command:
                outcome.data = bbox_bytes("different words")
            return outcome
    result = worker.process_file(source, "pdf", runner_factory=Mismatch)
    assert result["page_accounting_complete"] and not result["limited"]
    assert all(unit["native_text"] == FakeRunner.native.decode() and unit["text"] == FakeRunner.ocr.decode() for unit in result["units"])
    assert all(not unit["geometry_verified"] and unit["geometry_reason"] == "geometry_text_unverified" for unit in result["units"])


def test_geometry_budget_retains_text_and_reports_only_geometry_limit(source, monkeypatch):
    monkeypatch.setattr(worker.geometry, "MAX_WORDS", 4)
    result = worker.process_file(source, "pdf", runner_factory=FakeRunner)
    assert result["page_accounting_complete"] and not result["limited"]
    assert all(unit["geometry_reason"] == "geometry_limit" and not unit["native_words"] and not unit["ocr_words"] for unit in result["units"])
    assert all(unit["native_text"] and unit["text"] for unit in result["units"])


def test_geometry_repeated_values_and_distinct_blocks_are_not_deduplicated():
    xml = b'<html><doc><page width="72" height="72"><flow><block><line><word xMin="1" yMin="1" xMax="10" yMax="10">SAME</word></line></block><block><line><word xMin="40" yMin="40" xMax="50" yMax="50">SAME</word></line></block></flow></page></doc></html>'
    width, height, words = worker.geometry.native_words(xml)
    assert (width, height) == (72, 72)
    assert len(words) == 2 and [word["block"] for word in words] == [1, 2]
    assert worker.geometry.word_lines(words) == "SAME\n\nSAME"
    assert words[0]["left"] != words[1]["left"]


@pytest.mark.parametrize("mutation", [b'xMin="-1"', b'xMin="nan"', b'xMin="80"'])
def test_geometry_rejects_invalid_rectangles_without_clamping(mutation):
    data = bbox_bytes("SAME").replace(b'xMin="1"', mutation)
    with pytest.raises(worker.geometry.GeometryError):
        worker.geometry.native_words(data)


def test_geometry_mapping_requires_same_zero_origin_boxes_and_no_rotation():
    info = b"Page 1 MediaBox: 0 0 72 72\nPage 1 CropBox: 0 0 72 72\nPage 1 rot: 0\n"
    assert worker.geometry.verified_mapping(info, 1, 72, 72, 200, 200)
    for changed in (info.replace(b"rot: 0", b"rot: 90"), info.replace(b"CropBox: 0", b"CropBox: 1"), info.replace(b"0 0 72 72", b"1 1 73 73")):
        assert not worker.geometry.verified_mapping(changed, 1, 72, 72, 200, 200)
    assert not worker.geometry.verified_mapping(info, 1, 72, 72, 201, 200)


def test_geometry_mapping_accounts_only_for_pdfinfo_two_decimal_display_precision():
    info = b"Page 1 MediaBox: 0.00 0.00 595.28 841.89\nPage 1 CropBox: 0.00 0.00 595.28 841.89\nPage 1 rot: 0\n"
    assert worker.geometry.verified_mapping(info, 1, 595.275600, 841.889800, 1654, 2339)
    # A difference beyond the displayed rounding interval is never admitted.
    for width, height in ((595.2749, 841.8898), (595.2851, 841.8898), (595.2756, 841.8849), (595.2756, 841.8951)):
        assert not worker.geometry.verified_mapping(info, 1, width, height, 1654, 2339)
    for changed in (info.replace(b"rot: 0", b"rot: 90"),
                    info.replace(b"CropBox: 0.00", b"CropBox: 0.01"),
                    info.replace(b"0.00 0.00", b"0.01 0.01"),
                    info.replace(b"CropBox: 0.00 0.00 595.28", b"CropBox: 0.00 0.00 595.27")):
        assert not worker.geometry.verified_mapping(changed, 1, 595.2756, 841.8898, 1654, 2339)
    assert not worker.geometry.verified_mapping(info, 1, 595.2756, 841.8898, 1655, 2339)


def test_real_a4_fixture_poppler_geometry_when_available(tmp_path):
    if not all(shutil.which(command) for command in ("pdfinfo", "pdftoppm", "pdftotext")):
        pytest.skip("Poppler binaries unavailable")
    fixture = DIRECTORY.parents[1] / "fixtures/parser/mixed.pdf"
    # This is the small, checked-in synthetic fixture, not a hospital document.
    assert fixture.stat().st_size < 100_000
    for ordinal in (1, 2):
        page = str(ordinal)
        info = subprocess.check_output(["pdfinfo", "-f", page, "-l", page, "-box", str(fixture)], timeout=5)
        bbox = subprocess.check_output(["pdftotext", "-f", page, "-l", page, "-bbox-layout", "-enc", "UTF-8", str(fixture), "-"], timeout=5)
        assert len(info) < 65536 and len(bbox) < worker.geometry.MAX_GEOMETRY_BYTES
        width, height, _ = worker.geometry.native_words(bbox)
        pixel_width, pixel_height = worker._pdf_dimensions(info, ordinal, worker.MAX_PIXELS)
        output = tmp_path / f"page-{ordinal}"
        subprocess.run(["pdftoppm", "-f", page, "-l", page, "-singlefile", "-r", "200",
                        "-scale-to-x", str(pixel_width), "-scale-to-y", str(pixel_height), "-png", str(fixture), str(output)],
                       check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        actual_width, actual_height = worker._png_size(output.with_suffix(".png"), worker.MAX_PIXELS)
        assert worker.geometry.verified_mapping(info, ordinal, width, height, actual_width, actual_height)


@pytest.mark.parametrize("outcome", [worker.Outcome("completed", b"\xff"), worker.Outcome("processing_timeout")])
def test_native_decode_and_timeout_failures_never_complete(source, outcome):
    class FailedNative(FakeRunner):
        def run(self, command, **kwargs):
            return outcome if command[0] == "pdftotext" else super().run(command, **kwargs)
    result = worker.process_file(source, "pdf", runner_factory=FailedNative)
    assert not result["page_accounting_complete"]
    assert all(unit["native_status"] == "failed" and unit["native_text"] == "" for unit in result["units"])
    assert all(unit["ocr_status"] == "completed" for unit in result["units"])


def test_pixel_budget_rejects_page_before_render(source):
    result = worker.process_file(source, "pdf", worker.Limits.bounded(pixels=100), runner_factory=FakeRunner)
    assert result["limited"] and not result["page_accounting_complete"]
    assert all(unit["ocr_status"] == "not_attempted" for unit in result["units"])


def test_image_frame_inventory_and_nonvisual_metadata_flag(source):
    result = worker.process_file(source, "image", runner_factory=FakeRunner)
    assert result["original_format"] == "TIFF" and result["original_unit_count"] == 2
    assert result["page_accounting_complete"]
    assert result["nonvisual_content_present"] is False
    class Metadata(FakeRunner):
        image_metadata = True
    assert worker.process_file(source, "image", runner_factory=Metadata)["nonvisual_content_present"] is True


def test_unknown_image_metadata_and_descriptive_tiff_tags_are_conservative():
    class Image:
        format = "TIFF"
        info = {"compression": "raw", "dpi": (72, 72)}
        tag_v2 = {256: 10, 257: 10, 258: 8, 259: 1, 262: 1, 273: 100, 277: 1, 278: 10, 279: 100}
    assert images.nonvisual_content(Image()) is False
    hidden = Image()
    hidden.tag_v2 = {**hidden.tag_v2, 315: "synthetic artist metadata"}
    assert images.nonvisual_content(hidden) is True
    unknown = Image()
    unknown.info = {"unknown": "synthetic metadata"}
    assert images.nonvisual_content(unknown) is True


def test_loaded_tiff_frame_does_not_repeat_exif_orientation(monkeypatch, tmp_path):
    class LegacyTiff:
        format, n_frames, size, mode = "TIFF", 2, (10, 10), "RGB"
        info, tag_v2 = {}, {256: 10, 257: 10}
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def seek(self, frame):
            self.fp, self.cached = object(), False
        def getexif(self):
            if not self.cached and self.fp is None:
                raise AttributeError("closed TIFF frame")
            self.cached = True
            return {}
        def load(self): self.fp = None
        def copy(self): return self
        def getbands(self): return ("R", "G", "B")
        def convert(self, mode): return self
        def save(self, path, format): Path(path).write_bytes(b"synthetic PNG")
    image = LegacyTiff()
    def transpose(value):
        value.getexif()
        return value
    pillow = SimpleNamespace(Image=SimpleNamespace(open=lambda *args, **kwargs: image,
        DecompressionBombWarning=type("BombWarning", (Warning,), {}),
        DecompressionBombError=type("BombError", (Exception,), {})),
        ImageOps=SimpleNamespace(exif_transpose=transpose))
    monkeypatch.setitem(sys.modules, "PIL", pillow)
    for ordinal in (1, 2):
        result = images.process("render", tmp_path / "input", tmp_path / "unit.png", ordinal, 100)
        assert result["ok"] is True
        assert result["nonvisual_content_present"] is False


def test_pdf_feature_count_disagreement_and_untrusted_fields_stay_incomplete(source):
    class Disagrees(FakeRunner):
        def run(self, command, **kwargs):
            outcome = super().run(command, **kwargs)
            if command[0] == "java":
                data = json.loads(outcome.data)
                data["original_page_count"] = 1
                data["private_extra"] = "must not escape"
                outcome.data = json.dumps(data).encode()
            return outcome
    result = worker.process_file(source, "pdf", runner_factory=Disagrees)
    assert not result["page_accounting_complete"]
    assert "pdf_page_count_mismatch" in result["reason_codes"]
    assert "must not escape" not in json.dumps(result)
    assert result["embedded_annotation_coverage"] == "unverified"


def test_pdf_feature_invalid_success_is_rejected(source):
    class Invalid(FakeRunner):
        def run(self, command, **kwargs):
            outcome = super().run(command, **kwargs)
            if command[0] == "java":
                data = json.loads(outcome.data)
                data["feature_counts"]["annotations"] = 1
                outcome.data = json.dumps(data).encode()
            return outcome
    result = worker.process_file(source, "pdf", runner_factory=Invalid)
    assert result["pdf_features"]["status"] == "failed"
    assert not result["pdf_features"]["ancillary_absent"]
    assert "pdf_feature_inspection_failed" in result["reason_codes"]


def test_timeout_interrupt_and_unknown_child_diagnostics_cannot_be_complete(source, tmp_path):
    class Interrupted(FakeRunner):
        def run(self, command, **kwargs):
            raise worker.JobInterrupted()
    result = worker.process_file(source, "pdf", temp_parent=tmp_path, runner_factory=Interrupted)
    assert result["reason_codes"] == ["job_interrupted"]
    assert not result["page_accounting_complete"]
    assert not list(tmp_path.glob("page-ocr-*"))
    class Unknown(FakeRunner):
        def run(self, command, **kwargs):
            return worker.Outcome("completed", b'{"ok":false,"reason":"private diagnostic"}')
    result = worker.process_file(source, "image", runner_factory=Unknown)
    assert "private diagnostic" not in json.dumps(result)


def test_limits_are_clamped_and_input_size_is_checked_before_parser(tmp_path):
    assert worker.Limits.bounded(1000, 100_000_000, 5_000_000, 999) == worker.Limits()
    with pytest.raises(ValueError):
        worker.Limits.bounded(seconds=float("inf"))
    source = tmp_path / "large.pdf"
    with source.open("wb") as output:
        output.truncate(worker.MAX_INPUT_BYTES + 1)
    result = worker.process_file(source, "pdf")
    assert result["reason_codes"] == ["input_size_limit"]
    assert result["limited"] and result["original_unit_count"] is None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Production resource supervisor requires Linux")
def test_real_supervisor_bounds_child_output_and_kills_descendants(tmp_path):
    runner = worker.Runner(tmp_path, time.monotonic() + 3)
    output = runner.run([sys.executable, "-c", "import os; os.write(1, b'x' * 1000000)"], output_bytes=1024)
    assert output.status == "output_limit" and len(output.data) == 1024
    marker = tmp_path / "descendant-must-not-run"
    descendant = f"import time; from pathlib import Path; time.sleep(.5); Path({str(marker)!r}).write_text('bad')"
    program = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{descendant!r}]); time.sleep(3)"
    result = runner.run([sys.executable, "-c", program], phase_seconds=.15)
    assert result.status == "processing_timeout"
    time.sleep(.6)
    assert not marker.exists()
    assert not runner.active


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Production resource supervisor requires Linux")
def test_real_poppler_inventory_and_render_when_available(source, tmp_path):
    if not all(shutil.which(command) for command in ("pdfinfo", "pdftoppm", "pdftotext")):
        pytest.skip("Poppler binaries unavailable")
    source.write_bytes(pdf_bytes(2, ["PAGE_ONE", ""]))
    class RealPoppler(worker.Runner):
        def run(self, command, **kwargs):
            if command[0] == "tesseract":
                (self.directory / "ocr.txt").write_bytes(b"synthetic OCR result")
                (self.directory / "ocr.tsv").write_bytes(tsv_bytes("synthetic OCR result"))
                return worker.Outcome("completed")
            return super().run(command, **kwargs)
    result = worker.process_file(source, "pdf", temp_parent=tmp_path, runner_factory=RealPoppler)
    assert result["original_unit_count"] == 2, result
    assert result["page_accounting_complete"], result
    assert all(unit["pixel_width"] == unit["pixel_height"] == 200 for unit in result["units"])
    assert result["units"][0]["native_text"].strip() == "PAGE_ONE"
    assert result["units"][1]["native_text"].strip() == ""
    assert all(unit["native_status"] == "completed" for unit in result["units"])


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Production resource supervisor requires Linux")
def test_gateway_termination_cleans_private_files_and_child_groups(source, tmp_path):
    ready, marker = tmp_path / "ready", tmp_path / "descendant-must-not-run"
    descendant = f"import time; from pathlib import Path; time.sleep(.8); Path({str(marker)!r}).write_text('bad')"
    program = ("import subprocess,sys,time\nfrom pathlib import Path\n"
               f"subprocess.Popen([sys.executable,'-c',{descendant!r}])\n"
               f"Path({str(ready)!r}).write_text('ready')\ntime.sleep(10)\n")
    # The deployment's private tmpfs is deliberately noexec. Launch the trusted
    # Python binary and substitute only this synthetic pdfinfo workload, while
    # preserving the actual Runner supervisor, child groups and signal handler.
    launcher = (f"import sys\nsys.path.insert(0, {str(DIRECTORY)!r})\nimport page_ocr\n"
                "original_run = page_ocr.Runner.run\n"
                "def synthetic_run(self, command, **kwargs):\n"
                f"    if command[0] == 'pdfinfo': command = [sys.executable, '-c', {program!r}]\n"
                "    return original_run(self, command, **kwargs)\n"
                "page_ocr.Runner.run = synthetic_run\npage_ocr.main()\n")
    environment = dict(os.environ, TMPDIR=str(tmp_path))
    process = subprocess.Popen([sys.executable, "-c", launcher, "--input", str(source), "--kind", "pdf"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, start_new_session=True)
    try:
        until = time.monotonic() + 3
        while not ready.exists() and process.poll() is None and time.monotonic() < until:
            time.sleep(.02)
        assert ready.exists(), "Synthetic child did not start"
        os.killpg(process.pid, signal.SIGTERM)
        output, diagnostic = process.communicate(timeout=3)
        assert not diagnostic
        result = json.loads(output)
        assert result["reason_codes"] == ["job_interrupted"]
        assert not result["page_accounting_complete"]
        assert not list(tmp_path.glob("page-ocr-*"))
        time.sleep(.9)
        assert not marker.exists()
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


def test_real_pillow_multiframe_and_metadata_when_available(tmp_path):
    Image = pytest.importorskip("PIL.Image")
    PngImagePlugin = pytest.importorskip("PIL.PngImagePlugin")
    tiff = tmp_path / "frames.tif"
    Image.new("RGB", (20, 30), "white").save(tiff, save_all=True, append_images=[Image.new("RGB", (30, 20), "white")])
    inventory = images.process("inventory", tiff, tmp_path / "unit.png", 0, worker.MAX_PIXELS)
    assert inventory["unit_count"] == 2 and inventory["nonvisual_content_present"] is False
    for ordinal in (1, 2):
        assert images.process("render", tiff, tmp_path / "unit.png", ordinal, worker.MAX_PIXELS)["ok"] is True
    info = PngImagePlugin.PngInfo()
    info.add_text("Comment", "Synthetic nonvisual metadata")
    png = tmp_path / "metadata.png"
    Image.new("RGB", (20, 20), "white").save(png, pnginfo=info)
    assert images.process("inventory", png, tmp_path / "unit.png", 0, worker.MAX_PIXELS)["nonvisual_content_present"] is True
