"""Bounded page/frame inventory, rendering and English OCR; no full-object claim.

All source paths and raw native diagnostics remain inside a private temporary job.
Native programs are fixed commands without a shell. Deployment must also provide
an isolated, egress-denied parser container and its memory/PID/tmpfs limits.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import pdf_geometry as geometry

PROTOCOL = "parser-accounting/v1"
MAX_INPUT_BYTES = 25 * 1024 * 1024
MAX_PAGES = 100
MAX_PIXELS = 20_000_000
MAX_TEXT_CHARS = 1_000_000
MAX_JOB_SECONDS = 55
MAX_IMAGE_BYTES = 100 * 1024 * 1024
HERE = Path(__file__).resolve().parent
PDF_FEATURE_COUNTS = {"annotations", "unknown_annotations", "forms", "xfa", "layers", "embedded_name_trees",
                      "associated_files", "file_specifications", "embedded_streams", "actions", "metadata", "other_text",
                      "interactive_features", "unknown_streams", "image_resources", "image_uses", "unused_images",
                      "unverified_image_uses", "unsupported_resources", "unsupported_operators", "unknown_structure", "parser_warnings",
                      "nondefault_user_units", "native_text_operations"}
PDF_FEATURE_REASONS = {"encrypted_pdf", "extraction_not_permitted", "pdf_ancillary_content_unverified", "pdf_feature_limit",
                       "pdf_feature_inspection_failed"}


class JobInterrupted(Exception):
    pass


@dataclass(frozen=True)
class Limits:
    pages: int = MAX_PAGES
    pixels: int = MAX_PIXELS
    text_chars: int = MAX_TEXT_CHARS
    seconds: float = MAX_JOB_SECONDS

    @classmethod
    def bounded(cls, pages=MAX_PAGES, pixels=MAX_PIXELS, text_chars=MAX_TEXT_CHARS, seconds=MAX_JOB_SECONDS):
        values = [int(pages), int(pixels), int(text_chars)]
        duration = float(seconds)
        if any(value < 1 for value in values) or not math.isfinite(duration) or duration <= 0:
            raise ValueError
        return cls(min(values[0], MAX_PAGES), min(values[1], MAX_PIXELS),
                   min(values[2], MAX_TEXT_CHARS), min(duration, MAX_JOB_SECONDS))


@dataclass
class Outcome:
    status: str
    data: bytes = b""


def _kill_group(process):
    # Kill the group even if the original process exited: a descendant may remain.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass


class Runner:
    def __init__(self, directory, deadline):
        self.directory, self.deadline = Path(directory), deadline
        self.active = set()

    def close(self):
        for process in list(self.active):
            _kill_group(process)
            self.active.discard(process)

    def run(self, command, *, output_bytes=65536, phase_seconds=10, file_bytes=None):
        remaining = min(phase_seconds, self.deadline - time.monotonic())
        if remaining <= 0:
            return Outcome("job_timeout")
        binary = shutil.which(command[0]) if not os.path.isabs(command[0]) else command[0]
        if not binary or not Path(binary).is_file():
            return Outcome("dependency_unavailable")
        command = [binary, *[str(value) for value in command[1:]]]
        resource_file_limit = file_bytes or output_bytes + 1
        wrapper = [sys.executable, str(HERE / "sandbox_exec.py"), str(remaining + 1), str(resource_file_limit), *command]
        environment = {key: value for key, value in os.environ.items()
                       if key in {"PATH", "TESSDATA_PREFIX", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"}}
        environment.update({"LC_ALL": "C", "LANG": "C", "OMP_THREAD_LIMIT": "1", "OMP_NUM_THREADS": "1",
                            "OPENBLAS_NUM_THREADS": "1", "HOME": str(self.directory), "TMPDIR": str(self.directory)})
        process = None
        started = time.monotonic()
        with tempfile.TemporaryFile(dir=self.directory) as captured:
            try:
                # Register the child before delivering termination, so outer gateway
                # cancellation cannot strand a just-created independent child group.
                previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
                try:
                    process = subprocess.Popen(wrapper, stdin=subprocess.DEVNULL, stdout=captured,
                                               stderr=subprocess.DEVNULL, cwd=self.directory, env=environment,
                                               start_new_session=True, close_fds=True)
                    self.active.add(process)
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous)
                status = "completed"
                while process.poll() is None:
                    if time.monotonic() >= self.deadline or time.monotonic() - started >= remaining:
                        status = "job_timeout" if time.monotonic() >= self.deadline else "processing_timeout"
                        break
                    if os.fstat(captured.fileno()).st_size > output_bytes:
                        status = "output_limit"
                        break
                    time.sleep(.02)
                if status != "completed":
                    _kill_group(process)
                captured.seek(0)
                data = captured.read(output_bytes + 1)
                if len(data) > output_bytes:
                    status, data = "output_limit", data[:output_bytes]
                elif status == "completed" and process.returncode != 0:
                    status = "process_failed"
                return Outcome(status, data)
            except (OSError, ValueError):
                return Outcome("process_failed")
            finally:
                if process is not None:
                    _kill_group(process)
                    self.active.discard(process)


def _report(kind, limits):
    return {"protocol": PROTOCOL, "kind": kind, "original_format": None,
            "original_unit_count": None, "units": [], "units_omitted": None,
            "nonvisual_content_present": None, "pdf_features": None,
            "page_accounting_complete": False, "limited": False, "reason_codes": [],
            "embedded_annotation_coverage": "unverified" if kind == "pdf" else "not_applicable",
            "legibility_verified": False, "text_characters": 0,
            "limits": {"input_bytes": MAX_INPUT_BYTES, "units": limits.pages, "pixels_per_unit": limits.pixels,
                       "text_characters": limits.text_chars, "job_seconds": limits.seconds}}


def _reason(report, reason):
    allowed = {"input_size_limit", "page_limit", "pixel_limit", "text_limit", "job_timeout", "processing_timeout", "job_interrupted",
               "unsupported_kind", "unsupported_pdf_header", "inventory_failed", "encrypted_pdf", "image_inventory_failed",
               "image_dependency_unavailable", "unsupported_image_format", "image_stage_failed", "dependency_unavailable",
               "process_failed", "output_limit", "input_changed", "input_unavailable", "processing_failed", "invalid_request",
               "page_dimensions_unavailable", "render_output_invalid", "image_render_failed", "unit_render_failed",
               "pdf_feature_inspection_failed", "pdf_feature_limit", "pdf_page_count_mismatch", "extraction_not_permitted",
               "invalid_text_encoding"}
    if reason not in allowed:
        reason = "processing_failed"
    if reason not in report["reason_codes"]:
        report["reason_codes"].append(reason)
    if reason in {"input_size_limit", "page_limit", "pixel_limit", "text_limit", "job_timeout", "processing_timeout", "job_interrupted"}:
        report["limited"] = True


def _copy_input(source, destination):
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as incoming:
        before = os.fstat(incoming.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("input_unavailable")
        if before.st_size > MAX_INPUT_BYTES:
            raise ValueError("input_size_limit")
        total = 0
        with destination.open("xb") as output:
            while True:
                data = incoming.read(min(65536, MAX_INPUT_BYTES + 1 - total))
                if not data:
                    break
                total += len(data)
                if total > MAX_INPUT_BYTES:
                    raise ValueError("input_size_limit")
                output.write(data)
        after = os.fstat(incoming.fileno())
        if total != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("input_changed")
    destination.chmod(0o400)


def _json(outcome):
    if outcome.status != "completed":
        return {"ok": False, "reason": outcome.status}
    try:
        value = json.loads(outcome.data)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, UnicodeDecodeError):
        return {"ok": False, "reason": "image_stage_failed"}


def _image_command(operation, source, output, ordinal, limits):
    return [sys.executable, str(HERE / "image_units.py"), operation, str(source), str(output), str(ordinal), str(limits.pixels)]


def _pdf_features(runner, source):
    failure = {"protocol": "pdf-features/v1", "status": "failed", "inventory_complete": False,
               "original_page_count": None, "encrypted": None, "can_extract": False, "ancillary_absent": False,
               "feature_counts": {key: 0 for key in sorted(PDF_FEATURE_COUNTS)},
               "reason_codes": ["pdf_feature_inspection_failed"]}
    outcome = runner.run(["java", "-Xms16m", "-Xmx128m", "-Xss256k", "-XX:MaxMetaspaceSize=96m", "-XX:ReservedCodeCacheSize=32m",
                          "-XX:-UseCompressedOops", "-XX:-UseCompressedClassPointers", "-XX:+UseSerialGC", "-XX:-UsePerfData",
                          "-cp", "/opt/tika/server.jar:" + str(HERE), "PdfFeatures", str(source)],
                         output_bytes=8192, phase_seconds=3, file_bytes=65536)
    value = _json(outcome)
    try:
        if value.get("protocol") != "pdf-features/v1" or value.get("status") not in {"completed", "failed", "limited"}:
            raise ValueError
        for field in ("inventory_complete", "can_extract", "ancillary_absent"):
            if type(value.get(field)) is not bool:
                raise ValueError
        if value.get("encrypted") is not None and type(value["encrypted"]) is not bool:
            raise ValueError
        pages = value.get("original_page_count")
        if pages is not None and (type(pages) is not int or not 1 <= pages <= 100):
            raise ValueError
        counts, reasons = value.get("feature_counts"), value.get("reason_codes")
        if not isinstance(counts, dict) or set(counts) != PDF_FEATURE_COUNTS:
            raise ValueError
        if any(type(count) is not int or not 0 <= count <= 200000 for count in counts.values()):
            raise ValueError
        if not isinstance(reasons, list) or len(reasons) > len(PDF_FEATURE_REASONS) or any(reason not in PDF_FEATURE_REASONS for reason in reasons):
            raise ValueError
        completed = value["status"] == "completed" and value["inventory_complete"] and pages is not None
        if value["inventory_complete"] != completed:
            raise ValueError
        eligible = completed and value["encrypted"] is False and value["can_extract"] and all(
            count == 0 for key, count in counts.items() if key not in {"image_resources", "image_uses", "native_text_operations"})
        if value["ancillary_absent"] != eligible:
            raise ValueError
        # Reconstruct only the agreed fixed fields: never forward arbitrary child JSON.
        return {**{field: value[field] for field in failure if field not in {"feature_counts", "reason_codes"}},
                "feature_counts": {key: counts[key] for key in sorted(PDF_FEATURE_COUNTS)}, "reason_codes": reasons}
    except (KeyError, TypeError, ValueError):
        return failure


def _png_size(filename, max_pixels):
    descriptor = os.open(filename, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as image:
        info = os.fstat(image.fileno())
        header = image.read(24)
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_IMAGE_BYTES or len(header) != 24 or header[:8] != b"\x89PNG\r\n\x1a\n" or header[12:16] != b"IHDR":
        raise ValueError("render_output_invalid")
    width, height = struct.unpack(">II", header[16:24])
    if not width or not height or width * height > max_pixels:
        raise ValueError("pixel_limit")
    return width, height


def _pdf_dimensions(data, ordinal, max_pixels):
    decoded = data.decode("utf-8", errors="strict")
    number = r"([+-]?(?:\d+(?:\.\d*)?|\.\d+))"
    match = re.search(r"^(?:Page\s+" + str(ordinal) + r"\s+)?MediaBox:\s*" + r"\s+".join([number] * 4) + r"\s*$", decoded, re.M)
    if not match:
        raise ValueError("page_dimensions_unavailable")
    left, bottom, right, top = [float(value) for value in match.groups()]
    width, height = math.ceil((right - left) * 200 / 72), math.ceil((top - bottom) * 200 / 72)
    if width <= 0 or height <= 0 or width * height > max_pixels:
        raise ValueError("pixel_limit")
    # Rotated pages swap output dimensions but preserve pixel area.
    rotation = re.search(r"^Page(?:\s+" + str(ordinal) + r")?\s+rot:\s*(-?\d+)\s*$", decoded, re.M)
    if rotation and int(rotation.group(1)) % 180:
        width, height = height, width
    return width, height


def _store_text(report, unit, outcome, limits, field="text"):
    remaining = limits.text_chars - report["text_characters"]
    status_field = "ocr_status" if field == "text" else "native_status"
    truncated_field = "truncated" if field == "text" else "native_text_truncated"
    channel = "ocr" if field == "text" else "native"
    if outcome.status not in {"completed", "output_limit"}:
        unit[status_field] = "failed"
        unit["reason_codes"].append(channel + "_" + outcome.status)
        _reason(report, outcome.status)
        return
    try:
        decoded = outcome.data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        if outcome.status != "output_limit":
            unit[status_field] = "failed"
            unit["reason_codes"].append(channel + "_invalid_utf8")
            _reason(report, "invalid_text_encoding")
            return
        decoded = outcome.data.decode("utf-8", errors="ignore")
    limited = len(decoded) > remaining or outcome.status == "output_limit"
    unit[field] = decoded[:remaining]
    report["text_characters"] += len(unit[field])
    unit[status_field] = "limited" if limited else "completed"
    if limited:
        unit[truncated_field] = True
        unit["reason_codes"].append("text_limit")
        _reason(report, "text_limit")


def _read_private_output(path, maximum):
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as incoming:
            if not stat.S_ISREG(os.fstat(incoming.fileno()).st_mode):
                return Outcome("process_failed")
            data = incoming.read(maximum + 1)
        return Outcome("output_limit" if len(data) > maximum else "completed", data[:maximum])
    except OSError:
        return Outcome("process_failed")


def _ocr_with_geometry(runner, directory, rendered, remaining):
    text_path, geometry_path = directory / "ocr.txt", directory / "ocr.tsv"
    try:
        text_path.unlink(missing_ok=True)
        geometry_path.unlink(missing_ok=True)
        outcome = runner.run(["tesseract", str(rendered), str(directory / "ocr"), "-l", "eng", "txt", "tsv"],
                             output_bytes=4096, phase_seconds=20, file_bytes=geometry.MAX_GEOMETRY_BYTES + 1)
        if outcome.status != "completed":
            return Outcome(outcome.status), None
        return _read_private_output(text_path, remaining * 4), _read_private_output(geometry_path, geometry.MAX_GEOMETRY_BYTES)
    finally:
        text_path.unlink(missing_ok=True)
        geometry_path.unlink(missing_ok=True)


def _ocr_word_geometry(unit, tsv):
    """Verified words in this rendered original unit's normalized pixel space.

    Word geometry is transient parser output, not a patient record boundary or
    a claim of legibility. Geometry failure never changes successful OCR text.
    """
    if (unit["render_status"] != "completed" or unit["ocr_status"] != "completed"
            or unit["truncated"] or tsv is None):
        raise geometry.GeometryError("channel_incomplete")
    if tsv.status != "completed":
        raise geometry.GeometryError("geometry_limit" if tsv.status == "output_limit" else "geometry_unavailable")
    words = geometry.ocr_words(tsv.data, unit["pixel_width"], unit["pixel_height"])
    if unit["text"].split() != [word["text"] for word in words]:
        raise geometry.GeometryError("geometry_text_unverified")
    return words


def _pdf_word_geometry(runner, source, unit, page_info, tsv, features):
    if unit["native_status"] != "completed" or unit["native_text_truncated"] or page_info is None:
        raise geometry.GeometryError("channel_incomplete")
    ocr_words = _ocr_word_geometry(unit, tsv)
    ordinal = unit["ordinal"]
    bbox = runner.run(["pdftotext", "-f", str(ordinal), "-l", str(ordinal), "-bbox-layout", "-enc", "UTF-8", str(source), "-"],
                      output_bytes=geometry.MAX_GEOMETRY_BYTES, phase_seconds=5)
    if bbox.status != "completed":
        raise geometry.GeometryError("geometry_limit" if bbox.status == "output_limit" else "geometry_unavailable")
    width, height, native_words = geometry.native_words(bbox.data)
    if unit["native_text"].split() != [word["text"] for word in native_words]:
        raise geometry.GeometryError("geometry_text_unverified")
    verified = (features is not None and features["inventory_complete"] and
                features["feature_counts"].get("nondefault_user_units") == 0 and
                geometry.verified_mapping(page_info, ordinal, width, height, unit["pixel_width"], unit["pixel_height"]))
    return native_words, ocr_words, verified


def process_file(filename, kind, limits=None, *, temp_parent=None, runner_factory=Runner):
    limits = limits or Limits()
    report = _report(kind, limits)
    if kind not in {"pdf", "image"}:
        _reason(report, "unsupported_kind")
        return report
    runner = None
    try:
        with tempfile.TemporaryDirectory(prefix="page-ocr-", dir=temp_parent) as temporary:
            directory = Path(temporary)
            source, rendered = directory / "input.bin", directory / "unit.png"
            runner = runner_factory(directory, time.monotonic() + limits.seconds)
            try:
                _copy_input(filename, source)
                if kind == "pdf":
                    with source.open("rb") as document:
                        if document.read(5) != b"%PDF-":
                            _reason(report, "unsupported_pdf_header")
                            return report
                    inventory = runner.run(["pdfinfo", "-enc", "UTF-8", str(source)], phase_seconds=5)
                    if inventory.status != "completed":
                        _reason(report, "inventory_failed")
                        _reason(report, inventory.status)
                        return report
                    metadata = inventory.data.decode("utf-8", errors="strict")
                    if re.search(r"^Encrypted:\s+yes\b", metadata, re.M | re.I):
                        _reason(report, "encrypted_pdf")
                        return report
                    pages = re.search(r"^Pages:\s+(\d+)\s*$", metadata, re.M)
                    if not pages or int(pages.group(1)) < 1:
                        _reason(report, "inventory_failed")
                        return report
                    count, report["original_format"] = int(pages.group(1)), "PDF"
                else:
                    metadata = _json(runner.run(_image_command("inventory", source, rendered, 0, limits), output_bytes=4096, phase_seconds=5))
                    if metadata.get("ok") is not True or type(metadata.get("unit_count")) is not int or metadata["unit_count"] < 1 or metadata.get("original_format") not in {"PNG", "JPEG", "TIFF", "BMP"}:
                        _reason(report, "inventory_failed")
                        _reason(report, metadata.get("reason", "image_inventory_failed"))
                        return report
                    count, report["original_format"] = metadata["unit_count"], metadata["original_format"]
                report["original_unit_count"] = count
                if kind == "pdf":
                    features = report["pdf_features"] = _pdf_features(runner, source)
                    if features["status"] != "completed":
                        _reason(report, "pdf_feature_limit" if features["status"] == "limited" else "pdf_feature_inspection_failed")
                    if features["original_page_count"] is not None and features["original_page_count"] != count:
                        _reason(report, "pdf_page_count_mismatch")
                    if features["encrypted"] is True or (features["inventory_complete"] and not features["can_extract"]):
                        _reason(report, "encrypted_pdf" if features["encrypted"] else "extraction_not_permitted")
                        return report
                if kind == "image":
                    report["nonvisual_content_present"] = metadata.get("nonvisual_content_present") is not False
                if count > limits.pages:
                    _reason(report, "page_limit")
                geometry_words_used = geometry_characters_used = 0
                for ordinal in range(1, min(count, limits.pages) + 1):
                    if time.monotonic() >= runner.deadline:
                        _reason(report, "job_timeout")
                        break
                    if report["text_characters"] >= limits.text_chars:
                        _reason(report, "text_limit")
                        break
                    unit = {"ordinal": ordinal, "render_status": "not_attempted", "ocr_status": "not_attempted", "text": "",
                            "pixel_width": None, "pixel_height": None, "truncated": False, "reason_codes": [],
                            "ocr_words": [], "geometry_verified": False, "geometry_reason": "channel_incomplete"}
                    if kind == "pdf":
                        unit.update({"native_status": "not_attempted", "native_text": "", "native_text_truncated": False,
                                     "native_words": []})
                    page_info_bytes, ocr_geometry = None, None
                    report["units"].append(unit)
                    try:
                        rendered.unlink(missing_ok=True)
                        if kind == "pdf":
                            page_info = runner.run(["pdfinfo", "-f", str(ordinal), "-l", str(ordinal), "-box", "-enc", "UTF-8", str(source)], phase_seconds=5)
                            if page_info.status != "completed":
                                raise ValueError(page_info.status)
                            page_info_bytes = page_info.data
                            width, height = _pdf_dimensions(page_info.data, ordinal, limits.pixels)
                            outcome = runner.run(["pdftoppm", "-f", str(ordinal), "-l", str(ordinal), "-singlefile", "-r", "200",
                                                  "-scale-to-x", str(width), "-scale-to-y", str(height), "-png", str(source), str(directory / "unit")],
                                                 phase_seconds=15, file_bytes=MAX_IMAGE_BYTES)
                            if outcome.status != "completed":
                                raise ValueError(outcome.status)
                        else:
                            image = _json(runner.run(_image_command("render", source, rendered, ordinal, limits), output_bytes=4096,
                                                     phase_seconds=15, file_bytes=MAX_IMAGE_BYTES))
                            if image.get("ok") is not True:
                                raise ValueError(image.get("reason", "image_render_failed"))
                            report["nonvisual_content_present"] |= image.get("nonvisual_content_present") is not False
                        unit["pixel_width"], unit["pixel_height"] = _png_size(rendered, limits.pixels)
                        unit["render_status"] = "completed"
                        remaining = limits.text_chars - report["text_characters"]
                        ocr, ocr_geometry = _ocr_with_geometry(runner, directory, rendered, remaining)
                        _store_text(report, unit, ocr, limits)
                    except (ValueError, OSError, OverflowError, UnicodeDecodeError) as error:
                        # Only allow our fixed codes, never arbitrary parser exception text.
                        known = {"pixel_limit", "page_dimensions_unavailable", "render_output_invalid", "image_render_failed",
                                 "dependency_unavailable", "process_failed", "output_limit", "job_timeout", "processing_timeout"}
                        reason = str(error) if str(error) in known else "unit_render_failed"
                        unit["render_status"] = "failed"
                        unit["reason_codes"].append(reason)
                        _reason(report, reason)
                    finally:
                        rendered.unlink(missing_ok=True)
                    if kind == "pdf":
                        # Keep native text in the same original-page boundary,
                        # separate from the OCR channel; no deduplication here.
                        # The shared character and wall-clock budgets cover both.
                        remaining = limits.text_chars - report["text_characters"]
                        if remaining <= 0:
                            unit["reason_codes"].append("native_text_budget_exhausted")
                            _reason(report, "text_limit")
                        else:
                            native = runner.run(["pdftotext", "-f", str(ordinal), "-l", str(ordinal), "-layout", "-nopgbrk",
                                                 "-enc", "UTF-8", str(source), "-"],
                                                output_bytes=remaining * 4, phase_seconds=5)
                            _store_text(report, unit, native, limits, "native_text")
                    try:
                        if kind == "pdf":
                            native_words, ocr_words, verified = _pdf_word_geometry(runner, source, unit, page_info_bytes, ocr_geometry, report["pdf_features"])
                        else:
                            native_words, ocr_words, verified = [], _ocr_word_geometry(unit, ocr_geometry), True
                        words = native_words + ocr_words
                        word_count, characters = len(words), sum(len(word["text"]) for word in words)
                        if geometry_words_used + word_count > geometry.MAX_WORDS or geometry_characters_used + characters > geometry.MAX_WORD_CHARACTERS:
                            raise geometry.GeometryError("geometry_limit")
                        geometry_words_used += word_count
                        geometry_characters_used += characters
                        unit.update({"ocr_words": ocr_words, "geometry_verified": verified,
                                     "geometry_reason": "verified" if verified else "mapping_unverified"})
                        if kind == "pdf":
                            unit["native_words"] = native_words
                    except geometry.GeometryError as error:
                        unit["geometry_reason"] = str(error)
            finally:
                runner.close()
    except JobInterrupted:
        _reason(report, "job_interrupted")
    except (OSError, ValueError, OverflowError, UnicodeDecodeError) as error:
        allowed = {"input_size_limit", "input_changed", "input_unavailable"}
        _reason(report, str(error) if str(error) in allowed else "processing_failed")
    finally:
        if runner is not None:
            runner.close()
        count = report["original_unit_count"]
        report["units_omitted"] = max(0, count - len(report["units"])) if count is not None else None
        report["page_accounting_complete"] = (count is not None and count == len(report["units"]) and not report["limited"]
            and "pdf_page_count_mismatch" not in report["reason_codes"]
            and all(unit["render_status"] == unit["ocr_status"] == "completed" for unit in report["units"])
            and (kind != "pdf" or all(unit["native_status"] == "completed" for unit in report["units"])))
    return report


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid_request")


def main():
    def interrupted(signum, frame):
        raise JobInterrupted()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        parser = Arguments(add_help=False)
        parser.add_argument("--input", required=True)
        parser.add_argument("--kind", required=True, choices=["pdf", "image"])
        parser.add_argument("--max-pages", type=int, default=MAX_PAGES)
        parser.add_argument("--max-pixels", type=int, default=MAX_PIXELS)
        parser.add_argument("--max-text-chars", type=int, default=MAX_TEXT_CHARS)
        parser.add_argument("--timeout-seconds", type=float, default=MAX_JOB_SECONDS)
        arguments = parser.parse_args()
        limits = Limits.bounded(arguments.max_pages, arguments.max_pixels, arguments.max_text_chars, arguments.timeout_seconds)
        report = process_file(arguments.input, arguments.kind, limits)
    except JobInterrupted:
        report = _report(None, Limits())
        _reason(report, "job_interrupted")
    except Exception:
        report = _report(None, Limits())
        _reason(report, "invalid_request")
    sys.stdout.write(json.dumps(report, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
