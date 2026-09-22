"""Synthetic image-unit geometry checks; native OCR runs in packaged integration."""
import json
from pathlib import Path
import struct

import pytest

from test_parser_worker import FakeRunner, worker


def image_tsv(text, width, height):
    value = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n"
    value += f"1\t1\t0\t0\t0\t0\t0\t0\t{width}\t{height}\t-1\t\n"
    for index, word in enumerate(text.split()):
        value += f"5\t1\t1\t1\t1\t{index + 1}\t{10 + index * 30}\t10\t20\t20\t90\t{word}\n"
    return value.encode()


class ImageRunner(FakeRunner):
    count = 3
    texts = ("FRAME_ONE SAME", "", "FRAME_THREE SAME")

    def run(self, command, **kwargs):
        if Path(command[0]).name == "tesseract":
            self.commands.append(command)
            assert command[-2:] == ["txt", "tsv"] and command[2] != "stdout"
            text = self.texts[self.ordinal - 1]
            (self.directory / "ocr.txt").write_text(text)
            (self.directory / "ocr.tsv").write_bytes(image_tsv(text, self.width, self.height))
            return worker.Outcome("completed")
        result = super().run(command, **kwargs)
        if len(command) > 2 and "image_units.py" in str(command[1]) and command[2] == "render":
            self.ordinal = int(command[-2])
            self.width, self.height = 200 * self.ordinal, 100 * self.ordinal
            (self.directory / "unit.png").write_bytes(b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13)
                + b"IHDR" + struct.pack(">II", self.width, self.height))
        return result


@pytest.fixture
def source(tmp_path):
    # Source decoding is supplied by ImageRunner; no real patient image is used.
    value = tmp_path / "synthetic-original-frames.tiff"
    value.write_bytes(b"SYNTHETIC_MULTIFRAME_INPUT")
    return value


def test_image_frames_keep_original_ordinals_dimensions_blank_units_and_repeated_words(source, tmp_path):
    result = worker.process_file(source, "image", temp_parent=tmp_path, runner_factory=ImageRunner)
    assert result["original_unit_count"] == 3 and result["page_accounting_complete"]
    assert [unit["ordinal"] for unit in result["units"]] == [1, 2, 3]
    assert [(unit["pixel_width"], unit["pixel_height"]) for unit in result["units"]] == [(200, 100), (400, 200), (600, 300)]
    assert [unit["text"] for unit in result["units"]] == list(ImageRunner.texts)
    assert all(unit["geometry_verified"] and unit["geometry_reason"] == "verified" for unit in result["units"])
    assert result["units"][1]["ocr_words"] == []
    assert sum(word["text"] == "SAME" for unit in result["units"] for word in unit["ocr_words"]) == 2
    for unit in result["units"]:
        assert "native_words" not in unit and "native_status" not in unit
        assert [word["text"] for word in unit["ocr_words"]] == unit["text"].split()
        for word in unit["ocr_words"]:
            assert set(word) == {"text", "left", "top", "right", "bottom", "block", "line"}
            assert 0 <= word["left"] < word["right"] <= 1 and 0 <= word["top"] < word["bottom"] <= 1
    assert result["units"][0]["ocr_words"][0]["left"] == 10 / 200
    assert result["units"][2]["ocr_words"][0]["left"] == 10 / 600
    assert result["legibility_verified"] is False
    assert not list(tmp_path.glob("page-ocr-*"))


@pytest.mark.parametrize("failure,reason", [
    ("text_mismatch", "geometry_text_unverified"), ("dimensions", "geometry_invalid"),
    ("out_of_bounds", "geometry_invalid"), ("duplicate_word", "geometry_invalid"),
    ("invalid_utf8", "geometry_invalid"), ("missing_tsv", "geometry_unavailable"),
    ("tsv_limit", "geometry_limit"),
])
def test_bad_image_geometry_preserves_completed_ocr_text_and_processing_coverage(source, tmp_path, monkeypatch, failure, reason):
    if failure == "tsv_limit":
        monkeypatch.setattr(worker.geometry, "MAX_GEOMETRY_BYTES", 512)

    class BrokenGeometry(ImageRunner):
        count = 1
        def run(self, command, **kwargs):
            result = super().run(command, **kwargs)
            if Path(command[0]).name == "tesseract":
                path = self.directory / "ocr.tsv"
                data = path.read_bytes()
                if failure == "text_mismatch":
                    data = image_tsv("DIFFERENT WORDS", self.width, self.height)
                elif failure == "dimensions":
                    data = image_tsv(self.texts[0], self.width + 1, self.height)
                elif failure == "out_of_bounds":
                    data = data.replace(b"\t10\t10\t20\t20\t90\tFRAME_ONE", b"\t199\t10\t20\t20\t90\tFRAME_ONE")
                elif failure == "duplicate_word":
                    data += data.splitlines(keepends=True)[-1]
                elif failure == "invalid_utf8":
                    data = b"\xff"
                elif failure == "missing_tsv":
                    path.unlink()
                    return result
                elif failure == "tsv_limit":
                    data = b"x" * 513
                path.write_bytes(data)
            return result

    result = worker.process_file(source, "image", temp_parent=tmp_path, runner_factory=BrokenGeometry)
    unit = result["units"][0]
    assert result["page_accounting_complete"] and not result["limited"]
    assert result["reason_codes"] == []
    assert unit["text"] == ImageRunner.texts[0] and unit["ocr_status"] == "completed" and not unit["truncated"]
    assert unit["ocr_words"] == [] and not unit["geometry_verified"] and unit["geometry_reason"] == reason
    assert not list(tmp_path.glob("page-ocr-*"))


@pytest.mark.parametrize("budget,value", [("MAX_WORDS", 4), ("MAX_WORD_CHARACTERS", 18)])
def test_raster_geometry_limits_apply_across_all_original_frames(source, monkeypatch, budget, value):
    monkeypatch.setattr(worker.geometry, budget, value)
    class SameFrames(ImageRunner):
        texts = ("ALPHA BETA",) * 3
    result = worker.process_file(source, "image", runner_factory=SameFrames)
    assert result["page_accounting_complete"] and not result["limited"]
    assert [unit["geometry_verified"] for unit in result["units"]] == [True, True, False]
    assert result["units"][2]["geometry_reason"] == "geometry_limit"
    assert result["units"][2]["ocr_words"] == []
    assert all(unit["text"] == "ALPHA BETA" for unit in result["units"])


def test_truncated_raster_ocr_cannot_claim_verified_partial_word_geometry(source):
    result = worker.process_file(source, "image", worker.Limits.bounded(text_chars=4), runner_factory=ImageRunner)
    unit = result["units"][0]
    assert not result["page_accounting_complete"] and result["limited"]
    assert unit["truncated"] and unit["ocr_status"] == "limited" and unit["text"] == "FRAM"
    assert not unit["geometry_verified"] and unit["ocr_words"] == []
    assert unit["geometry_reason"] == "channel_incomplete"


def test_failed_raster_ocr_never_reuses_prior_frame_geometry_or_leaks_diagnostics(source, tmp_path):
    class FailsSecondFrame(ImageRunner):
        def run(self, command, **kwargs):
            if Path(command[0]).name == "tesseract" and self.ordinal == 2:
                # The preceding frame's private sidecar has already been removed.
                assert not (self.directory / "ocr.txt").exists()
                assert not (self.directory / "ocr.tsv").exists()
                return worker.Outcome("process_failed", b"PRIVATE_DIAGNOSTIC_MUST_NOT_ESCAPE")
            return super().run(command, **kwargs)
    result = worker.process_file(source, "image", temp_parent=tmp_path, runner_factory=FailsSecondFrame)
    assert [unit["geometry_verified"] for unit in result["units"]] == [True, False, True]
    assert not result["page_accounting_complete"]
    failed = result["units"][1]
    assert failed["ocr_status"] == "failed" and failed["text"] == "" and failed["ocr_words"] == []
    assert failed["geometry_reason"] == "channel_incomplete"
    assert "PRIVATE_DIAGNOSTIC" not in json.dumps(result)
    assert not list(tmp_path.glob("page-ocr-*"))


def test_interrupted_txt_tsv_generation_removes_all_private_outputs(source, tmp_path):
    class Interrupted(ImageRunner):
        def run(self, command, **kwargs):
            result = super().run(command, **kwargs)
            if Path(command[0]).name == "tesseract":
                raise worker.JobInterrupted()
            return result
    result = worker.process_file(source, "image", temp_parent=tmp_path, runner_factory=Interrupted)
    assert result["reason_codes"] == ["job_interrupted"] and not result["page_accounting_complete"]
    assert not list(tmp_path.glob("page-ocr-*"))
