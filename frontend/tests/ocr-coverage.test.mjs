import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ocrCoverage } from "../src/ocr-coverage.ts";

const unit = (ordinal, extra = {}) => ({ ordinal, render_status: "completed", ocr_status: "completed",
  text_truncated: false, text_characters: 12, ...extra });
const metadata = (extra = {}) => ({ extractor: "isolated_page_ocr", original_unit_count: 2,
  units_omitted: 0, units: [unit(1), unit(2)], page_accounting_complete: true,
  nonvisual_content_present: false, embedded_annotation_coverage: "not_applicable", ...extra });

test("direct image and nested PDF accounting preserve original unit counts", () => {
  for (const raw of [metadata(), { page_ocr: metadata() }, JSON.stringify(metadata()), JSON.stringify({ page_ocr: metadata() })]) {
    const view = ocrCoverage(raw);
    assert.equal(view.valid, true);
    assert.equal(view.completed, 2);
    assert.equal(view.total, 2);
    assert.equal(view.complete, true);
  }
});

test("actual packaged API metadata objects expose OCR accounting without string conversion", () => {
  const fixture = JSON.parse(readFileSync(new URL("../../fixtures/evaluation/deployed-synthetic-findings.json", import.meta.url), "utf8"));
  assert.equal(fixture.objects.length, 3);
  for (const object of fixture.objects) {
    assert.equal(typeof object.metadata, "object");
    const accounting = object.metadata.page_ocr ?? object.metadata;
    const view = ocrCoverage(object.metadata);
    assert.equal(view.valid, true);
    assert.equal(view.total, accounting.original_unit_count);
    assert.equal(view.completed, accounting.units_ocr_completed);
  }
});

test("failed, omitted and truncated units remain visible without complete claims", () => {
  const failed = ocrCoverage(JSON.stringify(metadata({ units: [unit(1), unit(2, { ocr_status: "failed" })] })));
  assert.equal(failed.completed, 1);
  assert.equal(failed.units[1].ocrStatus, "failed");
  assert.equal(failed.complete, false);
  const omitted = ocrCoverage(JSON.stringify(metadata({ units: [unit(1)], units_omitted: 1 })));
  assert.equal(omitted.omitted, 1);
  assert.equal(omitted.complete, false);
  const limited = ocrCoverage(JSON.stringify(metadata({ units: [unit(1), unit(2, { text_truncated: true, ocr_status: "limited" })] })));
  assert.equal(limited.units[1].truncated, true);
  assert.equal(limited.completed, 1);
});

test("unknown inventory is unknown rather than zero-unit success", () => {
  const view = ocrCoverage(JSON.stringify(metadata({ original_unit_count: null, units_omitted: null, units: [] })));
  assert.equal(view.total, null);
  assert.equal(view.complete, false);
});

test("invalid accounting cannot produce apparently complete coverage", () => {
  for (const extra of [
    { original_unit_count: -1 }, { units_omitted: 4 }, { units: [unit(1), unit(1)] },
    { units: [unit(1), unit(2, { render_status: "failed" })] },
    { units: [unit(1), unit(2, { ocr_status: "private arbitrary status" })] },
    { original_unit_count: null, units_omitted: null },
  ]) assert.deepEqual(ocrCoverage(JSON.stringify(metadata(extra))), { valid: false });
  assert.equal(ocrCoverage("{"), null);
  assert.equal(ocrCoverage(JSON.stringify({ extractor: "legacy_tika", text: "private" })), null);
});

test("display model excludes text, metadata values, arbitrary errors and filenames", () => {
  const raw = metadata({ private_filename: "PRIVATE_SOURCE", reason_codes: ["PRIVATE_ERROR"],
    units: [unit(1, { text: "PRIVATE_PATIENT_VALUE", excerpt: "PRIVATE_EXCERPT" }), unit(2)],
    private_metadata: "PRIVATE_EXIF", nonvisual_content_present: true });
  const view = ocrCoverage(JSON.stringify(raw));
  assert.equal(JSON.stringify(view).includes("PRIVATE"), false);
  assert.equal(view.metadataUninspected, true);
});

test("successful empty OCR remains processed without a legibility assertion", () => {
  const view = ocrCoverage(JSON.stringify(metadata({ units: [unit(1, { text_characters: 0 }), unit(2)] })));
  assert.equal(view.complete, true);
  assert.equal(view.units[0].characters, 0);
  assert.equal("legibility_verified" in view, false);
});
