type RenderStatus = "not_attempted" | "completed" | "failed";
type OcrStatus = RenderStatus | "limited";
export type OcrUnit = {
  ordinal: number;
  renderStatus: RenderStatus;
  ocrStatus: OcrStatus;
  truncated: boolean;
  characters: number | null;
};
export type OcrCoverage = {
  valid: true;
  total: number | null;
  completed: number;
  omitted: number | null;
  units: OcrUnit[];
  complete: boolean;
  metadataUninspected: boolean;
  ancillaryUnverified: boolean;
} | { valid: false };

function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
function count(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

// Only return typed accounting fields. Patient text, filenames and arbitrary
// metadata strings never enter the display model, even from an old response.
export function ocrCoverage(raw: unknown): OcrCoverage | null {
  let parsed: unknown = raw;
  if (typeof raw === "string") {
    if (!raw || raw.length > 300_000) return null;
    try { parsed = JSON.parse(raw); } catch { return null; }
  }
  if (!record(parsed)) return null;
  const value = record(parsed.page_ocr) ? parsed.page_ocr : parsed;
  if (value.extractor !== "isolated_page_ocr" && value.protocol !== "parser-accounting/v1") return null;
  if (!Array.isArray(value.units) || value.units.length > 100) return { valid: false };
  const total = value.original_unit_count === null ? null : value.original_unit_count;
  const omitted = value.units_omitted === null ? null : value.units_omitted;
  if (total !== null && (!count(total) || total < 1)) return { valid: false };
  if (omitted !== null && !count(omitted)) return { valid: false };
  const units: OcrUnit[] = [];
  for (const unit of value.units) {
    if (!record(unit) || !count(unit.ordinal) || unit.ordinal !== units.length + 1 ||
        !["not_attempted", "completed", "failed"].includes(String(unit.render_status)) ||
        !["not_attempted", "completed", "failed", "limited"].includes(String(unit.ocr_status))) return { valid: false };
    const truncated = unit.text_truncated ?? unit.truncated;
    if (typeof truncated !== "boolean") return { valid: false };
    if (unit.render_status !== "completed" && unit.ocr_status !== "not_attempted") return { valid: false };
    units.push({ ordinal: unit.ordinal, renderStatus: unit.render_status as RenderStatus,
      ocrStatus: unit.ocr_status as OcrStatus, truncated,
      characters: count(unit.text_characters) ? unit.text_characters : null });
  }
  if (total !== null && (units.length > total || omitted !== total - units.length)) return { valid: false };
  if (total === null && (units.length > 0 || omitted !== null)) return { valid: false };
  const completed = units.filter(unit => unit.renderStatus === "completed" && unit.ocrStatus === "completed" && !unit.truncated).length;
  return { valid: true, total, completed, omitted, units,
    complete: value.page_accounting_complete === true && total !== null && completed === total,
    metadataUninspected: value.nonvisual_content_present !== false,
    ancillaryUnverified: value.embedded_annotation_coverage === "unverified" };
}
