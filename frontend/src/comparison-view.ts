import type { Comparison, FindingDelta, ObjectChange } from "./api";

export type FindingComparisonView =
  | { comparable: false; reason: string }
  | { comparable: true; changed: FindingDelta[]; unchanged: FindingDelta[] };

export function findingComparisonView(
  object: ObjectChange,
  comparison: Pick<Comparison, "detector_changed" | "options_changed">,
): FindingComparisonView {
  const unavailable = (fallback: string): FindingComparisonView => ({
    comparable: false,
    reason: object.finding_comparison_reason || fallback,
  });
  if (comparison.detector_changed || comparison.options_changed) {
    return unavailable(
      "Detector or scan policy changed; finding changes cannot be attributed to source content.",
    );
  }
  if (["coverage_lost", "not_comparable"].includes(object.change)) {
    return unavailable(
      object.reason || "Coverage is insufficient to establish finding changes.",
    );
  }
  if (
    object.finding_comparison !== "comparable" ||
    !Array.isArray(object.finding_deltas)
  ) {
    return unavailable(
      "Finding-level comparison is unavailable for these observations.",
    );
  }
  if (
    object.finding_deltas.some(
      (delta) =>
        !Number.isSafeInteger(delta.before_count) ||
        delta.before_count < 0 ||
        !Number.isSafeInteger(delta.after_count) ||
        delta.after_count < 0 ||
        !["new", "changed", "no_longer_observed", "unchanged"].includes(
          delta.change,
        ),
    )
  ) {
    return unavailable(
      "Finding counts are unavailable; no conclusion about disappearance can be drawn.",
    );
  }
  return {
    comparable: true,
    changed: object.finding_deltas.filter(
      (delta) => delta.change !== "unchanged",
    ),
    unchanged: object.finding_deltas.filter(
      (delta) => delta.change === "unchanged",
    ),
  };
}

export function findingDeltaKey(delta: FindingDelta) {
  return JSON.stringify([
    delta.entity_type,
    delta.classification,
    delta.reason,
    delta.segment,
  ]);
}
