import test from "node:test";
import assert from "node:assert/strict";
import {
  findingComparisonView,
  findingDeltaKey,
} from "../src/comparison-view.ts";

const provenance = { detector_changed: false, options_changed: false };
const delta = (change, before_count, after_count, extra = {}) => ({
  entity_type: "EMAIL_ADDRESS",
  classification: "personal_data",
  reason: "pattern_match",
  segment: "column",
  change,
  before_count,
  after_count,
  ...extra,
});
const object = (finding_deltas = [], extra = {}) => ({
  location: "synthetic/records/contact",
  change: "changed",
  reason: "Comparable content changed.",
  finding_comparison: "comparable",
  finding_deltas,
  ...extra,
});

test("comparable type changes retain exact before/after match counts and separate unchanged groups", () => {
  const changes = [
    delta("new", 0, 2),
    delta("changed", 4, 5, { entity_type: "PERSON" }),
    delta("no_longer_observed", 3, 0, { entity_type: "PAN" }),
  ];
  const unchanged = delta("unchanged", 7, 7, { entity_type: "PHONE_NUMBER" });
  assert.deepEqual(
    findingComparisonView(object([...changes, unchanged]), provenance),
    {
      comparable: true,
      changed: changes,
      unchanged: [unchanged],
    },
  );
});

test("coverage gaps and sampled observations cannot display removal even if deltas are supplied", () => {
  for (const change of ["coverage_lost", "not_comparable"]) {
    const result = findingComparisonView(
      object([delta("no_longer_observed", 8, 0)], { change }),
      provenance,
    );
    assert.equal(result.comparable, false);
    assert.equal("changed" in result, false);
  }
  const sampled = findingComparisonView(
    object([delta("no_longer_observed", 8, 0)], {
      finding_comparison: "not_comparable",
      finding_comparison_reason:
        "Sampled observations cannot establish disappearance.",
    }),
    provenance,
  );
  assert.deepEqual(sampled, {
    comparable: false,
    reason: "Sampled observations cannot establish disappearance.",
  });
});

test("detector and scan-policy changes suppress finding deltas", () => {
  for (const flags of [{ detector_changed: true }, { options_changed: true }]) {
    const result = findingComparisonView(
      object([delta("no_longer_observed", 5, 0)]),
      { ...provenance, ...flags },
    );
    assert.equal(result.comparable, false);
    assert.equal("changed" in result, false);
  }
});

test("missing or unknown provenance is unknown rather than an empty or removal result", () => {
  assert.equal(
    findingComparisonView(
      { location: "synthetic.txt", change: "changed", reason: "Old response" },
      provenance,
    ).comparable,
    false,
  );
  assert.equal(
    findingComparisonView(
      object([], { finding_comparison: undefined }),
      provenance,
    ).comparable,
    false,
  );
  assert.equal(
    findingComparisonView(
      { ...object(), finding_deltas: undefined },
      provenance,
    ).comparable,
    false,
  );
  const unknown = findingComparisonView(
    object([], {
      finding_comparison: "not_comparable",
      finding_comparison_reason: "Detector provenance is unknown.",
    }),
    provenance,
  );
  assert.equal(unknown.reason, "Detector provenance is unknown.");
});

test("invalid counts fail closed instead of displaying manufactured zero matches", () => {
  for (const value of [
    undefined,
    -1,
    NaN,
    Infinity,
    1.5,
    Number.MAX_SAFE_INTEGER + 1,
  ]) {
    assert.equal(
      findingComparisonView(object([delta("changed", value, 1)]), provenance)
        .comparable,
      false,
    );
    assert.equal(
      findingComparisonView(object([delta("changed", 1, value)]), provenance)
        .comparable,
      false,
    );
  }
  assert.deepEqual(findingComparisonView(object(), provenance), {
    comparable: true,
    changed: [],
    unchanged: [],
  });
});

test("finding identities preserve reason and record segment boundaries", () => {
  const first = delta("changed", 1, 2, { reason: "column/a", segment: "b" });
  const second = delta("changed", 1, 2, { reason: "column", segment: "a/b" });
  assert.notEqual(findingDeltaKey(first), findingDeltaKey(second));
  assert.notEqual(
    findingDeltaKey(first),
    findingDeltaKey({ ...first, classification: "patient_linked_health" }),
  );
  assert.equal(
    findingDeltaKey(first),
    findingDeltaKey({ ...first, before_count: 7, after_count: 9 }),
  );
});
