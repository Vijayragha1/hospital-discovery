from collections import Counter

from sqlalchemy import select

from .models import Finding, Scan, ScanObject
from .provenance import provenance_is_known
from .security import decrypt


def compare_scans(db, baseline: Scan, current: Scan) -> dict:
    if baseline.source_id != current.source_id:
        raise ValueError("Compare scans of the same source.")
    if baseline.status != "completed" or current.status != "completed":
        raise ValueError("Both scans must be completed; interrupted scans do not establish comparable coverage.")
    old = {o.object_key: o for o in db.scalars(select(ScanObject).where(ScanObject.scan_id == baseline.id))}
    new = {o.object_key: o for o in db.scalars(select(ScanObject).where(ScanObject.scan_id == current.id))}
    detector_changed = baseline.detector_version != current.detector_version
    detector_provenance_unknown = not all(provenance_is_known(version)
                                          for version in (baseline.detector_version, current.detector_version))
    # Evidence retention does not change what content was examined or detected.
    options_changed = ({k: v for k, v in baseline.options.items() if k != "capture_evidence"} !=
                       {k: v for k, v in current.options.items() if k != "capture_evidence"})

    finding_cache = {}

    def findings(obj):
        if obj.id not in finding_cache:
            # Reasons and segment locators are classification metadata. Never load
            # FindingEvidence, raw matching values, excerpts or source credentials.
            finding_cache[obj.id] = Counter()
            for finding in db.scalars(select(Finding).where(Finding.object_id == obj.id)):
                identity = (finding.entity_type, finding.classification,
                            decrypt(finding.reason_encrypted), decrypt(finding.segment_encrypted))
                finding_cache[obj.id][identity] += finding.match_count
        return finding_cache[obj.id]

    def deltas(before, after):
        result = []
        for identity in sorted(before.keys() | after.keys()):
            old_count, new_count = before.get(identity, 0), after.get(identity, 0)
            state = ("new" if not old_count else "no_longer_observed" if not new_count
                     else "changed" if old_count != new_count else "unchanged")
            entity_type, classification, detection_reason, segment = identity
            result.append({"entity_type": entity_type, "classification": classification,
                           "reason": detection_reason, "segment": segment,
                           "before_count": old_count, "after_count": new_count, "change": state})
        return result

    def finding_comparison(a, b):
        if detector_provenance_unknown:
            return "Processing runtime identity was not recorded; run a new baseline."
        if detector_changed or options_changed:
            return "Detector or scan policy differs; finding changes cannot be attributed to the source."
        if b is None:
            return "The object was not inventoried; missing observations do not establish disappearance."
        if b.status != "full" or (a is not None and a.status != "full"):
            return "Finding deltas require complete reads; sampled or incomplete content cannot establish disappearance."
        if a is None and any(obj.status != "full" for obj in old.values()):
            return "The baseline has coverage gaps; these findings may have been present outside its inspected content."
        return None

    changes = []
    insufficient = {"partial", "inaccessible", "unsupported", "excluded", "failed"}
    for key in sorted(old.keys() | new.keys()):
        a, b = old.get(key), new.get(key)
        location = decrypt((b or a).location_encrypted)
        change, reason = "unchanged", "No change in comparable observations."
        if b is None:
            change, reason = "coverage_lost", "Previously observed object was not inventoried; absence does not establish removal."
        elif a and a.status == b.status and b.status in insufficient:
            change, reason = "not_comparable", "An inspection gap persists across both scans."
        elif b.status in insufficient or (a and a.status == "full" and b.status != "full") or (a and b.examined < a.examined and b.status != "full"):
            change, reason = "coverage_lost", "Current inspection is incomplete or has reduced coverage."
        elif detector_provenance_unknown:
            change, reason = "not_comparable", "Processing runtime identity was not recorded; run a new baseline."
        elif detector_changed or options_changed or (a and a.status in insufficient):
            change, reason = "not_comparable", "Detector, scan policy, or previous coverage differs."
        elif a is None:
            change, reason = "new", "Newly observed object; not necessarily newly created."
        else:
            af, bf = findings(a), findings(b)
            if af and not bf:
                if a.status == b.status == "full":
                    change, reason = "no_longer_observed", "Previously detected entities were not observed in this complete read; this is not proof of erasure."
                else:
                    change, reason = "not_comparable", "Sampled content cannot establish removal of a previous finding."
            elif af != bf or a.fingerprint != b.fingerprint:
                change, reason = "changed", "Content fingerprint or observed classifications changed."
        gap = finding_comparison(a, b)
        finding_deltas = [] if gap else deltas(findings(a) if a else Counter(), findings(b))
        comparison_reason = gap or ("Newly observed finding groups, not necessarily newly created data."
                                   if a is None else
                                   "Complete reads with matching detector and policy; counts are recognizer observations, not unique values or patients.")
        changes.append({"location": location, "change": change, "reason": reason,
                        "finding_comparison": "not_comparable" if gap else "comparable",
                        "finding_comparison_reason": comparison_reason,
                        "finding_deltas": finding_deltas})
    return {"baseline": baseline.id, "current": current.id, "detector_changed": detector_changed,
            "detector_provenance_unknown": detector_provenance_unknown,
            "options_changed": options_changed, "summary": dict(Counter(c["change"] for c in changes)),
            "finding_summary": dict(Counter(delta["change"] for item in changes for delta in item["finding_deltas"])),
            "finding_summary_unit": "finding_groups",
            "finding_count_unit": "recognizer_matches_not_unique_values_or_patients", "changes": changes}
