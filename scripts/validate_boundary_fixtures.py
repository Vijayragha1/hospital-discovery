#!/usr/bin/env python3
"""Original synthetic files through extraction, local detection and final findings.

Requires the isolated Tika and page/frame endpoints. No patient values, original
text, paths, evidence excerpts or private association events enter the report.
"""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, os.getenv('DISCOVERY_BACKEND_PATH', str(Path(__file__).resolve().parents[1] / 'backend')))
from app.detection import Detector
from app.scanning import scan_source


def validate(fixtures, mode):
    events = []

    def observe(event):
        if event['event'] == 'clinical':
            events.append(event)

    detector = Detector(mode, _association_sink=observe)
    rows = list(scan_source('filesystem', {'root': str(fixtures.resolve())},
                           {'capture_evidence': True}, detector, lambda: 'running'))
    by_name = {row['location']: row for row in rows}
    checks = {'all_seven_original_objects_accounted': len(rows) == len(by_name) == 7}

    def findings(name, kind=None):
        return [f for f in by_name[name]['findings'] if kind is None or f['entity_type'] == kind]

    def values(name, kind):
        return {example['value'] for f in findings(name, kind) for example in f.get('evidence', [])}

    def anchors(name):
        return [anchor for event in events if event['location'] == name for anchor in event['anchors']]

    nested = 'nested-records.csv'
    checks['nested_csv_inner_reference_kept'] = ('MRN', 'INNER456') in anchors(nested)
    checks['nested_csv_outer_reference_not_inherited'] = all(value != 'OUTER123' for _, value in anchors(nested))
    checks['nested_csv_orphan_clinical_record_retained'] = any(f['classification'] == 'clinical_content' for f in findings(nested, 'HEALTH_INFORMATION'))
    checks['nested_csv_pii_preserved'] = {'OUTER123', 'INNER456'} <= values(nested, 'MRN')
    checks['independent_csv_positive_links_preserved'] = {('MRN', 'FIRST123'), ('MRN', 'SECOND456')} <= set(anchors('independent-records.csv'))
    checks['equals_patient_header_does_not_inherit_prior_id'] = all(value != 'OUTER123' for _, value in anchors('patient-header.txt'))
    checks['equals_header_pii_and_clinical_content_retained'] = bool(findings('patient-header.txt', 'MRN')) and bool(findings('patient-header.txt', 'HEALTH_INFORMATION'))
    id_examples = [e for f in findings('patient-header.txt', 'MRN') for e in f.get('evidence', [])]
    clinical_examples = [e for f in findings('patient-header.txt', 'HEALTH_INFORMATION') for e in f.get('evidence', [])]
    checks['equals_header_evidence_stays_in_own_record'] = (bool(id_examples and clinical_examples)
        and all('Suresh Kumar' not in e['excerpt'] and 'diabetes' not in e['excerpt'] for e in id_examples)
        and all('OUTER123' not in e['excerpt'] for e in clinical_examples))
    malformed = by_name['malformed-nested.csv']
    checks['malformed_structured_cell_is_visible_gap'] = malformed['status'] == 'partial'
    checks['malformed_structured_cell_cannot_link'] = not anchors('malformed-nested.csv')
    checks['malformed_structured_cell_pii_preserved'] = 'OUTER123' in values('malformed-nested.csv', 'MRN')
    checks['malformed_structured_cell_clinical_content_preserved'] = bool(findings('malformed-nested.csv', 'HEALTH_INFORMATION'))

    for name in ('embedded-scan.docx', 'embedded-frames.docx'):
        checks[name + '_typed_identifier_detected'] = 'DOCX12345' in values(name, 'MRN')
        checks[name + '_partial_not_false_complete'] = by_name[name]['status'] == 'partial'
        checks[name + '_unverified_layout_not_linked'] = not anchors(name)
    checks['docx_embedded_scan_identifier_detected'] = 'OCR-45678' in values('embedded-scan.docx', 'UHID')
    checks['docx_both_embedded_frames_detected'] = ('FRAME12345' in values('embedded-frames.docx', 'MRN')
        and 'FRAME67890' in values('embedded-frames.docx', 'UHID'))
    frame_one = {f['segment'] for f in findings('embedded-frames.docx', 'MRN')
                 if any(e['value'] == 'FRAME12345' for e in f.get('evidence', []))}
    frame_two = {f['segment'] for f in findings('embedded-frames.docx', 'UHID')
                 if any(e['value'] == 'FRAME67890' for e in f.get('evidence', []))}
    checks['embedded_original_frames_have_distinct_segments'] = bool(frame_one and frame_two and frame_one.isdisjoint(frame_two))
    checks['embedded_hocr_page_markers_observed'] = by_name['embedded-frames.docx']['metadata'].get('observed_page_boundaries', 0) >= 2
    checks['raster_pii_and_clinical_content_retained'] = bool(findings('printed.png', 'UHID')) and bool(findings('printed.png', 'HEALTH_INFORMATION'))
    checks['raster_unknown_patient_layout_not_linked'] = not anchors('printed.png')
    checks['raster_layout_limit_recorded'] = by_name['printed.png']['metadata'].get('patient_linkage_context_verified') is False
    report = {'synthetic': True, 'hospital_validated': False, 'detector_mode': mode,
              'detector_version': detector.version, 'checks': checks, 'all_passed': all(checks.values()),
              'coverage_counts': {status: sum(row['status'] == status for row in rows) for status in sorted({row['status'] for row in rows})},
              'notice': 'Original synthetic file checks, not hospital accuracy acceptance. hOCR markers preserve observed embedded frame boundaries but do not prove independent Office inventory or arbitrary patient layout.'}
    serialized = json.dumps(report)
    assert all(value not in serialized for value in ('OUTER123', 'INNER456', 'FIRST123', 'SECOND456', 'Suresh Kumar',
        'DOCX12345', 'OCR-45678', 'FRAME12345', 'FRAME67890'))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', type=Path, default=Path(__file__).resolve().parents[1] / 'fixtures/boundaries')
    parser.add_argument('--mode', choices=('rules', 'presidio'), default='presidio')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = validate(args.fixtures, args.mode)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 0 if report['all_passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
