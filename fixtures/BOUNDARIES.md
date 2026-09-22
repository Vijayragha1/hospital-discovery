# Original synthetic boundary fixtures

The seven files in `boundaries/` contain fictional identifiers and clinical terms.
They exercise original-file extraction through the local detector and final
findings; they are not a hospital reference set or an accuracy benchmark.

- `independent-records.csv`: two scalar patient rows; both own-record links must survive.
- `nested-records.csv`: an outer identifier and two nested JSON records. One child
  has no identifier; the other has its own. Neither may inherit the outer ID.
- `malformed-nested.csv`: malformed structured content; retain PII and show partial
  coverage without inventing a patient association.
- `patient-header.txt`: a second patient's `Patient Name = ...` header separates
  that patient's clinical text from the preceding record's identifier. The file
  uses CR-only line endings; LF and CRLF are also covered by unit tests.
- `printed.png`: a printed synthetic scan. OCR retains identifiers and clinical
  content, but a frame alone does not prove patient-record layout.
- `embedded-scan.docx`: typed text and one embedded printed image. Both channels
  must reach detection; Office completeness remains unverified.
- `embedded-frames.docx`: typed text and one embedded two-frame TIFF. hOCR page
  markers must preserve distinct segments for the two known original frames.

Run `scripts/validate_boundary_fixtures.py --output /tmp/boundary-results.json`
inside an isolated test deployment with the local Tika and page/frame OCR
endpoints configured. The default mode uses packaged Presidio/spaCy. Its report
contains checks and coverage counts, not matching values or excerpts. The
fixture keys and expected values are synthetic; do not replace them with real
patient data in a distributable bundle.

hOCR boundaries prove observed segmentation for these fixtures. They do not
establish independent Office embedded-object inventory, OCR recognition accuracy
or general patient linkage in hospital documents.
