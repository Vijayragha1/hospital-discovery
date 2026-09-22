# Synthetic layout fixtures

All identifiers and clinical text are fictional. These original PNG/TIFF/PDF files
exercise geometry transport and automatic record segmentation; they are not a
hospital reference set or acceptance evidence.

- `single-record.png`: one labelled identifier and clinical block.
- `two-columns.png`: two independent labelled records, side by side.
- `two-rows.png`: two independent labelled records, stacked vertically.
- `unlabelled-neighbour.png`: left identifier and unrelated right clinical block;
  spatial proximity must not be treated as patient linkage.
- `two-frames.tif`: one separate record on each original frame.
- `two-columns-native.pdf`: independently typeset native-text counterpart of
  the two-column source. Native/OCR reconciliation must preserve both original
  records and exact patient associations. PDF coverage remains partial.
- `single-record-native.pdf`: one native-text record on one original page,
  exercising the supported whole-line reconciliation path. Correct visible
  record mapping still does not establish complete PDF coverage.
- `two-columns-repeated-native.pdf`: the same identifier appears in two
  independent original column records with different clinical text. Both
  original occurrences and both record associations must survive reconciliation.
- `two-columns-raster.pdf`: the original two-column RGB pixels on one PDF page.
- `two-pages-raster.pdf`: the two TIFF frames on separate original PDF pages.

Each canvas is 2000 by 1200 pixels, using 40px Arial at 70px line spacing.
Left column origin is (100,120), right column origin is (1100,120), and the
second stacked record begins at (100,650). These positions describe source
construction; OCR boxes must be verified from original-byte processing.

The PDFs have 720 by 432 point pages, yielding 2000 by 1200 pixels at the
parser's 200 dpi. `generate_pdf_fixtures.py` rebuilds them deterministically
using Pillow and reportlab. Raster PDFs use raw RGB Flate images without hidden
text or embedded PNG/TIFF metadata; native text uses 14.4pt Helvetica.

`reference.json` contains private synthetic v3 gold bound to original byte
hashes and original unit dimensions. Record rectangles are canvas halves for
columns/rows, or whole original frames/pages. The unlabelled neighbour has an
independent clinical-negative left half and an unlinked clinical right half.
Gold does not use algorithm region IDs, OCR word boxes or segmentation output.

With private `PAGE_OCR_URL` and `TIKA_URL` available, run in the API image:

```sh
python /app/fixtures/layout/verify_gateway.py --mode rules --output /tmp/layout-result.json
```

`--mode presidio` loads the production NLP detector once for all fixtures.
The runner uses the real `_file_result` scanner and private evaluator collectors,
then reconciles observations against final findings. It selects only the ten
gold objects; it does not validate directory inventory. Required checks cover
exact UHID occurrences, clinical records, patient-reference associations,
mapping, expected coverage and no retained values/geometry. Other NLP PII
predictions remain visible as occurrence false positives. Result JSON contains
counts and fixed codes, never reference values, source excerpts or word boxes.

`bounded_gateway_checks_passed` requires every object to pass the same exact
occurrence, clinical-record and patient-reference checks with complete mapping.
There are no named fixture exceptions. Every observed false positive or missed
association remains visible in the raw counts and fails the bounded check.
`all_exact_accuracy_checks_passed` summarizes these synthetic checks; it does
not establish hospital accuracy or complete PDF coverage.

These ten calibration objects provide neither the required sample sizes nor
hospital-held-out evidence. Acceptance is always false. Native PDF coverage is
explicitly partial, independently of successful visible association checks.
