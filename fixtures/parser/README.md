# Synthetic parser fixtures

These generated fixtures contain only fictional test identifiers.

- `mixed.pdf`: searchable English text on page 1 and a printed image on page 2. Both must yield detections.
- `printed.png`: clear printed English identifiers and clinical text.
- `encrypted.pdf`: password-protected PDF; fixture password is `testpw`. Scanning without the password must report a coverage gap.
- `native-repeats.pdf`: the same synthetic MRN appears at two distinct positions. Reconciliation must preserve both source occurrences.
- `native-offpage.pdf`: a visible synthetic MRN and another native text operation outside the page canvas. Successful rendering or OCR must not imply that all native source content was examined.
- `native-invisible.pdf`: visible text plus a different synthetic MRN using invisible text rendering mode. OCR completion alone cannot establish coverage of invisible native content.
- `plain-image-only.pdf`: one visible raster image stored as lossless pixel data, with no native text operations. Exercises the image-only PDF path and its separate page, image-feature, and geometry checks.
- `blank-page.pdf`: one original page with an empty content stream. Its page ordinal must remain present; an empty successful OCR attempt is processing completion, not proof of legibility.

Native-bearing PDFs remain partial while complete native-source representation is unverified, even when extracted text and page OCR are available. These are functional checks, not a representative hospital accuracy set.
