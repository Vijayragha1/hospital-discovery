"""Rebuild fictional original PDF fixtures; never use extractor output as gold.

Requires Pillow and reportlab. A 720x432 point page rendered at the parser's
200 dpi is exactly 2000x1200 pixels. The raster PDFs contain raw RGB Flate images
without an image metadata container, making ancillary-content checks explicit.
"""
from pathlib import Path
import zlib

from PIL import Image, ImageSequence
from reportlab.pdfgen import canvas


HERE = Path(__file__).resolve().parent
WIDTH, HEIGHT = 2000, 1200
PAGE_WIDTH, PAGE_HEIGHT = 720, 432


def raster_pdf(path, frames):
    # Small deterministic PDF writer avoids introducing hidden text or source
    # PNG/TIFF metadata. These fixtures exercise original image-only PDF pages.
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b""]
    pages = []
    for frame in frames:
        frame = frame.convert("RGB")
        assert frame.size == (WIDTH, HEIGHT)
        page, content, image = len(objects) + 1, len(objects) + 2, len(objects) + 3
        pages.append(page)
        objects.append((f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 720 432] "
            f"/Resources << /XObject << /Im0 {image} 0 R >> >> /Contents {content} 0 R >>").encode())
        commands = b"q\n720 0 0 432 0 0 cm\n/Im0 Do\nQ\n"
        objects.append(f"<< /Length {len(commands)} >>\nstream\n".encode() + commands + b"endstream")
        pixels = zlib.compress(frame.tobytes(), 9)
        objects.append((f"<< /Type /XObject /Subtype /Image /Width {WIDTH} /Height {HEIGHT} "
            f"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length {len(pixels)} >>\nstream\n").encode()
            + pixels + b"\nendstream")
    objects[1] = ("<< /Type /Pages /Count " + str(len(pages)) + " /Kids [" +
                  " ".join(f"{page} 0 R" for page in pages) + "] >>").encode()
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode() + obj + b"\nendobj\n")
    offset = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for value in offsets[1:]:
        output.extend(f"{value:010d} 00000 n \n".encode())
    output.extend((f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
                   f"startxref\n{offset}\n%%EOF\n").encode())
    path.write_bytes(output)


def main():
    pdf = canvas.Canvas(str(HERE / "two-columns-native.pdf"), pagesize=(PAGE_WIDTH, PAGE_HEIGHT),
                        invariant=1, pageCompression=0)
    pdf.setFont("Helvetica", 14.4)
    for left, lines in [(100, ["UHID: FX100001", "Diagnosis: diabetes", "Treatment: insulin"]),
                        (1100, ["UHID: FX200002", "Diagnosis: asthma", "Treatment: inhaler"])]:
        for row, line in enumerate(lines):
            # Baselines are defined from the source canvas, before extraction.
            pdf.drawString(left * .36, PAGE_HEIGHT - (160 + row * 70) * .36, line)
    pdf.showPage()
    pdf.save()
    pdf = canvas.Canvas(str(HERE / "single-record-native.pdf"), pagesize=(PAGE_WIDTH, PAGE_HEIGHT),
                        invariant=1, pageCompression=0)
    pdf.setFont("Helvetica", 14.4)
    for row, line in enumerate(["UHID: FX100001", "Diagnosis: diabetes", "Treatment: insulin"]):
        pdf.drawString(36, PAGE_HEIGHT - (160 + row * 70) * .36, line)
    pdf.showPage()
    pdf.save()
    pdf = canvas.Canvas(str(HERE / "two-columns-repeated-native.pdf"), pagesize=(PAGE_WIDTH, PAGE_HEIGHT),
                        invariant=1, pageCompression=0)
    pdf.setFont("Helvetica", 14.4)
    for left, lines in [(100, ["UHID: FX100001", "Diagnosis: diabetes", "Treatment: insulin"]),
                        (1100, ["UHID: FX100001", "Diagnosis: asthma", "Treatment: inhaler"])]:
        for row, line in enumerate(lines):
            pdf.drawString(left * .36, PAGE_HEIGHT - (160 + row * 70) * .36, line)
    pdf.showPage()
    pdf.save()
    with Image.open(HERE / "two-columns.png") as image:
        raster_pdf(HERE / "two-columns-raster.pdf", [image])
    with Image.open(HERE / "two-frames.tif") as image:
        raster_pdf(HERE / "two-pages-raster.pdf", [frame.copy() for frame in ImageSequence.Iterator(image)])


if __name__ == "__main__":
    main()
