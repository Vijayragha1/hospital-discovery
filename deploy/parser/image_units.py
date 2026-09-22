"""Isolated Pillow inventory/render stage. Only fixed JSON diagnostics leave it."""
import json
import math
from numbers import Real
from pathlib import Path
import sys
import warnings

FORMATS = {"PNG", "JPEG", "TIFF", "BMP"}


# Unknown fields/tags are treated as uninspected nonvisual content. Only simple
# format structure is exempt; no descriptive value is returned in the protocol.
STRUCTURAL_INFO = {"dpi", "resolution", "jfif", "jfif_version", "jfif_unit", "jfif_density", "adobe", "adobe_transform",
                   "progressive", "progression", "gamma", "duration", "loop", "default_image", "disposal", "blend", "bbox"}
STRUCTURAL_TIFF_TAGS = {254, 255, 256, 257, 258, 259, 262, 263, 264, 265, 266, 273, 274, 277, 278, 279,
                        280, 281, 282, 283, 284, 286, 287, 288, 289, 290, 291, 292, 293, 296, 297, 301,
                        317, 318, 319, 320, 321, 322, 323, 324, 325, 338, 339, 340, 341, 342, 347,
                        512, 513, 514, 515, 517, 518, 519, 520, 521, 522, 529, 530, 531, 532}
COMPRESSION_NAMES = {"raw", "packbits", "tiff_lzw", "tiff_adobe_deflate", "tiff_deflate", "jpeg", "group3", "group4", "tiff_ccitt"}


def _numeric(value):
    if isinstance(value, (tuple, list)):
        return len(value) <= 16 and all(_numeric(item) for item in value)
    return isinstance(value, Real) and math.isfinite(value)


def nonvisual_content(image):
    try:
        for key, value in image.info.items():
            if key == "compression" and value in COMPRESSION_NAMES:
                continue
            if key == "transparency" and (isinstance(value, bytes) and len(value) <= 256 or _numeric(value)):
                continue
            if key not in STRUCTURAL_INFO or not _numeric(value):
                return True
        if image.format == "TIFF":
            return any(tag not in STRUCTURAL_TIFF_TAGS for tag in image.tag_v2)
        return bool(image.getexif())
    except Exception:
        return True


def process(operation, filename, output, ordinal, max_pixels):
    try:
        from PIL import Image, ImageOps
    except ImportError:
        return {"ok": False, "reason": "image_dependency_unavailable"}
    Image.MAX_IMAGE_PIXELS = max_pixels
    warnings.simplefilter("error", Image.DecompressionBombWarning)
    try:
        with Image.open(filename, formats=sorted(FORMATS)) as image:
            original_format = image.format
            if original_format not in FORMATS:
                return {"ok": False, "reason": "unsupported_image_format"}
            count = image.n_frames if hasattr(image, "n_frames") else 1
            if not isinstance(count, int) or count < 1:
                return {"ok": False, "reason": "image_inventory_failed"}
            if operation == "inventory":
                return {"ok": True, "original_format": original_format, "unit_count": count,
                        "nonvisual_content_present": nonvisual_content(image)}
            if operation != "render" or not 1 <= ordinal <= count:
                return {"ok": False, "reason": "image_frame_unavailable"}
            image.seek(ordinal - 1)
            width, height = image.size
            if width < 1 or height < 1 or width * height > max_pixels:
                return {"ok": False, "reason": "pixel_limit"}
            image.load()
            metadata_present = nonvisual_content(image)
            # TiffImagePlugin.load_end already applies the frame orientation.
            # Re-running exif_transpose both risks a second rotation and asks
            # Pillow 9 to reload EXIF from a frame fp that load() has closed.
            oriented = image.copy() if original_format == "TIFF" else ImageOps.exif_transpose(image)
            if "A" in oriented.getbands() or "transparency" in oriented.info:
                rgba = oriented.convert("RGBA")
                background = Image.new("RGBA", rgba.size, "white")
                rendered = Image.alpha_composite(background, rgba).convert("RGB")
            else:
                rendered = oriented.convert("RGB")
            width, height = rendered.size
            if width * height > max_pixels:
                return {"ok": False, "reason": "pixel_limit"}
            rendered.save(output, format="PNG")
            return {"ok": True, "original_format": original_format, "pixel_width": width, "pixel_height": height,
                    "nonvisual_content_present": metadata_present}
    except (Image.DecompressionBombWarning, Image.DecompressionBombError):
        return {"ok": False, "reason": "pixel_limit"}
    except Exception:
        return {"ok": False, "reason": "image_inventory_failed" if operation == "inventory" else "image_render_failed"}


def main():
    try:
        operation, filename, output = sys.argv[1:4]
        ordinal, pixels = int(sys.argv[4]), int(sys.argv[5])
        if not 1 <= pixels <= 20_000_000 or not 0 <= ordinal <= 100:
            raise ValueError
        result = process(operation, filename, output, ordinal, pixels)
    except Exception:
        result = {"ok": False, "reason": "image_stage_failed"}
    sys.stdout.write(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
