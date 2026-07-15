"""Local-only image metadata and forensic signal extraction for Cros."""

from __future__ import annotations

import base64
import hashlib
import io
import mimetypes
import sys
from pathlib import Path


APP_DIR = Path(__file__).resolve().parent
ENGINE_DEPS_DIR = APP_DIR / "engine_deps"
MAX_IMAGE_BYTES = 50 * 1024 * 1024
MAX_IMAGE_PIXELS = 100_000_000


def _safe_text(value: object, limit: int = 260) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    text = str(value).replace("\x00", "").strip()
    return text[:limit]


def _ratio(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        numerator = float(getattr(value, "numerator", 0))
        denominator = float(getattr(value, "denominator", 1))
        return numerator / denominator if denominator else 0.0


def _gps_coordinates(exif: object, exif_tags: object) -> tuple[float, float] | None:
    gps_raw = None
    try:
        if hasattr(exif, "get_ifd") and hasattr(exif_tags, "IFD"):
            gps_raw = exif.get_ifd(exif_tags.IFD.GPSInfo)
    except (AttributeError, KeyError, TypeError, ValueError):
        gps_raw = None
    if not gps_raw:
        try:
            gps_key = next(key for key, name in exif_tags.TAGS.items() if name == "GPSInfo")
            gps_raw = exif.get(gps_key)
        except (AttributeError, KeyError, StopIteration, TypeError):
            return None
    if not hasattr(gps_raw, "items"):
        return None
    gps = {exif_tags.GPSTAGS.get(key, str(key)): value for key, value in gps_raw.items()}
    latitude = gps.get("GPSLatitude")
    longitude = gps.get("GPSLongitude")
    if not latitude or not longitude or len(latitude) < 3 or len(longitude) < 3:
        return None
    lat = _ratio(latitude[0]) + _ratio(latitude[1]) / 60 + _ratio(latitude[2]) / 3600
    lon = _ratio(longitude[0]) + _ratio(longitude[1]) / 60 + _ratio(longitude[2]) / 3600
    if _safe_text(gps.get("GPSLatitudeRef", "")).upper() == "S":
        lat = -lat
    if _safe_text(gps.get("GPSLongitudeRef", "")).upper() == "W":
        lon = -lon
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    return lat, lon


def _average_hash(grayscale: object) -> str:
    pixels = list(grayscale.resize((8, 8)).getdata())
    average = sum(pixels) / len(pixels)
    bits = "".join("1" if pixel >= average else "0" for pixel in pixels)
    return f"{int(bits, 2):016x}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyze_image_file(path_value: str | Path, *, include_thumbnail: bool = False) -> dict:
    """Analyze an image without uploading, identifying, or executing it."""
    path = Path(path_value).expanduser().resolve()
    if not path.is_file():
        raise ValueError("The selected image no longer exists.")
    size = path.stat().st_size
    if size <= 0:
        raise ValueError("The selected image is empty.")
    if size > MAX_IMAGE_BYTES:
        raise ValueError("Choose an image smaller than 50 MB.")

    if str(ENGINE_DEPS_DIR) not in sys.path:
        sys.path.insert(0, str(ENGINE_DEPS_DIR))
    try:
        from PIL import ExifTags, Image, ImageFilter, ImageOps, ImageStat
    except ImportError as exc:
        raise RuntimeError("Local image support is unavailable.") from exc

    digest = _sha256(path)
    metadata: list[dict[str, str]] = []
    with Image.open(path) as opened:
        width, height = opened.size
        if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS:
            raise ValueError("The image dimensions are invalid or too large to inspect safely.")
        image_format = opened.format or "Unknown"
        mode = opened.mode
        frames = int(getattr(opened, "n_frames", 1) or 1)
        animated = bool(getattr(opened, "is_animated", False) or frames > 1)
        exif = opened.getexif()
        named = {ExifTags.TAGS.get(key, str(key)): value for key, value in exif.items()}
        useful_labels = (
            "Make", "Model", "LensModel", "Software", "DateTimeOriginal", "DateTimeDigitized",
            "DateTime", "Artist", "Copyright", "ImageDescription", "Orientation",
        )
        for label in useful_labels:
            value = named.get(label)
            if value not in (None, ""):
                metadata.append({"label": label, "value": _safe_text(value)})
        gps = _gps_coordinates(exif, ExifTags)

        opened.seek(0)
        working = ImageOps.exif_transpose(opened).convert("RGB")
        sample = working.copy()
        sample.thumbnail((512, 512))
        grayscale = sample.convert("L")
        stats = ImageStat.Stat(grayscale)
        brightness = round(float(stats.mean[0]), 1)
        contrast = round(float(stats.stddev[0]), 1)
        entropy = round(float(grayscale.entropy()), 2)
        edge_strength = round(float(ImageStat.Stat(grayscale.filter(ImageFilter.FIND_EDGES)).mean[0]), 1)
        average_hash = _average_hash(grayscale)

        face_boxes: list[dict[str, float]] = []
        face_engine = "unavailable"
        try:
            import cv2
            import numpy as np
            detector = cv2.CascadeClassifier(str(Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml"))
            detection = cv2.cvtColor(np.asarray(sample), cv2.COLOR_RGB2GRAY)
            found = detector.detectMultiScale(detection, scaleFactor=1.1, minNeighbors=5, minSize=(28, 28))
            sample_width, sample_height = sample.size
            for x, y, box_width, box_height in found[:40]:
                face_boxes.append({
                    "x": round(float(x) / sample_width, 5),
                    "y": round(float(y) / sample_height, 5),
                    "width": round(float(box_width) / sample_width, 5),
                    "height": round(float(box_height) / sample_height, 5),
                })
            face_engine = "local-opencv"
        except (ImportError, AttributeError, OSError, ValueError):
            face_boxes = []

        thumbnail = ""
        if include_thumbnail:
            preview = working.copy()
            preview.thumbnail((960, 720))
            buffer = io.BytesIO()
            preview.save(buffer, format="JPEG", quality=84, optimize=True)
            thumbnail = "data:image/jpeg;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")

    metadata_text = " ".join(item["value"] for item in metadata).lower()
    creator_terms = (
        "photoshop", "lightroom", "gimp", "canva", "stable diffusion", "midjourney",
        "dall-e", "firefly", "comfyui", "automatic1111", "flux",
    )
    creator_hits = sorted({term for term in creator_terms if term in metadata_text})
    if creator_hits:
        generator_note = (
            "Metadata mentions " + ", ".join(creator_hits)
            + ". That may describe editing or generation software, but it does not prove how the image was created."
        )
    elif metadata:
        generator_note = "Metadata is present, but it contains no recognized generator label. That does not prove the image is camera-original."
    else:
        generator_note = "No useful creator metadata was found. Missing metadata is common after screenshots, messaging, and social-media processing."

    return {
        "file_name": path.name,
        "size_bytes": size,
        "mime": mimetypes.guess_type(path.name)[0] or "Unknown",
        "format": image_format,
        "width": width,
        "height": height,
        "megapixels": round(width * height / 1_000_000, 2),
        "mode": mode,
        "frames": frames,
        "animated": animated,
        "sha256": digest,
        "average_hash": average_hash,
        "brightness": brightness,
        "contrast": contrast,
        "entropy": entropy,
        "edge_strength": edge_strength,
        "metadata": metadata,
        "gps": {"latitude": round(gps[0], 6), "longitude": round(gps[1], 6)} if gps else None,
        "location_note": (
            "Embedded GPS was found. Confirm it against visible landmarks before treating it as reliable."
            if gps else
            "No embedded GPS was found. Location requires reverse-image results and visible scene clues."
        ),
        "generator_note": generator_note,
        "ai_note": "No local detector can reliably prove that an image is AI-generated. Use metadata, source history, reverse search, and visual inconsistencies together.",
        "face_note": "Face detection only counts possible face regions. It does not identify a person or search private biometric databases.",
        "face_count": len(face_boxes),
        "face_boxes": face_boxes,
        "face_engine": face_engine,
        "thumbnail": thumbnail,
    }
