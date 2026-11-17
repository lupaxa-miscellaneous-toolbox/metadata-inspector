"""Decode photographs with limits that reject decompression bombs."""

from __future__ import annotations

import io
from typing import cast

from PIL import Image

MAX_DIMENSION = 20000
MAX_PIXELS = 40_000_000


class ImageSafetyError(ValueError):
    """The image is too large or cannot be decoded."""


def decode_image(data: bytes) -> Image.Image:
    """Decode an image and enforce dimension and pixel limits."""
    previous = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    try:
        with Image.open(io.BytesIO(data)) as image:
            width, height = image.size
            if width > MAX_DIMENSION or height > MAX_DIMENSION or width * height > MAX_PIXELS:
                raise ImageSafetyError("image dimensions exceed the safety limit")
            image.load()
            return cast(Image.Image, image.copy())
    except ImageSafetyError:
        raise
    except Exception as exc:
        raise ImageSafetyError("image could not be decoded") from exc
    finally:
        Image.MAX_IMAGE_PIXELS = previous


def image_bytes(image: Image.Image, image_format: str, *, quality: int = 95) -> bytes:
    """Encode an image after an explicitly requested pixel transform."""
    buffer = io.BytesIO()
    save_format = {"jpeg": "JPEG", "png": "PNG", "webp": "WEBP", "tiff": "TIFF"}.get(image_format)
    if save_format is None:
        raise ImageSafetyError(f"{image_format} cannot be re-encoded")
    options: dict[str, object] = {}
    if save_format in {"JPEG", "WEBP"}:
        options["quality"] = quality
    image.save(buffer, format=save_format, **options)
    return buffer.getvalue()
