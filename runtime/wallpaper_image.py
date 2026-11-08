"""Prepare the receiver no-signal JPEG locally, preserving aspect ratio.

The vendor filename is fpv_new_bg_1920x1080.jpg. This module only measures,
plans a centered crop and generates a Windows image conversion command.
It does not communicate with a receiver or apply an image.
"""
from __future__ import annotations

import caddx_tile_image as tile

#: The goggles' target. Fixed by the vendor tool's filename and the display.
TARGET_W = 1920
TARGET_H = 1080
TARGET_ASPECT = TARGET_W / TARGET_H

#: Where the vendor tool reads it from, and the exact name it looks for. The SD
#: card mounts at /usrdata/record; the name is not negotiable.
REMOTE_DIR = "/usrdata/record"
REMOTE_NAME = "fpv_new_bg_1920x1080.jpg"
REMOTE_PATH = REMOTE_DIR + "/" + REMOTE_NAME

#: Below this the source is treated as already 16:9 and is resized straight to
#: target with no crop -- the deviation is sub-pixel and imperceptible. A 2134x1200
#: source (1.7783 vs 1.77778) is within this and needs no crop.
ASPECT_TOLERANCE = 0.01


class WallpaperError(ValueError):
    def __init__(self, code: str, message: str, evidence: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.evidence = evidence or {}


def measure(data: bytes) -> dict:
    """Container and pixel size from the bytes. Raises WallpaperError."""
    try:
        s = tile.sniff(data)
    except tile.TileImageError as e:
        raise WallpaperError("IMAGE_UNREADABLE",
                             "this file is not a readable PNG or JPEG", {"detail": str(e)})
    return {"format": s["format"], "width": s["width"], "height": s["height"]}


def plan_fit(width: int, height: int) -> dict:
    """How to get a WxH source to exactly 1920x1080 without distorting it.

    Returns the decision only; the pixels are moved by the PowerShell step. When a
    crop is needed it is CENTERED and the box is reported so the operator can see
    what will be lost, and `needs_review` is set so the UI stops for a look.
    """
    if width <= 0 or height <= 0:
        raise WallpaperError("IMAGE_BAD_DIMENSIONS",
                             "the image reports a non-positive dimension",
                             {"width": width, "height": height})
    aspect = width / height
    if abs(aspect - TARGET_ASPECT) <= ASPECT_TOLERANCE:
        return {"mode": "resize", "needs_review": False,
                "source": {"width": width, "height": height, "aspect": round(aspect, 4)},
                "crop": None, "target": {"width": TARGET_W, "height": TARGET_H},
                "note": "Already 16:9 within tolerance, so it is resized with no crop."}
    # Center-crop to 16:9, then resize. Never stretch.
    if aspect > TARGET_ASPECT:
        # Too wide: trim left/right.
        crop_w = round(height * TARGET_ASPECT)
        crop_h = height
        x = (width - crop_w) // 2
        y = 0
        lost = "the left and right edges"
    else:
        # Too tall: trim top/bottom.
        crop_w = width
        crop_h = round(width / TARGET_ASPECT)
        x = 0
        y = (height - crop_h) // 2
        lost = "the top and bottom"
    return {"mode": "crop", "needs_review": True,
            "source": {"width": width, "height": height, "aspect": round(aspect, 4)},
            "crop": {"x": x, "y": y, "width": crop_w, "height": crop_h},
            "target": {"width": TARGET_W, "height": TARGET_H},
            "note": f"Not 16:9, so {lost} are cropped (centered) before resizing. "
                    f"Review the result before deploying."}


def resize_powershell(src_path: str, dst_path: str, plan: dict) -> str:
    """A PowerShell program that produces the 1920x1080 JPEG via System.Drawing.

    Built here as one string so it can be asserted on. It crops (if the plan says
    so) and resizes with high-quality interpolation, then saves JPEG at q92. It
    never changes aspect: a crop plan removes pixels, it does not stretch.
    """
    src_path = str(src_path).replace("'", "''")
    dst_path = str(dst_path).replace("'", "''")
    c = plan.get("crop")
    # The source rectangle copied onto the 1920x1080 canvas: the crop box when
    # cropping, or the whole image when resizing. DrawImage maps src-rect ->
    # full dst, so aspect is preserved by construction (the src-rect is 16:9).
    if c:
        sx, sy, sw, sh = c["x"], c["y"], c["width"], c["height"]
    else:
        sx, sy, sw, sh = 0, 0, "$src.Width", "$src.Height"
    return (
        "$ErrorActionPreference='Stop';"
        "Add-Type -AssemblyName System.Drawing;"
        f"$src=[System.Drawing.Image]::FromFile('{src_path}');"
        "try{"
        f"$dst=New-Object System.Drawing.Bitmap({TARGET_W},{TARGET_H});"
        "try{"
        "$g=[System.Drawing.Graphics]::FromImage($dst);"
        "try{"
        "$g.InterpolationMode=[System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic;"
        "$g.PixelOffsetMode=[System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality;"
        f"$sr=New-Object System.Drawing.Rectangle(0,0,{TARGET_W},{TARGET_H});"
        f"$g.DrawImage($src,$sr,[int]({sx}),[int]({sy}),[int]({sw}),[int]({sh}),"
        "[System.Drawing.GraphicsUnit]::Pixel);"
        "}finally{$g.Dispose()}"
        "$enc=[System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|"
        "Where-Object{$_.MimeType -eq 'image/jpeg'};"
        "$p=New-Object System.Drawing.Imaging.EncoderParameters(1);"
        "$p.Param[0]=New-Object System.Drawing.Imaging.EncoderParameter("
        "[System.Drawing.Imaging.Encoder]::Quality,[int64]92);"
        f"$dst.Save('{dst_path}',$enc,$p);"
        "}finally{$dst.Dispose()}"
        "}finally{$src.Dispose()}"
        f"Write-Output '{TARGET_W}x{TARGET_H}'"
    )
