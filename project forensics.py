# ================================
# Digital Image Metadata & Geolocation Analysis Tool
# File: main.py
#
# Requirements:
#   pip install exifread
#
# Usage:
#   python main.py                             process ./sample_images/
#   python main.py -f C:\path\to\images       custom folder
#   python main.py -f C:\path -o report.json  custom folder + output file
#   python main.py -f C:\path --no-save       print only, no JSON file
# ================================

import os
import sys
import json
import argparse
from datetime import datetime

import exifread

# Fix Windows terminal encoding so all characters print correctly
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ================================
# Configuration
# ================================

SUPPORTED_EXTENSIONS = (".jpg", ".jpeg", ".png", ".tiff", ".tif", ".heic")

SUSPICIOUS_SOFTWARE = [
    "Photoshop",
    "Snapseed",
    "Lightroom",
    "Canva",
    "GIMP",
    "Affinity Photo",
    "PicsArt",
    "VSCO",
]

DEFAULT_FOLDER = "sample_images"
DEFAULT_OUTPUT = "forensics_report.json"
DATE_FORMAT    = "%Y:%m:%d %H:%M:%S"

DIVIDER = "-" * 50


# ================================
# EXIF Extraction
# ================================

def get_exif_data(image_path: str) -> dict | None:
    """
    Opens an image and reads its raw EXIF tags.
    Returns a non-empty tag dict, or None on any failure.
    """
    try:
        with open(image_path, "rb") as f:
            tags = exifread.process_file(f, details=False, strict=False)
        return tags if tags else None
    except OSError as e:
        _warn(f"Could not open '{image_path}': {e}")
        return None
    except Exception as e:
        _warn(f"Unexpected error reading '{image_path}': {e}")
        return None


# ================================
# GPS Helpers
# ================================

def _ratio_to_float(ratio) -> float:
    """Converts an exifread IFD Ratio to float, guarding against zero denominator."""
    try:
        den = float(ratio.den)
        return float(ratio.num) / den if den != 0.0 else 0.0
    except (AttributeError, TypeError, ZeroDivisionError):
        return 0.0


def _dms_to_decimal(value) -> float | None:
    """
    Converts a GPS tag stored as (degrees, minutes, seconds) rationals
    into a single decimal-degree float.
    """
    try:
        d = _ratio_to_float(value.values[0])
        m = _ratio_to_float(value.values[1])
        s = _ratio_to_float(value.values[2])
        return d + (m / 60.0) + (s / 3600.0)
    except (TypeError, IndexError, AttributeError):
        return None


def extract_gps(tags: dict) -> tuple[float | None, float | None]:
    """
    Returns (latitude, longitude) in signed decimal degrees, or (None, None)
    if GPS data is missing or cannot be parsed.

    Sign conventions:
      Latitude  -- positive = North, negative = South
      Longitude -- positive = East,  negative = West
    """
    lat_tag = tags.get("GPS GPSLatitude")
    lat_ref = tags.get("GPS GPSLatitudeRef")
    lon_tag = tags.get("GPS GPSLongitude")
    lon_ref = tags.get("GPS GPSLongitudeRef")

    if not all([lat_tag, lat_ref, lon_tag, lon_ref]):
        return None, None

    lat = _dms_to_decimal(lat_tag)
    lon = _dms_to_decimal(lon_tag)

    if lat is None or lon is None:
        return None, None

    if str(lat_ref).strip().upper() == "S":
        lat = -lat

    if str(lon_ref).strip().upper() == "W":
        lon = -lon

    return lat, lon


# ================================
# Metadata Extraction
# ================================

def _tag_str(tags: dict, key: str) -> str | None:
    """Returns the string value of an EXIF tag, or None if absent."""
    val = tags.get(key)
    return str(val).strip() if val else None


def extract_metadata(image_path: str) -> dict:
    """
    Extracts forensic metadata from one image file.
    Always returns a dict containing at least 'filename' and 'status'.
    """
    filename = os.path.basename(image_path)

    if not os.path.isfile(image_path):
        return {"filename": filename, "status": "Error: not a regular file"}

    tags = get_exif_data(image_path)

    if not tags:
        return {"filename": filename, "status": "No EXIF metadata found"}

    latitude, longitude = extract_gps(tags)

    return {
        "filename":      filename,
        "status":        "Success",
        "date_taken":    _tag_str(tags, "EXIF DateTimeOriginal"),
        "camera_make":   _tag_str(tags, "Image Make"),
        "camera_model":  _tag_str(tags, "Image Model"),
        "software":      _tag_str(tags, "Image Software"),
        "image_width":   _tag_str(tags, "EXIF ExifImageWidth")  or _tag_str(tags, "Image ImageWidth"),
        "image_height":  _tag_str(tags, "EXIF ExifImageLength") or _tag_str(tags, "Image ImageLength"),
        "flash":         _tag_str(tags, "EXIF Flash"),
        "focal_length":  _tag_str(tags, "EXIF FocalLength"),
        "iso":           _tag_str(tags, "EXIF ISOSpeedRatings"),
        "exposure_time": _tag_str(tags, "EXIF ExposureTime"),
        "f_number":      _tag_str(tags, "EXIF FNumber"),
        "latitude":      latitude,
        "longitude":     longitude,
        "gps_available": latitude is not None and longitude is not None,
    }


# ================================
# Anomaly Detection
# ================================

def detect_anomalies(metadata: dict) -> list[str]:
    """
    Checks a metadata dict for forensic red flags.
    Returns a (possibly empty) list of human-readable anomaly strings.
    """
    if metadata.get("status") != "Success":
        return ["No EXIF metadata -- file may be stripped or re-saved"]

    anomalies = []

    if not metadata.get("date_taken"):
        anomalies.append("Missing capture timestamp")

    if not metadata.get("gps_available"):
        anomalies.append("No GPS data embedded")

    if not metadata.get("camera_make") and not metadata.get("camera_model"):
        anomalies.append("No camera make/model recorded")

    software = metadata.get("software") or ""
    for tool in SUSPICIOUS_SOFTWARE:
        if tool.lower() in software.lower():
            anomalies.append(f"Edited with {tool}")

    return anomalies


# ================================
# Timeline Sorting
# ================================

def _parse_date(item: dict) -> datetime:
    """Parses date_taken for sorting; returns datetime.min if missing/invalid."""
    raw = item.get("date_taken")
    if raw:
        try:
            return datetime.strptime(raw, DATE_FORMAT)
        except ValueError:
            pass
    return datetime.min


def sort_by_date(metadata_list: list[dict]) -> list[dict]:
    """Returns metadata_list sorted chronologically by date_taken."""
    return sorted(metadata_list, key=_parse_date)


# ================================
# Folder Processing
# ================================

def process_images_in_folder(folder_path: str) -> list[dict]:
    """
    Walks folder_path, processes every supported image (alphabetical order),
    and returns results sorted chronologically.
    """
    results = []

    for file_name in sorted(os.listdir(folder_path)):
        # Skip hidden files and unsupported extensions
        if file_name.startswith("."):
            continue
        if not file_name.lower().endswith(SUPPORTED_EXTENSIONS):
            continue

        image_path = os.path.join(folder_path, file_name)

        if not os.path.isfile(image_path):
            _info(f"Skipping non-regular file: {file_name}")
            continue

        _info(f"Processing: {file_name}")
        metadata = extract_metadata(image_path)
        metadata["anomalies"] = detect_anomalies(metadata)
        results.append(metadata)

    return sort_by_date(results)


# ================================
# JSON Report
# ================================

def _unique_path(output_file: str) -> str:
    """
    Returns output_file unchanged if it does not exist.
    Otherwise appends a timestamp to avoid silent overwrites.
    """
    if not os.path.exists(output_file):
        return output_file
    base, ext = os.path.splitext(output_file)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = f"{base}_{stamp}{ext}"
    _warn(f"'{output_file}' already exists -- writing to '{safe}' instead")
    return safe


def save_to_json(data: list[dict], output_file: str = DEFAULT_OUTPUT) -> str:
    """Writes results to a UTF-8 JSON file. Returns the path written."""
    output_file = _unique_path(output_file)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    _info(f"Report saved -> {output_file}")
    return output_file


# ================================
# Console Report
# ================================

def _field(label: str, value) -> None:
    """Prints one labelled field, substituting N/A for falsy values."""
    print(f"  {label:<14}: {value or 'N/A'}")


def print_report(data: list[dict]) -> None:
    """Prints a structured forensic report to stdout."""
    print()
    print("=" * 50)
    print("  DIGITAL FORENSICS REPORT")
    print("=" * 50)
    print(f"  Images analysed : {len(data)}")
    print(f"  Run at          : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)

    for i, item in enumerate(data, 1):
        print(f"\n[{i}] {item['filename']}")
        print(DIVIDER)
        _field("Status",       item["status"])
        _field("Date taken",   item.get("date_taken"))
        _field("Camera make",  item.get("camera_make"))
        _field("Camera model", item.get("camera_model"))
        _field("Software",     item.get("software"))

        w = item.get("image_width")
        h = item.get("image_height")
        _field("Resolution",   f"{w} x {h}" if w and h else None)

        _field("ISO",          item.get("iso"))
        _field("Focal length", item.get("focal_length"))
        _field("Exposure",     item.get("exposure_time"))
        _field("F-number",     item.get("f_number"))

        if item.get("gps_available"):
            lat = item["latitude"]
            lon = item["longitude"]
            _field("GPS",       f"{lat:.6f}, {lon:.6f}")
            _field("Maps link", f"https://maps.google.com/?q={lat:.6f},{lon:.6f}")
        else:
            _field("GPS",       None)

        anomalies = item.get("anomalies", [])
        if anomalies:
            print(f"  {'Anomalies':<14}:")
            for a in anomalies:
                print(f"                   [!] {a}")
        else:
            _field("Anomalies", "None detected")

    print()
    print(DIVIDER)
    print()


# ================================
# Logging Helpers
# ================================

def _info(msg: str) -> None:
    print(f"[INFO] {msg}")


def _warn(msg: str) -> None:
    print(f"[WARN] {msg}")


# ================================
# CLI
# ================================

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Digital Image Metadata & Geolocation Forensics Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py\n"
            "  python main.py -f C:\\Users\\you\\photos\n"
            "  python main.py -f ./imgs -o my_report.json\n"
            "  python main.py -f ./imgs --no-save\n"
        ),
    )
    parser.add_argument(
        "--folder", "-f",
        default=DEFAULT_FOLDER,
        help=f"Folder of images to analyse (default: {DEFAULT_FOLDER})",
    )
    parser.add_argument(
        "--output", "-o",
        default=DEFAULT_OUTPUT,
        help=f"JSON output path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Print report only, do not write a JSON file",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if not os.path.isdir(args.folder):
        print(f"[ERROR] Folder not found: '{args.folder}'")
        sys.exit(1)

    results = process_images_in_folder(args.folder)

    if not results:
        print("[INFO] No supported images found.")
        return

    print_report(results)

    if not args.no_save:
        save_to_json(results, args.output)


if __name__ == "__main__":
    main()
