import hashlib
import os
from typing import Dict, Optional, Tuple

from flask import Flask, jsonify, render_template, request


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB


def get_file_signature(file_bytes: bytes, max_len: int = 16) -> bytes:
    """
    Return the file "magic number" (first N bytes).
    """
    if not isinstance(file_bytes, (bytes, bytearray)):
        return b""
    if max_len <= 0:
        return b""
    return bytes(file_bytes[:max_len])


def detect_file_type(signature: bytes) -> str:
    """
    Detect file type from the magic number.
    Uses a simple dictionary of well-known signatures.
    """
    if not signature:
        return "Unknown"

    # Signatures are checked in order (longer / more specific first).
    signatures: Tuple[Tuple[bytes, str], ...] = (
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF87a", "GIF image"),
        (b"GIF89a", "GIF image"),
        (b"%PDF-", "PDF document"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"PK\x05\x06", "ZIP archive (empty)"),
        (b"PK\x07\x08", "ZIP archive (spanned)"),
        (b"MZ", "Windows EXE/DLL"),
        (b"Rar!\x1a\x07\x00", "RAR archive (v1.5+)"),
        (b"Rar!\x1a\x07\x01\x00", "RAR archive (v5+)"),
        (b"\x1f\x8b\x08", "GZIP archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"ID3", "MP3 audio (ID3)"),
        (b"OggS", "Ogg container"),
        (b"BM", "BMP image"),
        (b"\x00\x00\x01\x00", "Windows ICO"),
        (b"\x25\x21PS-Adobe-", "PostScript document"),
        (b"SQLite format 3\x00", "SQLite database"),
    )

    for magic, label in signatures:
        if signature.startswith(magic):
            return label

    # Special-case: MP3 can also start with frame sync 0xFF 0xFB/0xF3/0xF2
    if len(signature) >= 2 and signature[0] == 0xFF and (signature[1] & 0xE0) == 0xE0:
        return "MP3 audio (frame sync)"

    return "Unknown"


def calculate_hashes(file_bytes: bytes) -> Dict[str, str]:
    """
    Compute MD5 and SHA256 for the file bytes.
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    md5.update(file_bytes)
    sha256.update(file_bytes)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def analyze_file(filename: str, file_bytes: bytes) -> Dict[str, object]:
    """
    Analyze the uploaded file and return a JSON-friendly dict.
    """
    safe_filename = os.path.basename(filename or "")
    _, ext = os.path.splitext(safe_filename)
    extension = ext.lower().lstrip(".") if ext else ""

    signature = get_file_signature(file_bytes, max_len=16)
    actual_type = detect_file_type(signature)
    size_bytes = len(file_bytes)

    hashes = calculate_hashes(file_bytes)

    # Map detected labels to expected common extensions (simple heuristic).
    expected_extensions = {
        "PNG image": {"png"},
        "JPEG image": {"jpg", "jpeg"},
        "GIF image": {"gif"},
        "BMP image": {"bmp"},
        "Windows ICO": {"ico"},
        "PDF document": {"pdf"},
        "ZIP archive": {"zip"},
        "ZIP archive (empty)": {"zip"},
        "ZIP archive (spanned)": {"zip"},
        "Windows EXE/DLL": {"exe", "dll"},
        "RAR archive (v1.5+)": {"rar"},
        "RAR archive (v5+)": {"rar"},
        "GZIP archive": {"gz"},
        "7-Zip archive": {"7z"},
        "MP3 audio (ID3)": {"mp3"},
        "MP3 audio (frame sync)": {"mp3"},
        "Ogg container": {"ogg"},
        "PostScript document": {"ps"},
        "SQLite database": {"sqlite", "db"},
    }

    suspicious = False
    status_message: Optional[str] = None
    reason: Optional[str] = None
    expected_list = sorted(expected_extensions.get(actual_type, set()))

    if actual_type == "Unknown":
        suspicious = False
        status_message = "Unknown type (no matching signature)"
        reason = "No known signature matched the file's first bytes."
    else:
        expected = expected_extensions.get(actual_type)
        if extension and expected and extension not in expected:
            suspicious = True
            status_message = "Suspicious file detected"
            reason = (
                f"Extension '.{extension}' does not match detected type '{actual_type}' "
                f"(expected: {', '.join('.' + e for e in sorted(expected))})."
            )
        else:
            suspicious = False
            status_message = "Safe file"
            if extension and expected:
                reason = (
                    f"Extension '.{extension}' matches detected type '{actual_type}'."
                )
            elif not extension:
                reason = "No extension found in filename."
            else:
                reason = "Detected type is known, but no extension rule exists for it."

    return {
        "file_name": safe_filename,
        "extension": extension or "(none)",
        "uploaded_extension": extension or "",
        "actual_type": actual_type,
        "expected_extensions": expected_list,
        "extension_match": (not extension) or (extension in expected_extensions.get(actual_type, set())),
        "file_size_bytes": size_bytes,
        "file_size_kb": round(size_bytes / 1024, 2),
        "md5": hashes["md5"],
        "sha256": hashes["sha256"],
        "suspicious": suspicious,
        "status": status_message,
        "reason": reason,
        "signature_hex": signature.hex(),
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/analyze")
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file field found in request"}), 400

    f = request.files.get("file")
    if f is None or not f.filename:
        return jsonify({"error": "No file selected"}), 400

    try:
        file_bytes = f.read()
    except Exception:
        return jsonify({"error": "Failed to read uploaded file"}), 400

    if not file_bytes:
        return jsonify({"error": "Empty file"}), 400

    result = analyze_file(f.filename, file_bytes)
    return jsonify(result)


if __name__ == "__main__":
    import socket
    import os

    def pick_port(preferred: int) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", preferred))   
                return preferred
            except OSError:
                return 5001 if preferred == 5000 else preferred

    port = int(os.environ.get("PORT", "10000"))  
    port = pick_port(port)
    app.run(host="0.0.0.0", port=port)

