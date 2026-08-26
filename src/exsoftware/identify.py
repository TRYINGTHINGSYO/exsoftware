from __future__ import annotations

import json
from pathlib import Path

from .models import FileIdentity

# (magic, offset, type, family, mime, description)
_SIGNATURES: list[tuple[bytes, int, str, str, str, str]] = [
    (b"MZ", 0, "pe", "executable", "application/vnd.microsoft.portable-executable", "Windows PE executable, DLL, or driver"),
    (b"\x7fELF", 0, "elf", "executable", "application/x-elf", "ELF executable or library"),
    (b"\xcf\xfa\xed\xfe", 0, "macho64", "executable", "application/x-mach-binary", "Mach-O 64-bit binary"),
    (b"\xce\xfa\xed\xfe", 0, "macho32", "executable", "application/x-mach-binary", "Mach-O 32-bit binary"),
    (b"\xca\xfe\xba\xbe", 0, "macho-fat", "executable", "application/x-mach-binary", "Mach-O fat/universal binary or Java class"),
    (b"\xfe\xed\xfa\xce", 0, "macho32-be", "executable", "application/x-mach-binary", "Mach-O 32-bit big-endian binary"),
    (b"\xfe\xed\xfa\xcf", 0, "macho64-be", "executable", "application/x-mach-binary", "Mach-O 64-bit big-endian binary"),
    (b"%PDF", 0, "pdf", "document", "application/pdf", "PDF document"),
    (b"PK\x03\x04", 0, "zip", "archive", "application/zip", "ZIP archive or ZIP-based document"),
    (b"PK\x05\x06", 0, "zip", "archive", "application/zip", "Empty ZIP archive"),
    (b"PK\x07\x08", 0, "zip", "archive", "application/zip", "ZIP archive (spanned)"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole", "document", "application/x-ole-storage", "OLE Compound File (Office, MSI, or similar)"),
    (b"\x89PNG\r\n\x1a\n", 0, "png", "image", "image/png", "PNG image"),
    (b"\xff\xd8\xff", 0, "jpeg", "image", "image/jpeg", "JPEG image"),
    (b"GIF87a", 0, "gif", "image", "image/gif", "GIF image"),
    (b"GIF89a", 0, "gif", "image", "image/gif", "GIF image"),
    (b"BM", 0, "bmp", "image", "image/bmp", "BMP image"),
    (b"RIFF", 0, "riff", "media", "application/octet-stream", "RIFF container (WAV, AVI, WEBP, …)"),
    (b"\x00\x00\x01\x00", 0, "ico", "image", "image/x-icon", "Windows icon"),
    (b"Rar!\x1a\x07", 0, "rar", "archive", "application/vnd.rar", "RAR archive"),
    (b"7z\xbc\xaf'\x1c", 0, "7z", "archive", "application/x-7z-compressed", "7-Zip archive"),
    (b"\x1f\x8b\x08", 0, "gzip", "archive", "application/gzip", "gzip compressed data"),
    (b"BZh", 0, "bzip2", "archive", "application/x-bzip2", "bzip2 compressed data"),
    (b"\xfd7zXZ\x00", 0, "xz", "archive", "application/x-xz", "XZ compressed data"),
    (b"ustar", 257, "tar", "archive", "application/x-tar", "TAR archive"),
    (b"SQLite format 3\x00", 0, "sqlite", "database", "application/vnd.sqlite3", "SQLite database"),
    (b"\x00asm", 0, "wasm", "executable", "application/wasm", "WebAssembly module"),
    (b"dex\n", 0, "dex", "executable", "application/x-dex", "Android DEX file"),
    (b"#!", 0, "script", "script", "text/x-shellscript", "Text script with a shebang"),
    (b"<?xml", 0, "xml", "text", "application/xml", "XML document"),
    (b"\xef\xbb\xbf<?xml", 0, "xml", "text", "application/xml", "XML document (UTF-8 BOM)"),
    (b"{\\rtf", 0, "rtf", "document", "application/rtf", "RTF document"),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", 0, "lnk", "shortcut", "application/x-ms-shortcut", "Windows shortcut (LNK)"),
    (b"regf", 0, "registry-hive", "database", "application/octet-stream", "Windows registry hive"),
    (b"\x80\x00\x00\x00", 0, "pyc", "bytecode", "application/x-python-bytecode", "Possible Python bytecode (needs confirmation)"),
]

_EXTENSION_FAMILIES: dict[str, set[str]] = {
    ".exe": {"pe"},
    ".dll": {"pe"},
    ".sys": {"pe"},
    ".scr": {"pe"},
    ".ocx": {"pe"},
    ".cpl": {"pe"},
    ".efi": {"pe"},
    ".acm": {"pe"},
    ".ax": {"pe"},
    ".drv": {"pe"},
    ".so": {"elf"},
    ".elf": {"elf"},
    ".o": {"elf", "macho32", "macho64", "macho-fat"},
    ".dylib": {"macho32", "macho64", "macho-fat", "macho32-be", "macho64-be"},
    ".pdf": {"pdf"},
    ".zip": {"zip"},
    ".jar": {"jar", "zip"},
    ".apk": {"apk", "zip"},
    ".whl": {"wheel", "zip"},
    ".docx": {"docx", "zip"},
    ".xlsx": {"xlsx", "zip"},
    ".pptx": {"pptx", "zip"},
    ".doc": {"ole", "doc"},
    ".xls": {"ole", "xls"},
    ".ppt": {"ole", "ppt"},
    ".msi": {"ole", "msi"},
    ".msg": {"ole", "msg"},
    ".png": {"png"},
    ".jpg": {"jpeg"},
    ".jpeg": {"jpeg"},
    ".gif": {"gif"},
    ".bmp": {"bmp"},
    ".ico": {"ico"},
    ".webp": {"webp", "riff"},
    ".wav": {"wav", "riff"},
    ".avi": {"avi", "riff"},
    ".gz": {"gzip"},
    ".tgz": {"gzip"},
    ".bz2": {"bzip2"},
    ".xz": {"xz"},
    ".7z": {"7z"},
    ".rar": {"rar"},
    ".tar": {"tar"},
    ".sqlite": {"sqlite"},
    ".db": {"sqlite"},
    ".wasm": {"wasm"},
    ".dex": {"dex"},
    ".class": {"java-class", "macho-fat"},
    ".lnk": {"lnk"},
    ".xml": {"xml", "text"},
    ".svg": {"xml", "text"},
    ".toml": {"toml", "text"},
    ".json": {"json", "text"},
    ".py": {"python", "script", "text"},
    ".ps1": {"powershell", "script", "text"},
    ".js": {"javascript", "script", "text"},
    ".mjs": {"javascript", "script", "text"},
    ".ts": {"typescript", "script", "text"},
    ".vbs": {"vbscript", "script", "text"},
    ".bat": {"batch", "script", "text"},
    ".cmd": {"batch", "script", "text"},
    ".sh": {"shell", "script", "text"},
    ".bash": {"shell", "script", "text"},
    ".rb": {"ruby", "script", "text"},
    ".php": {"php", "script", "text"},
    ".html": {"html", "text"},
    ".htm": {"html", "text"},
    ".css": {"text"},
    ".txt": {"text"},
    ".md": {"text"},
    ".csv": {"text"},
    ".reg": {"text", "registry-script"},
    ".rtf": {"rtf"},
    ".pyc": {"pyc"},
}


def _hex_preview(data: bytes, n: int = 16) -> str:
    return data[:n].hex(" ")


def _is_pe(data: bytes) -> bool:
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    e_lfanew = int.from_bytes(data[60:64], "little")
    if e_lfanew < 0 or e_lfanew + 4 > len(data):
        return False
    return data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"


def _is_java_class(data: bytes) -> bool:
    if len(data) < 8 or data[:4] != b"\xca\xfe\xba\xbe":
        return False
    # Fat Mach-O stores architecture count at offset 4 as a small integer.
    # Java class stores version at offset 4-8 as 0x0000xxxx typically.
    nfat = int.from_bytes(data[4:8], "big")
    if 1 <= nfat <= 20:
        return False
    major = int.from_bytes(data[6:8], "big")
    return 45 <= major <= 70


def _looks_like_utf16le_text(sample: bytes) -> bool:
    if len(sample) < 8:
        return False
    even = sample[0::2]
    odd = sample[1::2]
    if not odd or sum(1 for b in odd if b == 0) / len(odd) < 0.7:
        return False
    printable = sum(1 for b in even if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(even) >= 0.8


def _looks_like_text(sample: bytes) -> bool:
    if not sample:
        return True
    if sample.startswith(b"\xff\xfe") or sample.startswith(b"\xfe\xff"):
        return True
    if _looks_like_utf16le_text(sample):
        return True
    snippet = sample[:4096]
    if b"\x00" in snippet:
        return False
    try:
        text = snippet.decode("utf-8")
    except UnicodeDecodeError:
        printable = sum(1 for b in snippet if 9 <= b <= 13 or 32 <= b <= 126)
        return printable / max(len(snippet), 1) >= 0.85
    # Reject if too many control chars besides tab/newline.
    bad = sum(1 for ch in text if ord(ch) < 32 and ch not in "\t\r\n")
    return bad / max(len(text), 1) < 0.05


def _script_kind_from_shebang(data: bytes) -> str | None:
    if not data.startswith(b"#!"):
        return None
    line = data.split(b"\n", 1)[0].decode("utf-8", "replace").lower()
    if "python" in line:
        return "python"
    if "powershell" in line or "pwsh" in line:
        return "powershell"
    if "node" in line:
        return "javascript"
    if "ruby" in line:
        return "ruby"
    if "perl" in line:
        return "perl"
    if "bash" in line or "/sh" in line or "zsh" in line:
        return "shell"
    return "script"


def refine_zip_type_from_names(names: list[str]) -> tuple[str, str, str, str]:
    """Classify a ZIP-family container from member *names only*.

    This is not ZIP parsing. Names come from a validated container manifest
    (untrusted strings used only as metadata). The trusted parent never opens
    the archive with zipfile to make this decision.
    """
    normalized = [str(name).replace("\\", "/") for name in names]
    if any(name.startswith("word/") for name in normalized):
        return "docx", "document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "Word document (Office Open XML)"
    if any(name.startswith("xl/") for name in normalized):
        return "xlsx", "document", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Excel workbook (Office Open XML)"
    if any(name.startswith("ppt/") for name in normalized):
        return "pptx", "document", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "PowerPoint presentation (Office Open XML)"
    if "AndroidManifest.xml" in normalized:
        return "apk", "archive", "application/vnd.android.package-archive", "Android package (ZIP-based)"
    if "META-INF/MANIFEST.MF" in normalized and any(name.endswith(".class") for name in normalized):
        return "jar", "archive", "application/java-archive", "Java JAR archive"
    if any(name.endswith(".dist-info/METADATA") or name.endswith(".dist-info/WHEEL") for name in normalized):
        return "wheel", "archive", "application/x-wheel+zip", "Python wheel"
    return "zip", "archive", "application/zip", "ZIP archive"


def _refine_riff(data: bytes) -> tuple[str, str, str, str]:
    kind = data[8:12] if len(data) >= 12 else b""
    if kind == b"WEBP":
        return "webp", "image", "image/webp", "WEBP image"
    if kind == b"WAVE":
        return "wav", "media", "audio/wav", "WAV audio"
    if kind == b"AVI ":
        return "avi", "media", "video/x-msvideo", "AVI video"
    return "riff", "media", "application/octet-stream", f"RIFF container ({kind.decode('latin-1', 'replace')!r})"


def refine_ole_type_from_streams(streams: list[str]) -> tuple[str, str, str, str]:
    """Classify an OLE compound file from stream *names only*.

    This is not OLE parsing. Names come from a validated contained-worker
    manifest (untrusted strings used only as metadata). The trusted parent
    never opens the buffer with olefile to make this decision.
    """
    lowered = {str(item).replace("\\", "/").lower() for item in streams}

    def has(name: str) -> bool:
        target = name.lower()
        return target in lowered or any(item.endswith("/" + target.lstrip("/")) for item in lowered)

    if has("/worddocument"):
        return "doc", "document", "application/msword", "Microsoft Word document (OLE)"
    if has("/workbook") or has("/book"):
        return "xls", "document", "application/vnd.ms-excel", "Microsoft Excel workbook (OLE)"
    if has("/powerpoint document"):
        return "ppt", "document", "application/vnd.ms-powerpoint", "Microsoft PowerPoint presentation (OLE)"
    if has("/__properties_version1.0") or has("/__nameid_version1.0"):
        return "msg", "document", "application/vnd.ms-outlook", "Outlook message (OLE)"
    if has("/_stringdata") or has("/_tables"):
        return "msi", "installer", "application/x-msi", "Windows Installer package (OLE)"
    return "ole", "document", "application/x-ole-storage", "OLE Compound File"


def _looks_like_json(text: str) -> bool:
    snippet = text.strip()
    if not snippet or snippet[0] not in "{[":
        return False
    try:
        json.loads(snippet)
        return True
    except json.JSONDecodeError:
        return False


def _refine_text(data: bytes, extension: str) -> tuple[str, str, str, str]:
    sample = data[:8192]
    shebang = _script_kind_from_shebang(data)
    if shebang:
        mime = "text/x-script"
        return shebang, "script", mime, f"{shebang} script (shebang)"
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        if _looks_like_utf16le_text(sample):
            return "text-utf16", "text", "text/plain", "UTF-16 text"
        return "text", "text", "text/plain", "Text file"
    head = text.lstrip().lower()
    if _looks_like_json(text):
        return "json", "text", "application/json", "JSON text"
    if head.startswith("<!doctype html") or head.startswith("<html"):
        return "html", "text", "text/html", "HTML document"
    if "windows registry editor" in head:
        return "registry-script", "script", "text/x-registry", "Windows registry script"
    mapping = {
        ".py": ("python", "script", "text/x-python", "Python source"),
        ".ps1": ("powershell", "script", "text/x-powershell", "PowerShell script"),
        ".js": ("javascript", "script", "text/javascript", "JavaScript source"),
        ".mjs": ("javascript", "script", "text/javascript", "JavaScript source"),
        ".ts": ("typescript", "script", "text/typescript", "TypeScript source"),
        ".vbs": ("vbscript", "script", "text/vbscript", "VBScript source"),
        ".bat": ("batch", "script", "text/x-batch", "Windows batch script"),
        ".cmd": ("batch", "script", "text/x-batch", "Windows batch script"),
        ".sh": ("shell", "script", "text/x-shellscript", "Shell script"),
        ".php": ("php", "script", "text/x-php", "PHP source"),
        ".rb": ("ruby", "script", "text/x-ruby", "Ruby source"),
        ".html": ("html", "text", "text/html", "HTML document"),
        ".htm": ("html", "text", "text/html", "HTML document"),
        ".xml": ("xml", "text", "application/xml", "XML document"),
        ".svg": ("xml", "text", "image/svg+xml", "SVG image (XML)"),
        ".json": ("json", "text", "application/json", "JSON text"),
        ".toml": ("toml", "text", "text/x-toml", "TOML text"),
        ".reg": ("registry-script", "script", "text/x-registry", "Windows registry script"),
    }
    if extension in mapping:
        return mapping[extension]
    return "text", "text", "text/plain", "Text file"


def _extension_matches(extension: str, detected_type: str) -> bool | None:
    if not extension:
        return None
    allowed = _EXTENSION_FAMILIES.get(extension)
    if allowed is None:
        return None
    return detected_type in allowed


def identify_bytes(data: bytes, name: str, size: int | None = None) -> FileIdentity:
    filename = Path(name).name if name else "unnamed"
    extension = Path(filename).suffix.lower()
    file_size = size if size is not None else len(data)
    sample = data[:65536]

    detected_type = "unknown"
    family = "unknown"
    mime = "application/octet-stream"
    description = "Unrecognized binary data"
    magic_offset = 0
    matched_magic = b""

    for magic, offset, kind, fam, kind_mime, desc in _SIGNATURES:
        end = offset + len(magic)
        if len(data) >= end and data[offset:end] == magic:
            detected_type, family, mime, description = kind, fam, kind_mime, desc
            magic_offset = offset
            matched_magic = magic
            break

    extra: dict[str, object] = {}

    if detected_type == "pe":
        if _is_pe(data):
            extra["pe_signature"] = True
        else:
            detected_type = "dos-mz"
            family = "executable"
            mime = "application/x-dosexec"
            description = "DOS MZ stub without a PE signature"
            extra["pe_signature"] = False
    elif detected_type == "zip":
        extra["zip_subtype_pending"] = True
    elif detected_type == "riff":
        detected_type, family, mime, description = _refine_riff(data)
    elif detected_type == "ole":
        # Subtype (doc/xls/…) requires olefile stream listing in a contained worker.
        extra["ole_subtype_pending"] = True
    elif detected_type == "macho-fat":
        if _is_java_class(data):
            detected_type, family, mime, description = (
                "java-class",
                "bytecode",
                "application/java-vm",
                "Java class file",
            )
    elif detected_type == "pyc":
        # The 0x80 00 00 00 magic is too short; only keep if extension suggests pyc
        # or we see a typical pyc timestamp/header layout.
        if extension != ".pyc" and not filename.endswith(".pyc"):
            detected_type = "unknown"
            family = "unknown"
            mime = "application/octet-stream"
            description = "Unrecognized binary data"
            matched_magic = b""

    if detected_type == "unknown":
        if _looks_like_text(sample):
            detected_type, family, mime, description = _refine_text(data, extension)
            extra["text_heuristic"] = True
        else:
            extra["text_heuristic"] = False

    if detected_type == "script":
        shebang = _script_kind_from_shebang(data)
        if shebang:
            detected_type = shebang
            extra["shebang"] = True

    return FileIdentity(
        name=filename,
        path=None,
        source="bytes",
        extension=extension,
        size=file_size,
        detected_type=detected_type,
        detected_family=family,
        detected_mime=mime,
        description=description,
        extension_matches=_extension_matches(extension, detected_type),
        magic_offset=magic_offset,
        magic_hex=_hex_preview(matched_magic or data),
        extra=extra,
    )
