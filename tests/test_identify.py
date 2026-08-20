from pathlib import Path

from exsoftware.identify import identify_bytes


def test_pe_magic(tmp_path: Path):
    # Minimal MZ + PE signature at a plausible e_lfanew.
    data = bytearray(256)
    data[0:2] = b"MZ"
    data[60:64] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    ident = identify_bytes(bytes(data), "demo.exe")
    assert ident.detected_type == "pe"
    assert ident.extension_matches is True


def test_zip_disguised_as_txt():
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("readme.txt", "hello")
    ident = identify_bytes(buf.getvalue(), "notes.txt")
    assert ident.detected_type == "zip"
    assert ident.extension_matches is False


def test_png_magic():
    ident = identify_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16, "pic.png")
    assert ident.detected_type == "png"
    assert ident.extension_matches is True


def test_python_text():
    ident = identify_bytes(b"import os\nprint('x')\n", "tool.py")
    assert ident.detected_type == "python"
    assert ident.detected_family == "script"


def test_unknown_binary():
    ident = identify_bytes(bytes(range(32)), "blob.dat")
    assert ident.detected_type == "unknown"


def test_toml_is_not_json():
    data = b"[project]\nname = \"exsoftware\"\n"
    ident = identify_bytes(data, "pyproject.toml")
    assert ident.detected_type == "toml"


def test_json_object():
    ident = identify_bytes(b'{"a": 1}\n', "data.json")
    assert ident.detected_type == "json"

