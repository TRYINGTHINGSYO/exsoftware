from __future__ import annotations

import struct
from datetime import datetime, timezone
from types import SimpleNamespace

from exsoftware.analyzers.macho import MachOAnalyzer
from exsoftware.cli import render_text
from exsoftware.composition import compose
from exsoftware.investigation import Investigation
from exsoftware.models import AnalyzerResult, FileIdentity, Report
from exsoftware.rules.macho_capabilities import normalize_macho_library_name, normalize_macho_symbol_name


SHA = "3" * 64


def _identity() -> FileIdentity:
    return FileIdentity(
        name="sample",
        path=None,
        source="bytes",
        extension="",
        size=1024,
        detected_type="macho64",
        detected_family="executable",
        detected_mime="application/x-mach-binary",
        description="Mach-O executable",
        extension_matches=True,
        magic_offset=0,
        magic_hex="cffaedfe",
    )


def _macho_details(
    *,
    dylibs: list[str],
    symbols: list[tuple[str, str] | str],
) -> dict:
    imported = []
    for item in symbols:
        if isinstance(item, tuple):
            library, name = item
        else:
            library, name = "unknown", item
        imported.append(
            {
                "name": name,
                "normalized_name": normalize_macho_symbol_name(name),
                "library": library,
                "normalized_library": normalize_macho_library_name(library),
            }
        )
    return {
        "is64": True,
        "filetype": "EXECUTE",
        "dylibs": dylibs,
        "dylibs_normalized": [normalize_macho_library_name(name) for name in dylibs],
        "imported_functions": imported,
        "rpaths": [],
        "code_signature_command": False,
    }


def _report(
    *,
    dylibs: list[str] | None = None,
    symbols: list[tuple[str, str] | str] | None = None,
    details: dict | None = None,
) -> Report:
    inv = Investigation()
    artifact = inv.add_file_artifact(
        sha256=SHA,
        name="sample",
        size=1024,
        hashes={"sha256": SHA},
        detected_type="macho64",
        detected_family="executable",
        detected_mime="application/x-mach-binary",
        description="Mach-O executable",
    )
    run = inv.begin_run(
        analyzer_id="macho",
        analyzer_version="1.0.0",
        analyzer_title="Mach-O",
        artifact_id=artifact.id,
    )
    payload = details if details is not None else _macho_details(dylibs=dylibs or [], symbols=symbols or [])
    macho_result = AnalyzerResult(
        name="macho",
        title="Mach-O",
        applies=True,
        status="completed",
        analyzer_version="1.0.0",
        details=payload,
    )
    inv.ingest_result("macho", "1.0.0", artifact.id, macho_result, run)
    report = Report(
        schema_version=1,
        analyzed_at=datetime.now(tz=timezone.utc).isoformat(),
        identity=_identity(),
        overview="",
        next_steps=[],
        hashes={"sha256": SHA},
        findings=list(inv.findings),
        sections=[macho_result],
        limits={"executed": False, "static_only": True},
        capabilities=[],
        engine={"name": "exsoftware", "version": "test", "schema": "exsoftware.report"},
        root_artifact_id=artifact.id,
        artifacts=list(inv.artifacts.values()),
        relationships=list(inv.relationships),
        observations=list(inv.observations),
        evidence_store=list(inv.evidence),
        analyzer_runs=list(inv.runs),
    )
    report.composition = compose(report).to_dict()
    return report


def _caps(report: Report) -> dict[str, dict]:
    return {item["id"]: item for item in report.composition["capabilities"]}


def test_normalize_macho_library_framework_and_versioned_dylib():
    assert (
        normalize_macho_library_name("/System/Library/Frameworks/CFNetwork.framework/Versions/A/CFNetwork")
        == "cfnetwork.framework"
    )
    assert normalize_macho_library_name("/usr/lib/libSystem.B.dylib") == "libsystem.b.dylib"
    assert normalize_macho_library_name("@rpath/libcurl.4.dylib") == "libcurl.dylib"
    assert normalize_macho_library_name("Foundation.framework/Foundation") == "foundation.framework"


def test_normalize_macho_symbol_strips_leading_underscore_and_objc_class():
    assert normalize_macho_symbol_name("_socket") == "socket"
    assert normalize_macho_symbol_name("_posix_spawn") == "posix_spawn"
    assert normalize_macho_symbol_name("_NSLookupSymbolInImage") == "NSLookupSymbolInImage"
    assert normalize_macho_symbol_name("_OBJC_CLASS_$_NSURLSession") == "NSURLSession"
    assert normalize_macho_symbol_name("_OBJC_METACLASS_$_NSTask") == "NSTask"
    assert normalize_macho_symbol_name("") is None


def test_posix_spawn_and_fork_yield_process_capability():
    caps = _caps(_report(symbols=["_fork", "_posix_spawn"]))
    cap = caps["CAP.PROCESS.MACHO_FORK.001"]
    assert cap["certainty"] == "inferred"
    assert cap["confidence"] == "high"
    evidence = " ".join(cap["evidence"])
    assert "fork" in evidence
    assert "posix_spawn" in evidence


def test_execve_yields_exec_capability():
    caps = _caps(_report(symbols=["_execve"]))
    assert "CAP.PROCESS.MACHO_EXEC.001" in caps


def test_system_yields_shell_capability():
    caps = _caps(_report(symbols=["_system"]))
    assert "CAP.SHELL.MACHO_SYSTEM.001" in caps


def test_dlopen_and_nslookup_yield_dynamic_loading():
    caps = _caps(_report(symbols=["_dlopen", "_NSLookupSymbolInImage"]))
    cap = caps["CAP.DYNAMIC_LOADING.MACHO_DLOPEN.001"]
    evidence = " ".join(cap["evidence"])
    assert "dlopen" in evidence
    assert "NSLookupSymbolInImage" in evidence


def test_socket_symbols_yield_network_capability():
    report = _report(
        dylibs=["/usr/lib/libSystem.B.dylib"],
        symbols=[("/usr/lib/libSystem.B.dylib", "_socket"), ("/usr/lib/libSystem.B.dylib", "_connect")],
    )
    cap = _caps(report)["CAP.NETWORK.MACHO_SOCKET.001"]
    evidence = " ".join(cap["evidence"])
    assert "socket" in evidence
    assert "libsystem.b.dylib" in evidence


def test_nsurlsession_class_ref_yields_cfnetwork_capability():
    caps = _caps(_report(symbols=["_OBJC_CLASS_$_NSURLSession"]))
    cap = caps["CAP.NETWORK.MACHO_NSURLSESSION.001"]
    assert cap["confidence"] == "high"
    assert "NSURLSession" in " ".join(cap["evidence"])


def test_read_and_write_alone_do_not_yield_filesystem_capability():
    caps = _caps(_report(symbols=["_read", "_write"]))
    assert "CAP.FILESYSTEM.MACHO_OPEN_WRITE.001" not in caps


def test_open_and_unlink_yield_filesystem_capability():
    caps = _caps(_report(symbols=["_open", "_unlink", "_rename"]))
    assert "CAP.FILESYSTEM.MACHO_OPEN_WRITE.001" in caps


def test_mmap_is_memory_not_injection():
    caps = _caps(_report(symbols=["_mmap", "_mprotect"]))
    assert "CAP.MEMORY.MACHO_MMAP.001" in caps
    assert not any("INJECTION" in item for item in caps)


def test_dylib_links_stay_depends_on_not_imports():
    report = _report(
        dylibs=["/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/Foundation.framework/Foundation"],
        symbols=[("/usr/lib/libSystem.B.dylib", "_socket")],
    )
    types = {rel.type for rel in report.relationships}
    targets = {rel.target_id for rel in report.relationships if rel.type == "DEPENDS_ON"}
    assert types == {"DEPENDS_ON"}
    assert any("libSystem.B.dylib" in item for item in targets)
    assert all(rel.certainty == "observed" for rel in report.relationships)


def test_missing_symbols_do_not_invent_capabilities_from_dylibs_alone():
    report = _report(dylibs=["/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/CFNetwork.framework/CFNetwork"])
    assert report.composition["capabilities"] == []
    assert any(rel.type == "DEPENDS_ON" for rel in report.relationships)


def test_fat_first_slice_dylibs_do_not_create_depends_on():
    details = {
        "kind": "fat",
        "nfat": 1,
        "arches": [],
        "first_slice": {
            "dylibs": ["/usr/lib/libSystem.B.dylib"],
            "imported_functions": [
                {
                    "name": "_socket",
                    "normalized_name": "socket",
                    "library": "/usr/lib/libSystem.B.dylib",
                    "normalized_library": "libsystem.b.dylib",
                }
            ],
        },
        "imported_functions": [
            {
                "name": "_socket",
                "normalized_name": "socket",
                "library": "/usr/lib/libSystem.B.dylib",
                "normalized_library": "libsystem.b.dylib",
            }
        ],
    }
    report = _report(details=details)
    assert not any(rel.type == "DEPENDS_ON" for rel in report.relationships)
    assert "IMPORTS" not in {rel.type for rel in report.relationships}
    assert any(obs.kind == "macho.import.function" for obs in report.observations)
    assert "CAP.NETWORK.MACHO_SOCKET.001" in _caps(report)


def test_evidence_links_survive_from_observation_to_capability():
    report = _report(symbols=["_posix_spawn"])
    cap = _caps(report)["CAP.PROCESS.MACHO_FORK.001"]
    assert cap["refs"]["evidence_ids"]
    assert cap["refs"]["observation_ids"]
    assert set(cap["refs"]["evidence_ids"]) <= {item.id for item in report.evidence_store}
    assert set(cap["refs"]["observation_ids"]) <= {item.id for item in report.observations}


def test_completeness_records_macho_import_only_gap():
    report = _report(symbols=["_socket"])
    gap_ids = [item["id"] for item in report.composition["gaps"]]
    assert "GAP.MACHO.CAPABILITIES.IMPORTS_ONLY.001" in gap_ids
    statement = next(item["statement"] for item in report.composition["gaps"] if item["id"] == "GAP.MACHO.CAPABILITIES.IMPORTS_ONLY.001")
    assert "not observed" in statement
    assert "not absent" in statement


def test_rendered_report_shows_capability_evidence_and_confidence():
    report = _report(symbols=["_OBJC_CLASS_$_NSURLSession"])
    text = render_text(report)
    assert "NSURLSession / CFNetwork client" in text
    assert "Evidence:" in text
    assert "NSURLSession" in text
    assert "Confidence: high" in text
    assert "Mach-O capability inference is based on static undefined symbols" in text


def _dylib_command(path: str, cmd: int = 0x0C) -> bytes:
    name = path.encode("utf-8") + b"\x00"
    name_off = 24
    pad = (8 - ((name_off + len(name)) % 8)) % 8
    cmdsize = name_off + len(name) + pad
    return struct.pack("<II", cmd, cmdsize) + struct.pack("<IIII", name_off, 0, 0, 0) + name + (b"\x00" * pad)


def _build_macho64(
    *,
    dylibs: list[str],
    undef: list[tuple[str, int]],
    defined: list[str] | None = None,
    extra_dylibs: list[tuple[int, str]] | None = None,
) -> bytes:
    defined = defined or []
    extra_dylibs = extra_dylibs or []
    names = [name for name, _ordinal in undef] + defined
    string_table = bytearray(b"\x00")
    offsets = {}
    for name in names:
        offsets[name] = len(string_table)
        string_table.extend(name.encode("utf-8") + b"\x00")

    nlist = bytearray()
    for name, ordinal in undef:
        n_desc = (ordinal & 0xFF) << 8
        nlist.extend(struct.pack("<IBBHQ", offsets[name], 0x01, 0, n_desc, 0))
    for name in defined:
        nlist.extend(struct.pack("<IBBHQ", offsets[name], 0x0F, 1, 0, 0x1000))

    load = b"".join(_dylib_command(path) for path in dylibs)
    load += b"".join(_dylib_command(path, cmd=cmd) for cmd, path in extra_dylibs)
    nsyms = len(undef) + len(defined)
    header_size = 32
    sizeofcmds = len(load) + 24 + 32
    symoff = header_size + sizeofcmds
    stroff = symoff + nsyms * 16
    symtab = struct.pack("<IIIIII", 0x02, 24, symoff, nsyms, stroff, len(string_table))
    dysymtab = struct.pack("<II", 0x0B, 32) + struct.pack("<IIII", 0, 0, 0, 0) + struct.pack("<II", 0, len(undef))
    ncmds = len(dylibs) + len(extra_dylibs) + 2
    header = (
        b"\xcf\xfa\xed\xfe"
        + struct.pack("<IIIIII", 0x01000007, 3, 2, ncmds, sizeofcmds, 0)
        + struct.pack("<I", 0)
    )
    return header + load + symtab + dysymtab + bytes(nlist) + bytes(string_table)


def test_analyzer_extracts_undefined_symbols_and_dylib_ordinals():
    data = _build_macho64(
        dylibs=["/usr/lib/libSystem.B.dylib"],
        undef=[("_socket", 1), ("_posix_spawn", 1)],
        defined=["_local_helper"],
    )
    result = MachOAnalyzer().analyze(SimpleNamespace(data=data))
    assert result.status == "completed"
    assert result.details["dylibs"] == ["/usr/lib/libSystem.B.dylib"]
    names = {item["normalized_name"]: item for item in result.details["imported_functions"]}
    assert set(names) == {"socket", "posix_spawn"}
    assert names["socket"]["name"] == "_socket"
    assert names["socket"]["library"] == "/usr/lib/libSystem.B.dylib"
    assert names["socket"]["normalized_library"] == "libsystem.b.dylib"


def test_analyzer_keeps_reexport_out_of_depends_on_dylibs_but_uses_it_for_ordinals():
    data = _build_macho64(
        dylibs=["/usr/lib/libSystem.B.dylib"],
        extra_dylibs=[(0x1F | 0x80000000, "/usr/lib/libfoo.dylib")],
        undef=[("_socket", 1), ("_foo_helper", 2)],
    )
    result = MachOAnalyzer().analyze(SimpleNamespace(data=data))
    assert result.details["dylibs"] == ["/usr/lib/libSystem.B.dylib"]
    by_name = {item["normalized_name"]: item for item in result.details["imported_functions"]}
    assert by_name["foo_helper"]["library"] == "/usr/lib/libfoo.dylib"


def test_legacy_macho_details_without_imported_functions_do_not_invent_capabilities():
    details = {
        "is64": True,
        "filetype": "EXECUTE",
        "dylibs": ["/usr/lib/libSystem.B.dylib"],
        "rpaths": [],
        "code_signature_command": False,
    }
    report = _report(details=details)
    assert {rel.type for rel in report.relationships} == {"DEPENDS_ON"}
    assert report.composition["capabilities"] == []
    assert not any(obs.kind == "macho.import.function" for obs in report.observations)
