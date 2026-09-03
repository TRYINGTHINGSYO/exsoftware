from __future__ import annotations

from datetime import datetime, timezone

from exsoftware.analyzers.elf import collect_imported_functions
from exsoftware.cli import render_text
from exsoftware.composition import compose
from exsoftware.investigation import Investigation
from exsoftware.models import AnalyzerResult, FileIdentity, Report
from exsoftware.rules.elf_capabilities import normalize_elf_library_name, normalize_elf_symbol_name


SHA = "2" * 64


def _identity() -> FileIdentity:
    return FileIdentity(
        name="sample",
        path=None,
        source="bytes",
        extension="",
        size=1024,
        detected_type="elf",
        detected_family="executable",
        detected_mime="application/x-elf",
        description="ELF executable",
        extension_matches=True,
        magic_offset=0,
        magic_hex="7f454c46",
    )


def _elf_details(
    *,
    needed: list[str],
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
                "normalized_name": normalize_elf_symbol_name(name),
                "library": library,
                "normalized_library": normalize_elf_library_name(library),
                "version": None,
                "symbol_type": "STT_FUNC",
            }
        )
    return {
        "class": "ELFCLASS64",
        "machine": "Advanced Micro Devices X86-64",
        "needed": needed,
        "needed_normalized": [normalize_elf_library_name(name) for name in needed],
        "imported_functions": imported,
        "sections": [],
        "symbols_sample": [item[1] if isinstance(item, tuple) else item for item in symbols],
        "symbol_count": len(symbols),
    }


def _report(
    *,
    needed: list[str] | None = None,
    symbols: list[tuple[str, str] | str] | None = None,
    legacy: bool = False,
) -> Report:
    inv = Investigation()
    artifact = inv.add_file_artifact(
        sha256=SHA,
        name="sample",
        size=1024,
        hashes={"sha256": SHA},
        detected_type="elf",
        detected_family="executable",
        detected_mime="application/x-elf",
        description="ELF executable",
    )
    run = inv.begin_run(
        analyzer_id="elf",
        analyzer_version="1.0.0",
        analyzer_title="ELF",
        artifact_id=artifact.id,
    )
    details = _elf_details(needed=needed or [], symbols=symbols or [])
    if legacy:
        details.pop("imported_functions")
        details.pop("needed_normalized")
    elf_result = AnalyzerResult(
        name="elf",
        title="ELF",
        applies=True,
        status="completed",
        analyzer_version="1.0.0",
        details=details,
    )
    inv.ingest_result("elf", "1.0.0", artifact.id, elf_result, run)
    report = Report(
        schema_version=1,
        analyzed_at=datetime.now(tz=timezone.utc).isoformat(),
        identity=_identity(),
        overview="",
        next_steps=[],
        hashes={"sha256": SHA},
        findings=list(inv.findings),
        sections=[elf_result],
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


def test_normalize_elf_library_strips_path_and_so_version():
    assert normalize_elf_library_name("/usr/lib/libcurl.so.4") == "libcurl.so"
    assert normalize_elf_library_name("libssl.so.3") == "libssl.so"
    assert normalize_elf_library_name("libc.so.6") == "libc.so"
    assert normalize_elf_library_name("libpthread.so") == "libpthread.so"


def test_normalize_elf_symbol_strips_gnu_versions():
    assert normalize_elf_symbol_name("fork@GLIBC_2.2.5") == "fork"
    assert normalize_elf_symbol_name("curl_easy_init@@CURL_OPENSSL_4") == "curl_easy_init"
    assert normalize_elf_symbol_name("_GLOBAL_OFFSET_TABLE_") is None
    assert normalize_elf_symbol_name("") is None


def test_fork_and_execve_yield_process_capabilities():
    caps = _caps(_report(symbols=["fork", "execve"]))
    assert caps["CAP.PROCESS.ELF_FORK.001"]["confidence"] == "high"
    assert caps["CAP.PROCESS.ELF_EXEC.001"]["confidence"] == "high"
    assert "fork" in " ".join(caps["CAP.PROCESS.ELF_FORK.001"]["evidence"])
    assert "execve" in " ".join(caps["CAP.PROCESS.ELF_EXEC.001"]["evidence"])


def test_posix_spawn_is_process_creation():
    caps = _caps(_report(symbols=["posix_spawn"]))
    assert "CAP.PROCESS.ELF_FORK.001" in caps


def test_system_and_popen_yield_shell_capability():
    caps = _caps(_report(symbols=["system", "popen"]))
    assert "CAP.SHELL.ELF_SYSTEM.001" in caps


def test_dlopen_yields_dynamic_loading_capability():
    caps = _caps(_report(symbols=["dlopen", "dlsym"]))
    cap = caps["CAP.DYNAMIC_LOADING.ELF_DLOPEN.001"]
    assert cap["confidence"] == "high"
    assert "dlopen" in " ".join(cap["evidence"])


def test_libcurl_symbols_yield_network_capability_with_library_evidence():
    report = _report(
        needed=["libcurl.so.4"],
        symbols=[("libcurl.so.4", "curl_easy_init"), ("libcurl.so.4", "curl_easy_perform")],
    )
    caps = _caps(report)
    cap = caps["CAP.NETWORK.ELF_LIBCURL.001"]
    evidence = " ".join(cap["evidence"])
    assert cap["confidence"] == "high"
    assert "curl_easy_init" in evidence
    assert "curl_easy_perform" in evidence
    assert "libcurl.so" in evidence


def test_socket_symbols_without_libc_needed_still_match():
    caps = _caps(_report(needed=[], symbols=["socket", "connect"]))
    assert "CAP.NETWORK.ELF_SOCKET.001" in caps


def test_ptrace_is_process_control_not_anti_analysis_claim():
    caps = _caps(_report(symbols=["ptrace"]))
    assert "CAP.PROCESS_INJECTION.ELF_PTRACE.001" in caps
    assert not any(item.startswith("CAP.ANTI_ANALYSIS.") for item in caps)


def test_mmap_alone_is_memory_not_injection():
    caps = _caps(_report(symbols=["mmap", "mprotect"]))
    assert "CAP.MEMORY.ELF_MMAP.001" in caps
    assert "CAP.PROCESS_INJECTION.ELF_PTRACE.001" not in caps
    assert "CAP.PROCESS_INJECTION.ELF_PROCESS_VM.001" not in caps


def test_missing_imports_do_not_invent_capabilities():
    report = _report(needed=["libc.so.6"], symbols=[])
    assert report.composition["capabilities"] == []
    assert any(rel.type == "DEPENDS_ON" for rel in report.relationships)


def test_dt_needed_stays_depends_on_not_imports():
    report = _report(needed=["libcurl.so.4"], symbols=[("libcurl.so.4", "curl_easy_init")])
    types = {rel.type for rel in report.relationships}
    assert "DEPENDS_ON" in types
    assert "IMPORTS" not in types


def test_evidence_links_survive_from_observation_to_capability():
    report = _report(symbols=["fork"])
    cap = _caps(report)["CAP.PROCESS.ELF_FORK.001"]
    assert cap["refs"]["evidence_ids"]
    assert cap["refs"]["observation_ids"]
    evidence_ids = {item.id for item in report.evidence_store}
    observation_ids = {item.id for item in report.observations}
    assert set(cap["refs"]["evidence_ids"]) <= evidence_ids
    assert set(cap["refs"]["observation_ids"]) <= observation_ids
    assert any(obs.kind == "elf.import.function" for obs in report.observations)


def test_legacy_symbols_sample_reports_remain_compatible():
    report = _report(needed=["libc.so.6"], symbols=["fork", "execve"], legacy=True)
    payload = report.to_dict()
    restored = Report.from_dict(payload)
    restored.composition = compose(restored).to_dict()
    assert restored.schema_version == 1
    assert "CAP.PROCESS.ELF_FORK.001" in _caps(restored)
    assert "CAP.PROCESS.ELF_EXEC.001" in _caps(restored)


def test_completeness_records_elf_import_only_gap():
    report = _report(symbols=["socket"])
    gap_ids = [item["id"] for item in report.composition["gaps"]]
    assert "GAP.ELF.CAPABILITIES.IMPORTS_ONLY.001" in gap_ids


def test_rendered_report_shows_capability_evidence_and_confidence():
    report = _report(
        needed=["libcurl.so.4"],
        symbols=[("libcurl.so.4", "curl_easy_init"), ("libcurl.so.4", "curl_easy_perform")],
    )
    text = render_text(report)
    assert "libcurl HTTP/network client" in text
    assert "Evidence:" in text
    assert "curl_easy_perform" in text
    assert "Confidence: high" in text
    assert "ELF capability inference is based on static dynamic-symbol imports" in text


def test_collect_imported_functions_skips_defined_symbols():
    class FakeSymbol:
        def __init__(self, name, shndx="SHN_UNDEF", typ="STT_FUNC"):
            self.name = name
            self._data = {"st_shndx": shndx, "st_info": {"type": typ}}

        def __getitem__(self, key):
            return self._data[key]

    class FakeSection:
        def __init__(self, name, symbols):
            self.name = name
            self._symbols = symbols

        def iter_symbols(self):
            yield from self._symbols

    class FakeELF:
        def iter_sections(self):
            yield FakeSection(
                ".dynsym",
                [
                    FakeSymbol(""),
                    FakeSymbol("fork"),
                    FakeSymbol("curl_easy_init@GLIBC_2.2.5"),
                    FakeSymbol("defined_local", shndx=12),
                    FakeSymbol("stdin", typ="STT_OBJECT"),
                ],
            )
            yield FakeSection(".symtab", [FakeSymbol("local_func")])

        def get_section_by_name(self, name):
            return None

    imported = collect_imported_functions(FakeELF())
    names = {item["normalized_name"] for item in imported}
    assert names == {"fork", "curl_easy_init"}
    assert all(item["library"] == "unknown" for item in imported)


def test_collect_imported_functions_binds_gnu_version_library():
    class FakeSymbol:
        def __init__(self, name, shndx="SHN_UNDEF", typ="STT_FUNC"):
            self.name = name
            self._data = {"st_shndx": shndx, "st_info": {"type": typ}}

        def __getitem__(self, key):
            return self._data[key]

    class FakeSection:
        def __init__(self, name, symbols):
            self.name = name
            self._symbols = symbols

        def iter_symbols(self):
            yield from self._symbols

    class FakeVer:
        def __init__(self, ndx):
            self._ndx = ndx

        def __getitem__(self, key):
            if key == "ndx":
                return self._ndx
            raise KeyError(key)

    class FakeNeed:
        def __init__(self, filename):
            self.name = filename

    class FakeAux:
        def __init__(self, index, version):
            self.name = version
            self._index = index

        def __getitem__(self, key):
            if key == "vna_other":
                return self._index
            raise KeyError(key)

    class FakeVerNeed:
        def iter_versions(self):
            yield FakeNeed("libcurl.so.4"), iter([FakeAux(2, "CURL_OPENSSL_4")])

    class FakeVerSym:
        def iter_symbols(self):
            yield FakeVer("VER_NDX_LOCAL")
            yield FakeVer(2)

    class FakeELF:
        def iter_sections(self):
            yield FakeSection(".dynsym", [FakeSymbol(""), FakeSymbol("curl_easy_init")])

        def get_section_by_name(self, name):
            if name == ".gnu.version":
                return FakeVerSym()
            if name == ".gnu.version_r":
                return FakeVerNeed()
            return None

    imported = collect_imported_functions(FakeELF())
    assert imported == [
        {
            "name": "curl_easy_init",
            "normalized_name": "curl_easy_init",
            "library": "libcurl.so.4",
            "normalized_library": "libcurl.so",
            "version": "CURL_OPENSSL_4",
            "symbol_type": "STT_FUNC",
        }
    ]
