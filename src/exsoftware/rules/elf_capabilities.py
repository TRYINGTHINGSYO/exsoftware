"""Original ELF capability rules built from normalized static features.

These rules describe primitives a Linux/Unix binary can probably use based on
its dynamic imports and DT_NEEDED libraries. They are not malware verdicts and
do not claim runtime behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ELFCapabilityRule:
    id: str
    family: str
    title: str
    statement: str
    symbols_any: tuple[str, ...] = ()
    symbols_all: tuple[str, ...] = ()
    libraries_any: tuple[str, ...] = ()
    libraries_all: tuple[str, ...] = ()
    confidence: str = "medium"
    certainty: str = "inferred"
    explanation: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)


def normalize_elf_library_name(value: str | None) -> str:
    """Normalize a DT_NEEDED / versioned library name for matching."""
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return "unknown"
    leaf = text.rsplit("/", 1)[-1] or text
    lowered = leaf.lower()
    if ".so." in lowered:
        lowered = lowered.split(".so.", 1)[0] + ".so"
    return lowered


def normalize_elf_symbol_name(value: str | None) -> str | None:
    """Return a canonical ELF import symbol, or None for empty/unknown names."""
    text = str(value or "").strip()
    if not text or text == "unknown":
        return None
    if text.startswith("_GLOBAL_OFFSET_TABLE"):
        return None
    if "@@" in text:
        text = text.split("@@", 1)[0]
    elif "@" in text:
        text = text.split("@", 1)[0]
    return text or None


ELF_CAPABILITY_RULES: tuple[ELFCapabilityRule, ...] = (
    ELFCapabilityRule(
        "CAP.PROCESS.ELF_FORK.001",
        "PROCESS",
        "Process creation",
        "Contains imports that can create a new process.",
        symbols_any=("fork", "vfork", "clone", "posix_spawn", "posix_spawnp"),
        confidence="high",
        explanation="fork/clone/posix_spawn are direct primitives for starting another process.",
    ),
    ELFCapabilityRule(
        "CAP.PROCESS.ELF_EXEC.001",
        "PROCESS",
        "Execute another program",
        "Contains imports that can replace the current process image.",
        symbols_any=("execve", "execv", "execvp", "execl", "execlp", "execle", "fexecve", "execvpe"),
        confidence="high",
        explanation="exec* imports overlay a new program image in the current process.",
    ),
    ELFCapabilityRule(
        "CAP.SHELL.ELF_SYSTEM.001",
        "SHELL",
        "C library command execution",
        "Contains C library imports that can pass a command to the shell.",
        symbols_any=("system", "popen"),
        confidence="high",
        explanation="system/popen execute a shell command string.",
    ),
    ELFCapabilityRule(
        "CAP.DYNAMIC_LOADING.ELF_DLOPEN.001",
        "DYNAMIC_LOADING",
        "Dynamic library loading",
        "Contains imports that can load libraries or resolve symbols at runtime.",
        symbols_any=("dlopen", "dlsym", "dlmopen"),
        confidence="high",
        explanation="dlopen/dlsym can hide later code use from the static DT_NEEDED list.",
    ),
    ELFCapabilityRule(
        "CAP.NETWORK.ELF_SOCKET.001",
        "NETWORK",
        "Socket networking",
        "Contains imports that can create TCP/UDP network sockets.",
        symbols_any=("socket", "connect", "send", "recv", "sendto", "recvfrom", "bind", "listen", "accept"),
        confidence="high",
        explanation="BSD socket imports are direct network communication primitives.",
    ),
    ELFCapabilityRule(
        "CAP.NETWORK.ELF_DNS.001",
        "NETWORK",
        "DNS resolution",
        "Contains imports that can resolve host names.",
        symbols_any=("getaddrinfo", "gethostbyname", "getnameinfo"),
        confidence="high",
        explanation="Name-resolution imports resolve hosts before network communication.",
    ),
    ELFCapabilityRule(
        "CAP.NETWORK.ELF_LIBCURL.001",
        "NETWORK",
        "libcurl HTTP/network client",
        "Contains libcurl imports that can perform HTTP or other transfers.",
        symbols_any=("curl_easy_init", "curl_easy_perform", "curl_easy_setopt", "curl_multi_perform"),
        confidence="high",
        explanation="curl_easy_* imports are direct libcurl client primitives.",
    ),
    ELFCapabilityRule(
        "CAP.NETWORK.ELF_OPENSSL_TLS.001",
        "NETWORK",
        "OpenSSL TLS client/server",
        "Contains OpenSSL imports that can establish a TLS session.",
        symbols_any=("SSL_connect", "SSL_accept", "SSL_read", "SSL_write", "SSL_new"),
        confidence="high",
        explanation="SSL_* imports are direct TLS session primitives.",
    ),
    ELFCapabilityRule(
        "CAP.FILESYSTEM.ELF_OPEN_WRITE.001",
        "FILESYSTEM",
        "File creation or modification",
        "Contains imports that can create, open, rename, or remove filesystem entries.",
        symbols_any=("open", "openat", "creat", "unlink", "unlinkat", "rename", "renameat", "mkdir", "mkdirat"),
        confidence="high",
        explanation="These POSIX file APIs can create, open, rename, or delete files; arguments determine the exact operation.",
    ),
    ELFCapabilityRule(
        "CAP.MEMORY.ELF_MMAP.001",
        "MEMORY",
        "Map or protect memory",
        "Contains imports that can map files/anonymous pages or change memory protections.",
        symbols_any=("mmap", "mmap64", "mprotect", "munmap"),
        confidence="medium",
        explanation="mmap/mprotect can make memory writable/executable, but legitimate loaders use them too.",
    ),
    ELFCapabilityRule(
        "CAP.PROCESS_INJECTION.ELF_PTRACE.001",
        "PROCESS_INJECTION",
        "Trace or control another process",
        "Contains ptrace imports that can inspect or modify another process.",
        symbols_any=("ptrace",),
        confidence="high",
        explanation="ptrace is the standard Linux primitive for debugging or injecting into another process.",
    ),
    ELFCapabilityRule(
        "CAP.PROCESS_INJECTION.ELF_PROCESS_VM.001",
        "PROCESS_INJECTION",
        "Read or write another process's memory",
        "Contains imports that can copy bytes into or out of another process.",
        symbols_any=("process_vm_writev", "process_vm_readv"),
        confidence="high",
        explanation="process_vm_readv/writev are direct remote-memory primitives.",
    ),
    ELFCapabilityRule(
        "CAP.PRIVILEGE.ELF_SETUID.001",
        "PRIVILEGE",
        "Change process credentials",
        "Contains imports that can change user or group IDs.",
        symbols_any=("setuid", "seteuid", "setgid", "setegid", "setresuid", "setresgid"),
        confidence="high",
        explanation="setuid/setgid-family calls change the process identity.",
    ),
    ELFCapabilityRule(
        "CAP.CRYPTOGRAPHY.ELF_OPENSSL_EVP.001",
        "CRYPTOGRAPHY",
        "OpenSSL cryptography",
        "Contains libcrypto/OpenSSL imports that can encrypt or digest data.",
        symbols_any=("EVP_EncryptInit", "EVP_EncryptInit_ex", "EVP_DecryptInit_ex", "AES_encrypt", "SHA256_Init"),
        confidence="high",
        explanation="OpenSSL EVP/AES/SHA imports are direct cryptographic primitives.",
    ),
)
