"""Secret resolution for device credentials.

Passwords are never meant to live in inventory.yaml. Inventory holds a
*reference* that is resolved at runtime:

    env:FG_PASSWORD          environment variable
    ${FG_PASSWORD}           environment variable (inline form)
    file:C:\\secrets\\fg.txt   first line of a file
    wincred:netaudit/fg-01   Windows Credential Manager (generic credential)
    keyring:netaudit/fg-01   keyring package (service/username)
    prompt                   interactive prompt (not for scheduled runs)

A `.env` file in the working directory is loaded automatically (existing
environment variables always win).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, replace
from getpass import getpass
from pathlib import Path

from netaudit.models import Device

DEFAULT_ENV_FILE = ".env"
_ENV_INLINE_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
# Env var checked when inventory leaves the password empty
_ENV_NAME_TEMPLATE = "NETAUDIT_{name}_PASSWORD"
_ENABLE_ENV_NAME_TEMPLATE = "NETAUDIT_{name}_ENABLE_PASSWORD"


class SecretError(Exception):
    """Raised when a secret reference cannot be resolved."""


@dataclass
class SecretStatus:
    """Where a single credential came from (never holds the secret itself)."""

    device: str
    field: str
    reference: str
    source: str  # env | file | wincred | keyring | prompt | inline | auto-env | missing
    resolved: bool
    detail: str = ""

    @property
    def inline_plaintext(self) -> bool:
        return self.source == "inline"


def load_env_file(path: str | Path = DEFAULT_ENV_FILE) -> dict[str, str]:
    """Load KEY=VALUE pairs from a .env file without overwriting real env vars."""
    p = Path(path)
    loaded: dict[str, str] = {}
    if not p.exists():
        return loaded

    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if not key:
            continue
        loaded[key] = value
        os.environ.setdefault(key, value)
    return loaded


def _read_file_secret(path: str) -> str:
    p = Path(path).expanduser()
    if not p.exists():
        raise SecretError(f"secret file not found: {p}")
    text = p.read_text(encoding="utf-8")
    first = text.splitlines()[0] if text.splitlines() else ""
    if not first.strip():
        raise SecretError(f"secret file is empty: {p}")
    return first.strip()


def _read_wincred(target: str) -> str:
    """Read a generic credential from Windows Credential Manager."""
    if os.name != "nt":
        raise SecretError("wincred: is only available on Windows")

    import ctypes
    from ctypes import wintypes

    class _Credential(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    cred_read = advapi32.CredReadW
    cred_read.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(_Credential)),
    ]
    cred_read.restype = wintypes.BOOL
    cred_free = advapi32.CredFree
    cred_free.argtypes = [ctypes.c_void_p]

    cred_type_generic = 1
    pcred = ctypes.POINTER(_Credential)()
    if not cred_read(target, cred_type_generic, 0, ctypes.byref(pcred)):
        err = ctypes.get_last_error()
        raise SecretError(f"credential '{target}' not found in Credential Manager (err {err})")

    try:
        cred = pcred.contents
        blob = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
    finally:
        cred_free(pcred)

    if not blob:
        raise SecretError(f"credential '{target}' has an empty secret")
    # cmdkey / CredWrite store UTF-16LE; other writers may use UTF-8.
    if len(blob) >= 2 and blob[1] == 0:
        return blob.decode("utf-16-le").rstrip("\x00")
    return blob.decode("utf-8", errors="replace").rstrip("\x00")


def _read_keyring(reference: str) -> str:
    try:
        import keyring  # type: ignore[import-not-found]
    except ImportError as exc:
        raise SecretError("keyring: requires the 'keyring' package (pip install keyring)") from exc

    parts = re.split(r"[/:]", reference, maxsplit=1)
    if len(parts) != 2 or not all(parts):
        raise SecretError("keyring: expects keyring:SERVICE/USERNAME")
    service, username = parts
    value = keyring.get_password(service, username)
    if not value:
        raise SecretError(f"keyring: no secret for {service}/{username}")
    return value


def _resolve_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SecretError(f"environment variable {name} is not set")
    return value


def resolve_secret(reference: str, *, allow_prompt: bool = False, label: str = "") -> tuple[str, str]:
    """Resolve one reference. Returns (secret, source)."""
    ref = (reference or "").strip()
    if not ref:
        raise SecretError("empty secret reference")

    inline = _ENV_INLINE_RE.fullmatch(ref)
    if inline:
        return _resolve_env(inline.group(1)), "env"

    scheme, _, rest = ref.partition(":")
    scheme = scheme.lower()
    rest = rest.strip()

    if scheme == "env":
        if not rest:
            raise SecretError("env: expects env:VARIABLE_NAME")
        return _resolve_env(rest), "env"
    if scheme == "file":
        if not rest:
            raise SecretError("file: expects file:PATH")
        return _read_file_secret(rest), "file"
    if scheme == "wincred":
        if not rest:
            raise SecretError("wincred: expects wincred:TARGET")
        return _read_wincred(rest), "wincred"
    if scheme == "keyring":
        return _read_keyring(rest), "keyring"
    if ref.lower() == "prompt" or scheme == "prompt":
        if not allow_prompt:
            raise SecretError("prompt is not available in non-interactive runs")
        text = rest or label or "password"
        value = getpass(f"{text}: ")
        if not value:
            raise SecretError("empty value entered at prompt")
        return value, "prompt"

    # Anything else is a literal password committed in the inventory.
    return ref, "inline"


def _auto_env_name(device_name: str, template: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", device_name).strip("_").upper()
    return template.format(name=slug)


def _resolve_field(
    device_name: str,
    field: str,
    reference: str,
    auto_env: str,
    *,
    required: bool,
    allow_prompt: bool,
) -> tuple[str, SecretStatus]:
    if not (reference or "").strip():
        value = os.environ.get(auto_env)
        if value:
            return value, SecretStatus(
                device=device_name,
                field=field,
                reference=f"env:{auto_env}",
                source="auto-env",
                resolved=True,
                detail=f"picked up {auto_env}",
            )
        return "", SecretStatus(
            device=device_name,
            field=field,
            reference="",
            source="missing" if required else "unset",
            resolved=not required,
            detail=f"set {auto_env} or a reference in inventory" if required else "not configured",
        )

    try:
        value, source = resolve_secret(
            reference, allow_prompt=allow_prompt, label=f"{device_name} {field}"
        )
    except SecretError as exc:
        return "", SecretStatus(
            device=device_name,
            field=field,
            reference=reference,
            source="missing",
            resolved=False,
            detail=str(exc),
        )

    return value, SecretStatus(
        device=device_name,
        field=field,
        reference=reference,
        source=source,
        resolved=True,
        detail="literal value in inventory" if source == "inline" else "",
    )


def resolve_device_secrets(
    device: Device,
    *,
    allow_prompt: bool = False,
) -> tuple[Device, list[SecretStatus]]:
    """Return a copy of the device with resolved credentials plus a status report."""
    password, pw_status = _resolve_field(
        device.name,
        "password",
        device.password,
        _auto_env_name(device.name, _ENV_NAME_TEMPLATE),
        required=True,
        allow_prompt=allow_prompt,
    )
    enable_password, enable_status = _resolve_field(
        device.name,
        "enable_password",
        device.enable_password,
        _auto_env_name(device.name, _ENABLE_ENV_NAME_TEMPLATE),
        required=False,
        allow_prompt=allow_prompt,
    )

    resolved = replace(device, password=password, enable_password=enable_password)
    return resolved, [pw_status, enable_status]


def resolve_inventory_secrets(
    devices: list[Device],
    *,
    allow_prompt: bool = False,
) -> tuple[list[Device], list[SecretStatus]]:
    resolved: list[Device] = []
    statuses: list[SecretStatus] = []
    for device in devices:
        dev, status = resolve_device_secrets(device, allow_prompt=allow_prompt)
        resolved.append(dev)
        statuses.extend(status)
    return resolved, statuses
