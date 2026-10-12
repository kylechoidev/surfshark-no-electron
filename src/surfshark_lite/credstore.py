"""Credential storage (`FileBackend` 0600, `SecretServiceBackend` via secret-tool, and official import)."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable

from surfshark_lite.errors import ErrorCode, SslError
from surfshark_lite.fsutil import atomic_write_json, file_lock, read_json_secure
from surfshark_lite.logs import mask_email

SAFE_PATH_ENV = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _subproc_env() -> dict[str, str]:
    env = {"LC_ALL": "C", "PATH": os.environ.get("PATH") or SAFE_PATH_ENV}
    for k in ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "DISPLAY", "HOME"):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


def iso_to_epoch(iso_str: str | None) -> float | None:
    if not iso_str or not isinstance(iso_str, str):
        return None
    try:
        s = iso_str.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


def epoch_to_iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Session:
    token: str
    renew_token: str
    obtained_at: float
    token_exp: float | None = None
    renew_exp: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "renew_token": self.renew_token,
            "obtained_at": epoch_to_iso(self.obtained_at),
            "token_exp": epoch_to_iso(self.token_exp),
            "renew_exp": epoch_to_iso(self.renew_exp),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "Session | None":
        if not isinstance(d, dict):
            return None
        tok = d.get("token")
        ren = d.get("renew_token")
        if not isinstance(tok, str) or not tok or len(tok) > 8192:
            return None
        if not isinstance(ren, str) or not ren or len(ren) > 8192:
            return None
        obt = iso_to_epoch(d.get("obtained_at"))
        if obt is None:
            obt = 0.0
        return cls(
            token=tok,
            renew_token=ren,
            obtained_at=obt,
            token_exp=iso_to_epoch(d.get("token_exp")),
            renew_exp=iso_to_epoch(d.get("renew_exp")),
        )


@dataclass(frozen=True)
class WireGuardKeyRecord:
    private_key: str
    public_key: str
    account_id: str | None = None
    key_id: str | None = None
    registered_at: float | None = None
    expires_at: float | None = None
    last_validated_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "private_key": self.private_key,
            "public_key": self.public_key,
            "account_id": self.account_id,
            "key_id": self.key_id,
            "registered_at": epoch_to_iso(self.registered_at),
            "expires_at": epoch_to_iso(self.expires_at),
            "last_validated_at": epoch_to_iso(self.last_validated_at),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "WireGuardKeyRecord | None":
        if not isinstance(d, dict):
            return None
        priv = d.get("private_key")
        pub = d.get("public_key")
        if not isinstance(priv, str) or not priv or not isinstance(pub, str) or not pub:
            return None
        return cls(
            private_key=priv,
            public_key=pub,
            account_id=d.get("account_id") if isinstance(d.get("account_id"), str) else None,
            key_id=d.get("key_id") if isinstance(d.get("key_id"), str) else None,
            registered_at=iso_to_epoch(d.get("registered_at")),
            expires_at=iso_to_epoch(d.get("expires_at")),
            last_validated_at=iso_to_epoch(d.get("last_validated_at")),
        )


@dataclass(frozen=True)
class StoredCredentials:
    email_hint: str | None = None
    user_id: str | None = None
    session: Session | None = None
    wireguard: WireGuardKeyRecord | None = None

    def to_dict(self, include_secrets: bool = True) -> dict[str, Any]:
        return {
            "schema": 1,
            "account": {
                "email_hint": self.email_hint,
                "user_id": self.user_id,
            },
            "session": self.session.to_dict() if (include_secrets and self.session) else None,
            "wireguard": self.wireguard.to_dict() if (include_secrets and self.wireguard) else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "StoredCredentials":
        if not isinstance(d, dict):
            return cls()
        acc = d.get("account") if isinstance(d.get("account"), dict) else {}
        hint = acc.get("email_hint")
        uid = acc.get("user_id")
        return cls(
            email_hint=hint if isinstance(hint, str) else None,
            user_id=uid if isinstance(uid, str) else None,
            session=Session.from_dict(d.get("session")),
            wireguard=WireGuardKeyRecord.from_dict(d.get("wireguard")),
        )


class SecretServiceUnavailableError(SslError):
    def __init__(self, message: str = "Secret Service keyring is locked or unavailable.") -> None:
        super().__init__(ErrorCode.INTERNAL, message, http_status=503)


class CredentialStore:
    """Manages reading and atomic updating of credentials via 0600 file or secret-tool."""

    def __init__(
        self,
        credentials_file: Path,
        lock_file: Path,
        backend: str = "file",
        which_fn: Callable[[str], str | None] = shutil.which,
    ) -> None:
        self.credentials_file = credentials_file
        self.lock_file = lock_file
        self.backend = backend
        self._which = which_fn

    def _secret_tool_store(self, secret_blob: str) -> None:
        bin_path = self._which("secret-tool")
        if not bin_path:
            raise SecretServiceUnavailableError("secret-tool binary not found (install libsecret-tools)")
        res = subprocess.run(
            [
                bin_path,
                "store",
                "--label=Surf Shark Ultra Lite",
                "service",
                "surfshark-ultralite",
                "account",
                "default",
            ],
            input=secret_blob.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5.0,
            shell=False,
            env=_subproc_env(),
        )
        if res.returncode != 0:
            raise SecretServiceUnavailableError("secret-tool store failed (keyring locked or unavailable)")

    def _secret_tool_lookup(self) -> dict[str, Any] | None:
        bin_path = self._which("secret-tool")
        if not bin_path:
            raise SecretServiceUnavailableError("secret-tool binary not found (install libsecret-tools)")
        res = subprocess.run(
            [
                bin_path,
                "lookup",
                "service",
                "surfshark-ultralite",
                "account",
                "default",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5.0,
            shell=False,
            env=_subproc_env(),
        )
        if res.returncode != 0:
            stderr_txt = res.stderr.decode("utf-8", errors="replace").strip()
            if stderr_txt:
                raise SecretServiceUnavailableError(f"secret-tool lookup failed: {stderr_txt}")
            return None
        raw = res.stdout.decode("utf-8", errors="replace").strip()
        if not raw:
            return None
        try:
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else None
        except ValueError as exc:
            raise SecretServiceUnavailableError("Corrupted JSON in Secret Service") from exc

    def _secret_tool_clear(self) -> None:
        bin_path = self._which("secret-tool")
        if not bin_path:
            return
        try:
            subprocess.run(
                [
                    bin_path,
                    "clear",
                    "service",
                    "surfshark-ultralite",
                    "account",
                    "default",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5.0,
                shell=False,
                env=_subproc_env(),
            )
        except Exception:
            pass

    def load(self) -> StoredCredentials:
        raw = read_json_secure(self.credentials_file, check_perms=True)
        base = StoredCredentials.from_dict(raw)
        if self.backend != "secret-service":
            return base
        sec = self._secret_tool_lookup()
        if not sec:
            return replace(base, session=None, wireguard=None)
        return StoredCredentials(
            email_hint=base.email_hint,
            user_id=base.user_id,
            session=Session.from_dict(sec.get("session")),
            wireguard=WireGuardKeyRecord.from_dict(sec.get("wireguard")),
        )

    def save(self, creds: StoredCredentials) -> None:
        if self.backend == "secret-service":
            sec_payload = json.dumps({
                "session": creds.session.to_dict() if creds.session else None,
                "wireguard": creds.wireguard.to_dict() if creds.wireguard else None,
            })
            self._secret_tool_store(sec_payload)
            atomic_write_json(
                self.credentials_file,
                creds.to_dict(include_secrets=False),
                mode=0o600,
                lock_path=self.lock_file,
            )
        else:
            atomic_write_json(
                self.credentials_file,
                creds.to_dict(include_secrets=True),
                mode=0o600,
                lock_path=self.lock_file,
            )

    def save_session(
        self,
        session: Session,
        *,
        email_hint: str | None = None,
        user_id: str | None = None,
    ) -> StoredCredentials:
        with file_lock(self.lock_file):
            raw = read_json_secure(self.credentials_file, check_perms=True)
            cur = StoredCredentials.from_dict(raw)
            if self.backend == "secret-service":
                sec = self._secret_tool_lookup() or {}
                cur = replace(cur, wireguard=WireGuardKeyRecord.from_dict(sec.get("wireguard")))
            updated = StoredCredentials(
                email_hint=email_hint if email_hint is not None else cur.email_hint,
                user_id=user_id if user_id is not None else cur.user_id,
                session=session,
                wireguard=cur.wireguard,
            )
            if self.backend == "secret-service":
                self._secret_tool_store(json.dumps({
                    "session": updated.session.to_dict() if updated.session else None,
                    "wireguard": updated.wireguard.to_dict() if updated.wireguard else None,
                }))
                atomic_write_json(self.credentials_file, updated.to_dict(include_secrets=False), mode=0o600)
            else:
                atomic_write_json(self.credentials_file, updated.to_dict(include_secrets=True), mode=0o600)
            return updated

    def save_wireguard(self, wg: WireGuardKeyRecord | None) -> StoredCredentials:
        with file_lock(self.lock_file):
            raw = read_json_secure(self.credentials_file, check_perms=True)
            cur = StoredCredentials.from_dict(raw)
            if self.backend == "secret-service":
                sec = self._secret_tool_lookup() or {}
                cur = replace(cur, session=Session.from_dict(sec.get("session")))
            updated = replace(cur, wireguard=wg)
            if self.backend == "secret-service":
                self._secret_tool_store(json.dumps({
                    "session": updated.session.to_dict() if updated.session else None,
                    "wireguard": updated.wireguard.to_dict() if updated.wireguard else None,
                }))
                atomic_write_json(self.credentials_file, updated.to_dict(include_secrets=False), mode=0o600)
            else:
                atomic_write_json(self.credentials_file, updated.to_dict(include_secrets=True), mode=0o600)
            return updated

    def wipe(self) -> None:
        if self.backend == "secret-service":
            self._secret_tool_clear()
        atomic_write_json(
            self.credentials_file,
            StoredCredentials().to_dict(include_secrets=False),
            mode=0o600,
            lock_path=self.lock_file,
        )


def import_official_surfshark_credentials(
    config_dir: Path | None = None,
    clock_now: float | None = None,
) -> StoredCredentials:
    """Import session and WireGuard keys from ~/.config/Surfshark/safe-storage.json or keyring.json."""
    now = clock_now if clock_now is not None else datetime.datetime.now(tz=datetime.timezone.utc).timestamp()
    ss_dir = config_dir or (Path.home() / ".config" / "Surfshark")
    safe_path = ss_dir / "safe-storage.json"
    keyring_path = ss_dir / "keyring.json"

    candidate_keys: list[bytes] = []
    st_bin = shutil.which("secret-tool")
    if st_bin:
        for svc in ("Surfshark", "surfshark"):
            try:
                res = subprocess.run(
                    [st_bin, "lookup", "service", svc, "account", "storage_key"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=3.0,
                    shell=False,
                    env=_subproc_env(),
                )
                if res.returncode == 0 and res.stdout.strip():
                    b64 = res.stdout.strip().decode("utf-8", errors="replace")
                    candidate_keys.append(base64.b64decode(b64))
                    candidate_keys.append(b64.encode("utf-8"))
            except Exception:
                pass
    if not candidate_keys:
        # Fallback to gir1.2-secret-1 via python3 subprocess when secret-tool CLI is not installed
        py_script = (
            "import gi; gi.require_version('Secret', '1'); from gi.repository import Secret; "
            "s = Secret.Schema.new('org.freedesktop.Secret.Generic', Secret.SchemaFlags.NONE, "
            "{'service': Secret.SchemaAttributeType.STRING, 'account': Secret.SchemaAttributeType.STRING}); "
            "pw = Secret.password_lookup_sync(s, {'service': 'Surfshark', 'account': 'storage_key'}, None); "
            "print(pw or '', end='')"
        )
        try:
            res = subprocess.run(
                ["/usr/bin/python3", "-c", py_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=3.0,
                shell=False,
                env=_subproc_env(),
            )
            if res.returncode == 0 and res.stdout.strip():
                b64 = res.stdout.strip().decode("utf-8", errors="replace")
                candidate_keys.append(base64.b64decode(b64))
                candidate_keys.append(b64.encode("utf-8"))
        except Exception:
            pass
    # Fallback key from official main.js j2()
    candidate_keys.append(b"WGtVd25SJmglS2MxUVkjXjdlCg==")

    openssl_bin = shutil.which("openssl")
    decrypted_obj: dict[str, Any] | None = None

    for path in (safe_path, keyring_path):
        if not path.is_file():
            continue
        raw_bytes = path.read_bytes()
        # Check if already plaintext JSON
        try:
            obj = json.loads(raw_bytes.decode("utf-8"))
            if isinstance(obj, dict) and "user_session" in obj:
                decrypted_obj = obj
                break
        except Exception:
            pass

        if len(raw_bytes) > 17 and raw_bytes[16:17] == b":" and openssl_bin:
            iv = raw_bytes[:16]
            ciphertext = raw_bytes[17:]
            salt = iv.decode("utf-8", errors="replace").encode("utf-8")
            for k_bytes in candidate_keys:
                derived = hashlib.pbkdf2_hmac("sha512", k_bytes, salt, 10000, 32)
                try:
                    proc = subprocess.run(
                        [
                            openssl_bin,
                            "enc",
                            "-d",
                            "-aes-256-cbc",
                            "-K",
                            derived.hex(),
                            "-iv",
                            iv.hex(),
                        ],
                        input=ciphertext,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        timeout=3.0,
                        shell=False,
                        env=_subproc_env(),
                    )
                    if proc.returncode == 0:
                        obj = json.loads(proc.stdout.decode("utf-8"))
                        if isinstance(obj, dict) and obj.get("user_session"):
                            decrypted_obj = obj
                            break
                except Exception:
                    continue
        if decrypted_obj:
            break

    if not decrypted_obj or not isinstance(decrypted_obj.get("user_session"), dict):
        raise SslError(
            ErrorCode.AUTH_REQUIRED,
            "No active session found in ~/.config/Surfshark. Please log in with email and password.",
        )

    us = decrypted_obj["user_session"]
    token = us.get("token")
    renew_token = us.get("renewToken")
    user_id = us.get("id")
    if not isinstance(token, str) or not token or not isinstance(renew_token, str) or not renew_token:
        raise SslError(ErrorCode.AUTH_REQUIRED, "Official Surfshark session does not contain valid tokens.")

    from surfshark_lite.auth import decode_jwt_exp

    sess = Session(
        token=token,
        renew_token=renew_token,
        obtained_at=now,
        token_exp=decode_jwt_exp(token),
        renew_exp=decode_jwt_exp(renew_token),
    )

    wg_priv = decrypted_obj.get("wg_priv")
    wg_pub = decrypted_obj.get("wg_pub")
    wg_rec: WireGuardKeyRecord | None = None
    if isinstance(wg_priv, str) and wg_priv and isinstance(wg_pub, str) and wg_pub:
        wg_rec = WireGuardKeyRecord(
            private_key=wg_priv,
            public_key=wg_pub,
            account_id=user_id if isinstance(user_id, str) else None,
            registered_at=now,
            last_validated_at=None,
        )

    return StoredCredentials(
        email_hint=None,
        user_id=user_id if isinstance(user_id, str) else None,
        session=sess,
        wireguard=wg_rec,
    )
