"""WireGuard keypair generation (3 backends) and KeyManager registration lifecycle."""

from __future__ import annotations

import base64
import logging
import os
import shutil
import subprocess
import time
from typing import Callable

from surfshark_lite import x25519
from surfshark_lite.api import SurfsharkAPI
from surfshark_lite. auth import TokenManager
from surfshark_lite.credstore import CredentialStore, WireGuardKeyRecord, iso_to_epoch
from surfshark_lite.errors import ApiStatusError, ErrorCode, SslError

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

log = logging.getLogger("surfshark_lite.keys")
SAFE_PATH_ENV = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
DEFAULT_KEY_TTL_S = 7 * 86400.0  # 7 days default if API omits expiresAt


def clamp_private_key_bytes(raw: bytes) -> bytes:
    if len(raw) != 32:
        raise ValueError("WireGuard private key must be 32 bytes")
    b = bytearray(raw)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def derive_public_key_cryptography(priv_bytes: bytes) -> str:
    if not _HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography backend not installed")
    clamped = clamp_private_key_bytes(priv_bytes)
    priv_obj = X25519PrivateKey.from_private_bytes(clamped)
    pub_bytes = priv_obj.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(pub_bytes).decode("ascii")


def derive_public_key_wg_cli(priv_bytes: bytes, which_fn: Callable[[str], str | None] = shutil.which) -> str:
    wg_bin = which_fn("wg")
    if not wg_bin:
        raise RuntimeError("wg binary not found")
    priv_b64 = base64.b64encode(clamp_private_key_bytes(priv_bytes)).decode("ascii")
    res = subprocess.run(
        [wg_bin, "pubkey"],
        input=(priv_b64 + "\n").encode("ascii"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3.0,
        shell=False,
        env={"LC_ALL": "C", "PATH": os.environ.get("PATH") or SAFE_PATH_ENV},
    )
    if res.returncode != 0:
        raise RuntimeError("wg pubkey command failed")
    out = res.stdout.decode("ascii").strip()
    if len(out) != 44 or not out.endswith("="):
        raise RuntimeError("wg pubkey returned malformed output")
    return out


def derive_public_key_pure_python(priv_bytes: bytes) -> str:
    clamped = clamp_private_key_bytes(priv_bytes)
    pub_bytes = x25519.public_key(clamped)
    return base64.b64encode(pub_bytes).decode("ascii")


def derive_public_key(priv_b64: str) -> str:
    """Derive WireGuard public key using first available backend: cryptography -> wg CLI -> pure Python."""
    priv_bytes = clamp_private_key_bytes(base64.b64decode(priv_b64))
    if _HAS_CRYPTOGRAPHY:
        try:
            return derive_public_key_cryptography(priv_bytes)
        except Exception:
            pass
    try:
        return derive_public_key_wg_cli(priv_bytes)
    except Exception:
        pass
    return derive_public_key_pure_python(priv_bytes)


def generate_keypair() -> tuple[str, str]:
    """Generate a new (private_key_b64, public_key_b64) WireGuard keypair."""
    raw = clamp_private_key_bytes(os.urandom(32))
    priv_b64 = base64.b64encode(raw).decode("ascii")
    pub_b64 = derive_public_key(priv_b64)
    return priv_b64, pub_b64


class KeyManager:
    """Manages WireGuard key registration, validation, and rotation against Surfshark API."""

    def __init__(
        self,
        store: CredentialStore,
        token_mgr: TokenManager,
        api: SurfsharkAPI,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.token_mgr = token_mgr
        self.api = api
        self._clock = clock

    def _validate_remote(self, pub_key: str, *, anycast: bool = False) -> tuple[bool, float | None, str | None]:
        resp = self.token_mgr.request(
            lambda tok: self.api.raw_call_with_token(
                "key_validate",
                tok,
                json_body={"pubKey": pub_key},
                anycast=anycast,
            )
        )
        if resp.ok:
            exp_ts: float | None = None
            key_id: str | None = None
            if isinstance(resp.json_data, dict):
                exp_ts = iso_to_epoch(resp.json_data.get("expiresAt"))
                kid = resp.json_data.get("id")
                key_id = str(kid) if kid is not None else None
            return True, exp_ts, key_id
        if resp.status in (400, 404):
            return False, None, None
        raise ApiStatusError(resp.status, f"Key validation failed with HTTP {resp.status}")

    def _register_remote(self, pub_key: str, *, anycast: bool = False) -> tuple[float | None, str | None]:
        resp = self.token_mgr.request(
            lambda tok: self.api.raw_call_with_token(
                "key_register",
                tok,
                json_body={"pubKey": pub_key},
                anycast=anycast,
            )
        )
        now = self._clock()
        if resp.ok:
            exp_ts: float | None = None
            key_id: str | None = None
            if isinstance(resp.json_data, dict):
                exp_ts = iso_to_epoch(resp.json_data.get("expiresAt"))
                kid = resp.json_data.get("id")
                key_id = str(kid) if kid is not None else None
            return exp_ts or (now + DEFAULT_KEY_TTL_S), key_id
        if resp.status == 409:
            # Already registered -> validate to learn expiry
            ok, exp_ts, key_id = self._validate_remote(pub_key, anycast=anycast)
            if ok:
                return exp_ts or (now + DEFAULT_KEY_TTL_S), key_id
        raise SslError(ErrorCode.KEY_REJECTED, f"WireGuard public key registration rejected (HTTP {resp.status})")

    def ensure_registered(self, max_age: float = 86400.0, *, anycast: bool = False) -> WireGuardKeyRecord:
        """Ensure a valid WireGuard keypair is registered for the current account."""
        creds = self.store.load()
        now = self._clock()
        rec = creds.wireguard
        account_id = creds.user_id

        needs_fresh = (
            rec is None
            or not rec.private_key
            or not rec.public_key
            or (account_id and rec.account_id and rec.account_id != account_id)
        )

        if not needs_fresh and rec is not None:
            age_ok = rec.last_validated_at is not None and (now - rec.last_validated_at) < max_age
            exp_ok = rec.expires_at is None or (rec.expires_at - now) >= 7 * 86400.0
            if age_ok and exp_ok:
                return rec

            # Validate existing key first
            ok, exp_ts, key_id = self._validate_remote(rec.public_key, anycast=anycast)
            if ok and (exp_ts is None or (exp_ts - now) >= 7 * 86400.0):
                updated = WireGuardKeyRecord(
                    private_key=rec.private_key,
                    public_key=rec.public_key,
                    account_id=account_id or rec.account_id,
                    key_id=key_id or rec.key_id,
                    registered_at=rec.registered_at or now,
                    expires_at=exp_ts or rec.expires_at,
                    last_validated_at=now,
                )
                self.store.save_wireguard(updated)
                return updated

            # Re-register the same key
            try:
                exp_ts, key_id = self._register_remote(rec.public_key, anycast=anycast)
                updated = WireGuardKeyRecord(
                    private_key=rec.private_key,
                    public_key=rec.public_key,
                    account_id=account_id or rec.account_id,
                    key_id=key_id or rec.key_id,
                    registered_at=now,
                    expires_at=exp_ts,
                    last_validated_at=now,
                )
                self.store.save_wireguard(updated)
                log.info("Re-registered existing WireGuard public key")
                return updated
            except SslError:
                log.warning("Existing WireGuard key rejected; rotating to a fresh keypair")

        # Generate and register a fresh keypair
        priv_b64, pub_b64 = generate_keypair()
        exp_ts, key_id = self._register_remote(pub_b64, anycast=anycast)
        fresh = WireGuardKeyRecord(
            private_key=priv_b64,
            public_key=pub_b64,
            account_id=account_id,
            key_id=key_id,
            registered_at=now,
            expires_at=exp_ts,
            last_validated_at=now,
        )
        self.store.save_wireguard(fresh)
        log.info("Generated and registered fresh WireGuard keypair")
        return fresh

    def force_revalidate_or_rotate(self, *, anycast: bool = False) -> WireGuardKeyRecord:
        """Used by Watchdog L3: validate key immediately and re-register/rotate if needed."""
        return self.ensure_registered(max_age=0.0, anycast=anycast)
