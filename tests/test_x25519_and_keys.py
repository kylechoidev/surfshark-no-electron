"""Unit tests for RFC 7748 Curve25519 scalar multiplication and WireGuard KeyManager."""

from __future__ import annotations

import base64
import os
import sys
import tempfile
import unittest
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parent.parent / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from surfshark_lite import x25519
from surfshark_lite.credstore import CredentialStore, Session
from surfshark_lite.httpclient import Response
from surfshark_lite.keys import (
    KeyManager,
    _HAS_CRYPTOGRAPHY,
    clamp_private_key_bytes,
    derive_public_key_cryptography,
    derive_public_key_pure_python,
    generate_keypair,
)


class _FakeTokenMgr:
    def request(self, fn):
        return fn("fake-jwt-token")


class _FakeApi:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.validate_status = 200
        self.register_status = 200

    def raw_call_with_token(self, endpoint_key: str, token: str, *, json_body=None, anycast: bool = False) -> Response:
        self.calls.append((endpoint_key, json_body or {}))
        if endpoint_key == "key_validate":
            return Response(
                status=self.validate_status,
                headers={},
                json_data={"expiresAt": "2030-01-01T00:00:00Z", "id": "k1"} if self.validate_status == 200 else {},
                raw_text='{"expiresAt":"2030-01-01T00:00:00Z","id":"k1"}',
                elapsed_ms=10,
            )
        return Response(
            status=self.register_status,
            headers={},
            json_data={"expiresAt": "2030-01-01T00:00:00Z", "id": "k2"} if self.register_status in (200, 201) else {},
            raw_text='{"expiresAt":"2030-01-01T00:00:00Z","id":"k2"}',
            elapsed_ms=10,
        )


class TestX25519AndKeys(unittest.TestCase):
    def test_rfc7748_vector_and_cross_backend_equivalence(self) -> None:
        scalar = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        expected_pub = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        self.assertEqual(x25519.public_key(scalar), expected_pub)

        for _ in range(5):
            raw = clamp_private_key_bytes(os.urandom(32))
            pure_pub = derive_public_key_pure_python(raw)
            self.assertEqual(len(pure_pub), 44)
            self.assertEqual(len(base64.b64decode(pure_pub)), 32)
            if _HAS_CRYPTOGRAPHY:
                self.assertEqual(pure_pub, derive_public_key_cryptography(raw))

    def test_key_manager_generates_and_revalidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            store = CredentialStore(p / "credentials.json", p / "credentials.lock")
            store.save_session(Session(token="t", renew_token="r", obtained_at=1000.0), user_id="u1")

            api = _FakeApi()
            km = KeyManager(store, _FakeTokenMgr(), api, clock=lambda: 1000.0)  # type: ignore[arg-type]

            rec1 = km.ensure_registered()
            self.assertEqual(len(rec1.public_key), 44)
            self.assertEqual([c[0] for c in api.calls], ["key_register"])

            # Subsequent call within max_age uses cached record without network call
            api.calls.clear()
            rec2 = km.ensure_registered()
            self.assertEqual(rec1.public_key, rec2.public_key)
            self.assertEqual(api.calls, [])

            # Force revalidate calls key_validate
            rec3 = km.force_revalidate_or_rotate()
            self.assertEqual(rec3.public_key, rec1.public_key)
            self.assertEqual([c[0] for c in api.calls], ["key_validate"])


if __name__ == "__main__":
    unittest.main()
