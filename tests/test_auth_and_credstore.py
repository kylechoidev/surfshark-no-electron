"""Unit tests for CredentialStore (0600 permissions, official import) and AuthEngine (2FA, 401 single-flight renew)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parent.parent / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from surfshark_lite.api import LoginHttpOutcome, TokenPair, UserAccountInfo
from surfshark_lite.auth import AuthEngine, AuthState, LoginNeedsOtp, LoginOk, TokenManager
from surfshark_lite.credstore import CredentialStore, Session, import_official_surfshark_credentials
from surfshark_lite.errors import (
    CredentialsInsecureError,
    NetworkError,
    OtpExpiredError,
    OtpInvalidError,
)
from surfshark_lite.httpclient import Response


class _MockSurfsharkAPI:
    def __init__(self) -> None:
        self.needs_otp = False
        self.otp_should_fail = False
        self.renew_calls = 0
        self.renew_network_error = False

        class _FakeHttp:
            clock_skew_s = 0.0

        self.http = _FakeHttp()

    def login(self, email: str, password: str) -> LoginHttpOutcome:
        return LoginHttpOutcome(
            tokens=TokenPair(token="interim-or-live-tok", renew_token="renew-tok-1"),
            needs_otp=self.needs_otp,
        )

    def verify_otp(self, interim_token: str, otp_code: str) -> TokenPair | None:
        if self.otp_should_fail:
            raise OtpInvalidError("Invalid 2FA code")
        return TokenPair(token="activated-tok", renew_token="activated-renew")

    def renew(self, renew_token: str) -> TokenPair:
        self.renew_calls += 1
        if self.renew_network_error:
            raise NetworkError("dns", "Temporary DNS failure")
        return TokenPair(token=f"fresh-tok-{self.renew_calls}", renew_token=f"fresh-renew-{self.renew_calls}")

    def raw_call_with_token(self, key: str, token: str, **kwargs) -> Response:
        return Response(200, {}, {"id": "u123", "email": "user@example.com"}, '{"id":"u123","email":"user@example.com"}', 5)

    def parse_me(self, resp: Response) -> UserAccountInfo:
        return UserAccountInfo(user_id="u123", external_id=None, email="user@example.com", technologies=())

    def logout(self, token: str) -> None:
        pass


class TestAuthAndCredstore(unittest.TestCase):
    def test_0600_permission_check_and_official_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            cred_file = p / "credentials.json"
            lock_file = p / "credentials.lock"
            store = CredentialStore(cred_file, lock_file)
            store.save_session(Session(token="tok1", renew_token="ren1", obtained_at=100.0), email_hint="u***@ex.com")

            # Broadening permissions to 0644 must trigger CredentialsInsecureError
            os.chmod(cred_file, 0o644)
            with self.assertRaises(CredentialsInsecureError):
                store.load()
            os.chmod(cred_file, 0o600)
            loaded = store.load()
            self.assertIsNotNone(loaded.session)
            assert loaded.session is not None
            self.assertEqual(loaded.session.token, "tok1")

            # Official ~/.config/Surfshark/safe-storage.json import
            off_dir = p / "Surfshark"
            off_dir.mkdir()
            (off_dir / "safe-storage.json").write_text(
                json.dumps({
                    "user_session": {"token": "off-jwt", "renewToken": "off-renew", "id": "u1"},
                    "wg_priv": "cHJpdi1rZXk=",
                    "wg_pub": "cHViLWtleQ==",
                }),
                encoding="utf-8",
            )
            imported = import_official_surfshark_credentials(config_dir=off_dir, clock_now=500.0)
            self.assertIsNotNone(imported.session)
            assert imported.session is not None
            self.assertEqual(imported.session.token, "off-jwt")
            self.assertIsNotNone(imported.wireguard)

    def test_2fa_login_and_5_attempt_lockout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            store = CredentialStore(p / "credentials.json", p / "credentials.lock")
            api = _MockSurfsharkAPI()
            api.needs_otp = True
            tm = TokenManager(store, api)  # type: ignore[arg-type]
            engine = AuthEngine(store, api, tm)  # type: ignore[arg-type]

            res = engine.login("alice@example.com", "pw123")
            self.assertIsInstance(res, LoginNeedsOtp)
            assert isinstance(res, LoginNeedsOtp)

            # 4 failed attempts raise OtpInvalidError, 5th raises OtpExpiredError
            api.otp_should_fail = True
            for _ in range(4):
                with self.assertRaises(OtpInvalidError):
                    engine.verify_otp(res.challenge_id, "000000")
            with self.assertRaises(OtpExpiredError):
                engine.verify_otp(res.challenge_id, "000000")

            # Fresh challenge succeeds on valid OTP
            res2 = engine.login("alice@example.com", "pw123")
            assert isinstance(res2, LoginNeedsOtp)
            api.otp_should_fail = False
            ok = engine.verify_otp(res2.challenge_id, "123456")
            self.assertIsInstance(ok, LoginOk)
            self.assertEqual(tm.state, AuthState.AUTHENTICATED)

    def test_token_manager_401_single_flight_and_network_error_preservation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            store = CredentialStore(p / "credentials.json", p / "credentials.lock")
            api = _MockSurfsharkAPI()
            tm = TokenManager(store, api)  # type: ignore[arg-type]
            tm.set_authenticated(Session(token="initial-tok", renew_token="initial-ren", obtained_at=100.0))

            # Simulate 401 followed by 200 after renewal
            seen_tokens: list[str] = []

            def _call(tok: str) -> Response:
                seen_tokens.append(tok)
                if tok == "initial-tok":
                    return Response(401, {}, b"", None, "https://api.surfshark.com/test")
                return Response(200, {}, b"{}", {}, "https://api.surfshark.com/test")

            resp = tm.request(_call)
            self.assertEqual(resp.status, 200)
            self.assertEqual(seen_tokens, ["initial-tok", "fresh-tok-1"])
            self.assertEqual(api.renew_calls, 1)

            # Transient NetworkError during renewal must preserve stored tokens and enter DEGRADED
            api.renew_network_error = True
            with self.assertRaises(NetworkError):
                tm.proactive_renew()
            self.assertEqual(tm.state, AuthState.DEGRADED)
            self.assertIsNotNone(tm.session)
            assert tm.session is not None
            self.assertEqual(tm.session.token, "fresh-tok-1")


if __name__ == "__main__":
    unittest.main()
