"""Authentication engine, 401 single-flight TokenManager, and OTP challenge management."""

from __future__ import annotations

import base64
import enum
import json
import logging
import random
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

from surfshark_lite.api import SurfsharkAPI, TokenPair
from surfshark_lite.credstore import (
    CredentialStore,
    SecretServiceUnavailableError,
    Session,
    StoredCredentials,
    epoch_to_iso,
    import_official_surfshark_credentials,
)
from surfshark_lite.errors import (
    ApiStatusError,
    AuthRequiredError,
    NetworkError,
    OtpExpiredError,
    OtpInvalidError,
    ReauthRequiredError,
)
from surfshark_lite.httpclient import Response
from surfshark_lite.logs import mask_email

log = logging.getLogger("surfshark_lite.auth")
_OTP_RE = re.compile(r"^\d{6,8}$")
DEGRADED_BACKOFF_STEPS = (30.0, 60.0, 120.0, 300.0, 600.0, 1800.0)


class AuthState(str, enum.Enum):
    LOGGED_OUT = "logged_out"
    AUTHENTICATED = "authenticated"
    DEGRADED = "degraded"
    REAUTH_REQUIRED = "reauth_required"
    UNAVAILABLE = "unavailable"


@dataclass
class OtpChallenge:
    challenge_id: str
    interim_token: str
    renew_token: str
    email_hint: str | None
    created_mono: float
    ttl_s: float = 300.0
    attempts: int = 0


@dataclass(frozen=True)
class LoginOk:
    account_hint: str | None
    user_id: str | None = None


@dataclass(frozen=True)
class LoginNeedsOtp:
    challenge_id: str
    method_hint: str | None = "totp"


LoginResult = LoginOk | LoginNeedsOtp


def decode_jwt_exp(token: str | None) -> float | None:
    """Decode JWT 'exp' claim without verifying signature (for proactive scheduling/display only)."""
    if not token or not isinstance(token, str) or token.count(".") != 2:
        return None
    try:
        middle = token.split(".")[1]
        padded = middle + "=" * (-len(middle) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        if isinstance(payload, dict) and isinstance(payload.get("exp"), (int, float)):
            return float(payload["exp"])
    except Exception:
        return None
    return None


def make_session(pair: TokenPair, now: float) -> Session:
    return Session(
        token=pair.token,
        renew_token=pair.renew_token,
        obtained_at=now,
        token_exp=decode_jwt_exp(pair.token),
        renew_exp=decode_jwt_exp(pair.renew_token),
    )


class TokenManager:
    """Serializes token renewals (single-flight), persists before swapping, and never drops tokens on NetworkError."""

    def __init__(
        self,
        store: CredentialStore,
        api: SurfsharkAPI,
        clock: Callable[[], float] = time.time,
        on_state_change: Callable[[AuthState, str | None], None] | None = None,
    ) -> None:
        self.store = store
        self.api = api
        self._clock = clock
        self._on_state_change = on_state_change
        self._lock = threading.Lock()
        self._session: Session | None = None
        self._state: AuthState = AuthState.LOGGED_OUT
        self._last_error: str | None = None
        self._degraded_step: int = 0
        self._email_hint: str | None = None
        self._user_id: str | None = None

    @property
    def state(self) -> AuthState:
        return self._state

    @property
    def last_error(self) -> str | None:
        return self._last_error

    @property
    def session(self) -> Session | None:
        return self._session

    @property
    def email_hint(self) -> str | None:
        return self._email_hint

    def _set_state(self, new_state: AuthState, error_msg: str | None = None) -> None:
        changed = (new_state != self._state) or (error_msg != self._last_error)
        self._state = new_state
        self._last_error = error_msg
        if changed and self._on_state_change:
            try:
                self._on_state_change(new_state, error_msg)
            except Exception:
                pass

    def load_from_store(self) -> AuthState:
        try:
            creds = self.store.load()
        except SecretServiceUnavailableError as exc:
            self._session = None
            self._set_state(AuthState.UNAVAILABLE, exc.message)
            return self._state

        self._email_hint = creds.email_hint
        self._user_id = creds.user_id
        self._session = creds.session
        if self._session is not None:
            self._degraded_step = 0
            self._set_state(AuthState.AUTHENTICATED, None)
        else:
            self._set_state(AuthState.LOGGED_OUT, None)
        return self._state

    def set_authenticated(self, session: Session, *, email_hint: str | None = None, user_id: str | None = None) -> None:
        with self._lock:
            saved = self.store.save_session(session, email_hint=email_hint, user_id=user_id)
            self._session = saved.session
            self._email_hint = saved.email_hint
            self._user_id = saved.user_id
            self._degraded_step = 0
            self._set_state(AuthState.AUTHENTICATED, None)

    def clear_session(self) -> None:
        with self._lock:
            self.store.wipe()
            self._session = None
            self._email_hint = None
            self._user_id = None
            self._degraded_step = 0
            self._set_state(AuthState.LOGGED_OUT, None)

    def _require_session(self) -> Session:
        if self._state == AuthState.REAUTH_REQUIRED:
            raise ReauthRequiredError(self._last_error or "Session expired. Please log in again.")
        if self._session is None:
            raise AuthRequiredError()
        return self._session

    def request(self, call: Callable[[str], Response]) -> Response:
        """Execute an authenticated API call with 401 interception and single-flight renewal."""
        s = self._require_session()
        resp = call(s.token)
        if resp.status != 401:
            return resp
        fresh = self._renew(seen=s)
        resp = call(fresh.token)
        if resp.status == 401:
            self._set_state(AuthState.REAUTH_REQUIRED, "Token rejected immediately after renewal.")
            raise ReauthRequiredError()
        return resp

    def proactive_renew(self) -> Session:
        """Trigger a proactive renewal of the current session."""
        s = self._require_session()
        return self._renew(seen=s)

    def _renew(self, seen: Session) -> Session:
        with self._lock:
            if self._session is not None and self._session is not seen:
                return self._session

            try:
                pair = self.api.renew(seen.renew_token)
            except ApiStatusError as exc:
                if exc.status in (400, 401, 403):
                    msg = "Session expired or revoked (HTTP {})".format(exc.status)
                    self._set_state(AuthState.REAUTH_REQUIRED, msg)
                    raise ReauthRequiredError(msg) from None
                self._degraded_step = min(self._degraded_step + 1, len(DEGRADED_BACKOFF_STEPS) - 1)
                self._set_state(AuthState.DEGRADED, exc.message)
                raise
            except NetworkError as exc:
                # KEEP tokens on transient network errors!
                self._degraded_step = min(self._degraded_step + 1, len(DEGRADED_BACKOFF_STEPS) - 1)
                self._set_state(AuthState.DEGRADED, exc.message)
                raise
            except Exception as exc:
                self._degraded_step = min(self._degraded_step + 1, len(DEGRADED_BACKOFF_STEPS) - 1)
                self._set_state(AuthState.DEGRADED, str(exc))
                raise

            new_sess = make_session(pair, self._clock())
            # 1. PERSIST FIRST (atomic fsync + rename)
            self.store.save_session(new_sess)
            # 2. THEN swap in memory
            self._session = new_sess
            self._degraded_step = 0
            self._set_state(AuthState.AUTHENTICATED, None)
            log.info("Renewed authentication session token")
            return new_sess

    def next_renew_delay_s(self, jitter_fn: Callable[[float, float], float] = random.uniform) -> float | None:
        """Compute seconds until next proactive token renewal."""
        if self._state not in (AuthState.AUTHENTICATED, AuthState.DEGRADED) or self._session is None:
            return None

        if self._state == AuthState.DEGRADED:
            base = DEGRADED_BACKOFF_STEPS[min(self._degraded_step, len(DEGRADED_BACKOFF_STEPS) - 1)]
            return max(5.0, base * jitter_fn(0.9, 1.1))

        now = self._clock() + self.api.http.clock_skew_s
        s = self._session
        if s.token_exp is not None:
            lifetime = max(300.0, s.token_exp - s.obtained_at)
            margin = max(600.0, 0.2 * lifetime)
            target_ts = max(now + 60.0, s.token_exp - margin)
            return max(60.0, target_ts - now)

        # Unknown token_exp: renew every 12h +/- 10% jitter, or immediately on start if older than 12h
        age = max(0.0, now - s.obtained_at)
        interval = 12 * 3600.0 * jitter_fn(0.9, 1.1)
        if age >= 12 * 3600.0:
            return 5.0
        return max(60.0, interval - age)


class AuthEngine:
    """High-level authentication flows: email/password, 2FA OTP, remote code, and official import."""

    def __init__(
        self,
        store: CredentialStore,
        api: SurfsharkAPI,
        token_mgr: TokenManager,
        clock: Callable[[], float] = time.time,
        mono_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.store = store
        self.api = api
        self.token_mgr = token_mgr
        self._clock = clock
        self._mono = mono_clock
        self._challenges: dict[str, OtpChallenge] = {}
        self._lock = threading.Lock()

    def _finalize_account(self, session: Session, email_hint: str | None) -> LoginOk:
        user_id: str | None = None
        try:
            resp = self.api.raw_call_with_token("me", session.token)
            if resp.ok:
                info = self.api.parse_me(resp)
                user_id = info.user_id
                if not email_hint and info.email:
                    email_hint = mask_email(info.email)
        except Exception:
            pass
        self.token_mgr.set_authenticated(session, email_hint=email_hint, user_id=user_id)
        return LoginOk(account_hint=self.token_mgr.email_hint, user_id=user_id)

    def login(self, email: str, password: str) -> LoginResult:
        email = email.strip()
        hint = mask_email(email)
        outcome = self.api.login(email, password)
        if not outcome.needs_otp:
            sess = make_session(outcome.tokens, self._clock())
            res = self._finalize_account(sess, hint)
            log.info("Logged in successfully (%s)", res.account_hint or "account")
            return res

        cid = secrets.token_urlsafe(16)
        ch = OtpChallenge(
            challenge_id=cid,
            interim_token=outcome.tokens.token,
            renew_token=outcome.tokens.renew_token,
            email_hint=hint,
            created_mono=self._mono(),
        )
        with self._lock:
            # Purge expired challenges
            now_m = self._mono()
            expired = [k for k, v in self._challenges.items() if (now_m - v.created_mono) > v.ttl_s]
            for k in expired:
                self._challenges.pop(k, None)
            self._challenges[cid] = ch

        log.info("2FA challenge required for login")
        return LoginNeedsOtp(challenge_id=cid, method_hint="totp")

    def verify_otp(self, challenge_id: str, code: str) -> LoginOk:
        norm_code = code.replace(" ", "").replace("-", "").strip()
        if not _OTP_RE.match(norm_code):
            raise OtpInvalidError("Verification code must be 6 to 8 digits.")

        with self._lock:
            ch = self._challenges.get(challenge_id)
            if ch is None or (self._mono() - ch.created_mono) > ch.ttl_s:
                self._challenges.pop(challenge_id, None)
                raise OtpExpiredError()

        try:
            updated_pair = self.api.verify_otp(ch.interim_token, norm_code)
        except OtpInvalidError:
            with self._lock:
                ch.attempts += 1
                if ch.attempts >= 5:
                    self._challenges.pop(challenge_id, None)
                    raise OtpExpiredError("Maximum 2FA attempts (5) exceeded.") from None
            raise
        except OtpExpiredError:
            with self._lock:
                self._challenges.pop(challenge_id, None)
            raise

        with self._lock:
            self._challenges.pop(challenge_id, None)

        final_pair = updated_pair or TokenPair(token=ch.interim_token, renew_token=ch.renew_token)
        sess = make_session(final_pair, self._clock())
        res = self._finalize_account(sess, ch.email_hint)
        log.info("2FA verification succeeded (%s)", res.account_hint or "account")
        return res

    def import_official(self, config_dir: Any = None) -> LoginOk:
        creds = import_official_surfshark_credentials(config_dir=config_dir, clock_now=self._clock())
        assert creds.session is not None
        if creds.wireguard is not None:
            self.store.save_wireguard(creds.wireguard)
        res = self._finalize_account(creds.session, creds.email_hint or "official-import")
        log.info("Imported session from official Surfshark installation")
        return res

    def logout(self) -> None:
        s = self.token_mgr.session
        if s is not None:
            self.api.logout(s.token)
        self.token_mgr.clear_session()
        log.info("Logged out and wiped stored credentials")

    def get_view(self, key_expires_at: float | None = None) -> dict[str, str | None]:
        s = self.token_mgr.session
        return {
            "state": self.token_mgr.state.value,
            "account_hint": self.token_mgr.email_hint,
            "token_exp": epoch_to_iso(s.token_exp) if s else None,
            "key_expires_at": epoch_to_iso(key_expires_at),
            "last_error": self.token_mgr.last_error,
        }
