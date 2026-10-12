"""Surfshark HTTPS API surface and verified Phase 0 endpoints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from surfshark_lite.errors import (
    ApiStatusError,
    CaptchaRequiredError,
    ErrorCode,
    InvalidCredentialsError,
    OtpExpiredError,
    OtpInvalidError,
    RateLimitedError,
    SslError,
)
from surfshark_lite.httpclient import HttpClient, Response, opt_int, opt_str, require_dict, require_str

# Verified in Phase 0 (docs/GROUND_TRUTH.md) against Surfshark Linux 3.14.0
ENDPOINTS: dict[str, Any] = {
    "bases": [
        "https://ext2.surfshark.com",  # G3: primary external API host in v3.14.0
        "https://api.surfshark.com",   # G3: canonical API host
    ],
    "anycast_base": "https://172.16.0.36",          # G3/G5: in-tunnel anycast API
    "anycast_sni": "wgs.prod.surfshark.com",        # G3/G5: TLS SNI for 172.16.0.36
    "login": ("POST", "/v1/auth/login"),            # G1
    "otp_verify": ("POST", "/v1/auth/activate"),    # G2: verified /v1/auth/activate (NOT /v1/auth/2fa/activate)
    "renew": ("POST", "/v1/auth/renew"),            # G1
    "logout": ("POST", "/v1/auth/logout"),          # G1
    "remote_create": ("POST", "/v1/account/authorization/create"),  # G1
    "remote_poll": ("POST", "/v1/auth/remote"),     # G1
    "me": ("GET", "/v1/account/users/me"),          # G3
    "clusters": ("GET", "/v5/server/clusters/all"), # G3
    "key_register": ("POST", "/v1/account/users/public-keys"),          # G4
    "key_validate": ("POST", "/v1/account/users/public-keys/validate"), # G4
    "ip_check": ("GET", "/v1/server/user"),         # G3
}

REQUIRED = ("login", "otp_verify", "renew", "clusters", "key_register", "key_validate")


def verify_endpoints_ready() -> None:
    for req_key in REQUIRED:
        entry = ENDPOINTS.get(req_key)
        if not isinstance(entry, tuple) or len(entry) != 2 or not entry[1]:
            raise SslError(
                ErrorCode.INTERNAL,
                f"Required API endpoint '{req_key}' is not configured.",
            )


@dataclass(frozen=True)
class TokenPair:
    token: str
    renew_token: str


@dataclass(frozen=True)
class LoginHttpOutcome:
    needs_otp: bool
    tokens: TokenPair


@dataclass(frozen=True)
class UserAccountInfo:
    user_id: str | None
    external_id: str | None
    email: str | None
    technologies: tuple[str, ...]


@dataclass(frozen=True)
class KeyRegistrationInfo:
    pub_key: str
    expires_at: str | None
    key_id: str | None


@dataclass(frozen=True)
class RemoteLoginChallenge:
    code: str
    hash_val: str
    expires_at: int | None


class SurfsharkAPI:
    """Typed wrapper around Surfshark REST API endpoints."""

    def __init__(self, http: HttpClient) -> None:
        verify_endpoints_ready()
        self.http = http

    def _call(
        self,
        ep_key: str,
        *,
        json_body: Any = None,
        bearer: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        anycast: bool = False,
    ) -> Response:
        method, path = ENDPOINTS[ep_key]
        if anycast:
            url = f"{ENDPOINTS['anycast_base'].rstrip('/')}/{path.lstrip('/')}"
            return self.http.request(
                method,
                url,
                json_body=json_body,
                bearer=bearer,
                headers=headers,
                timeout=timeout,
                sni_hostname=ENDPOINTS["anycast_sni"],
            )
        return self.http.request(
            method,
            path,
            json_body=json_body,
            bearer=bearer,
            headers=headers,
            timeout=timeout,
        )

    def login(self, email: str, password: str) -> LoginHttpOutcome:
        resp = self._call("login", json_body={"username": email, "password": password})
        if resp.status in (200, 423):
            d = require_dict(resp.json_data, "login response")
            token = require_str(d, "token")
            renew_token = require_str(d, "renewToken")
            return LoginHttpOutcome(
                needs_otp=(resp.status == 423),
                tokens=TokenPair(token=token, renew_token=renew_token),
            )
        if resp.status in (400, 401):
            raise InvalidCredentialsError()
        if resp.status == 403:
            if "captcha" in resp.raw_text.lower():
                raise CaptchaRequiredError()
            raise InvalidCredentialsError()
        if resp.status == 429:
            ra_str = resp.headers.get("retry-after")
            ra = int(ra_str) if ra_str and ra_str.isdigit() else None
            raise RateLimitedError(retry_after=ra)
        raise ApiStatusError(resp.status, f"Login failed with HTTP {resp.status}", path=ENDPOINTS["login"][1])

    def verify_otp(self, interim_token: str, otp_code: str) -> TokenPair | None:
        resp = self._call(
            "otp_verify",
            json_body={"otp": otp_code},
            bearer=interim_token,
        )
        if resp.ok:
            if isinstance(resp.json_data, dict) and "token" in resp.json_data and "renewToken" in resp.json_data:
                return TokenPair(
                    token=require_str(resp.json_data, "token"),
                    renew_token=require_str(resp.json_data, "renewToken"),
                )
            return None
        if resp.status in (400, 401):
            raise OtpInvalidError()
        if resp.status == 410:
            raise OtpExpiredError()
        if resp.status == 429:
            ra_str = resp.headers.get("retry-after")
            ra = int(ra_str) if ra_str and ra_str.isdigit() else None
            raise RateLimitedError(retry_after=ra)
        raise ApiStatusError(resp.status, f"2FA verification failed with HTTP {resp.status}", path=ENDPOINTS["otp_verify"][1])

    def renew(self, renew_token: str, *, anycast: bool = False) -> TokenPair:
        resp = self._call("renew", bearer=renew_token, timeout=20.0, anycast=anycast)
        if resp.ok:
            d = require_dict(resp.json_data, "renew response")
            return TokenPair(
                token=require_str(d, "token"),
                renew_token=require_str(d, "renewToken"),
            )
        if resp.status == 429:
            ra_str = resp.headers.get("retry-after")
            ra = int(ra_str) if ra_str and ra_str.isdigit() else None
            raise RateLimitedError(retry_after=ra)
        raise ApiStatusError(resp.status, f"Token renew failed with HTTP {resp.status}", path=ENDPOINTS["renew"][1])

    def logout(self, token: str) -> None:
        try:
            self._call("logout", bearer=token, timeout=5.0)
        except Exception:
            pass

    def create_remote_login(self) -> RemoteLoginChallenge:
        resp = self._call("remote_create")
        if not resp.ok:
            raise ApiStatusError(resp.status, f"Failed to create login code (HTTP {resp.status})")
        d = require_dict(resp.json_data, "remote login create")
        return RemoteLoginChallenge(
            code=require_str(d, "code", max_len=64),
            hash_val=require_str(d, "hash", max_len=512),
            expires_at=opt_int(d, "expiresAt"),
        )

    def poll_remote_login(self, hash_val: str) -> TokenPair | None:
        resp = self._call("remote_poll", json_body={"hash": hash_val})
        if resp.ok:
            d = require_dict(resp.json_data, "remote login poll")
            return TokenPair(
                token=require_str(d, "token"),
                renew_token=require_str(d, "renewToken"),
            )
        if resp.status == 404:
            return None
        raise ApiStatusError(resp.status, f"Remote login failed (HTTP {resp.status})")

    def raw_call_with_token(
        self,
        ep_key: str,
        token: str,
        *,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        anycast: bool = False,
    ) -> Response:
        return self._call(
            ep_key,
            json_body=json_body,
            bearer=token,
            headers=headers,
            timeout=timeout,
            anycast=anycast,
        )

    @staticmethod
    def parse_me(resp: Response) -> UserAccountInfo:
        if not resp.ok:
            raise ApiStatusError(resp.status, f"Fetching account info failed with HTTP {resp.status}", path=ENDPOINTS["me"][1])
        d = require_dict(resp.json_data, "users/me")
        techs_raw = d.get("technologies")
        techs: tuple[str, ...] = ()
        if isinstance(techs_raw, list):
            techs = tuple(str(x) for x in techs_raw if isinstance(x, str))
        return UserAccountInfo(
            user_id=opt_str(d, "id", 128),
            external_id=opt_str(d, "externalId", 128),
            email=opt_str(d, "email", 320),
            technologies=techs,
        )

    def clusters(
        self,
        *,
        bearer: str | None = None,
        etag: str | None = None,
    ) -> tuple[list[dict[str, Any]] | None, str | None]:
        """Fetch server catalog. Returns (items_or_None_if_304, new_etag)."""
        hdrs: dict[str, str] = {}
        if etag:
            hdrs["If-None-Match"] = etag
        resp = self._call("clusters", bearer=bearer, headers=hdrs, timeout=15.0)
        if resp.status == 304:
            return None, etag
        if not resp.ok:
            raise ApiStatusError(resp.status, f"Cluster catalog fetch failed with HTTP {resp.status}", path=ENDPOINTS["clusters"][1])
        if not isinstance(resp.json_data, list):
            raise SslError(ErrorCode.API_ERROR, "Cluster catalog response is not a JSON list")
        new_etag = resp.headers.get("etag")
        return resp.json_data, new_etag

    def ip_check(self, timeout: float = 4.0) -> dict[str, Any]:
        resp = self._call("ip_check", timeout=timeout)
        if not resp.ok:
            raise ApiStatusError(resp.status, f"IP check returned HTTP {resp.status}", path=ENDPOINTS["ip_check"][1])
        return require_dict(resp.json_data, "server/user")
