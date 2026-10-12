"""Error hierarchy and stable public error codes for Surf Shark Ultra Lite."""

from __future__ import annotations

from enum import Enum
from typing import Any


class ErrorCode(str, Enum):
    # Auth
    AUTH_REQUIRED = "AUTH_REQUIRED"
    REAUTH_REQUIRED = "REAUTH_REQUIRED"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    CAPTCHA_REQUIRED = "CAPTCHA_REQUIRED"
    RATE_LIMITED = "RATE_LIMITED"
    OTP_INVALID = "OTP_INVALID"
    OTP_EXPIRED = "OTP_EXPIRED"

    # Network / API
    NETWORK_UNAVAILABLE = "NETWORK_UNAVAILABLE"
    API_ERROR = "API_ERROR"

    # Target
    TARGET_NOT_FOUND = "TARGET_NOT_FOUND"
    TARGET_AMBIGUOUS = "TARGET_AMBIGUOUS"

    # Driver / tunnel
    DRIVER_UNAVAILABLE = "DRIVER_UNAVAILABLE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    FOREIGN_TUNNEL_ACTIVE = "FOREIGN_TUNNEL_ACTIVE"
    TUNNEL_VERIFY_FAILED = "TUNNEL_VERIFY_FAILED"

    # Keys / storage
    KEY_REJECTED = "KEY_REJECTED"
    CREDENTIALS_INSECURE = "CREDENTIALS_INSECURE"

    # Other
    VALIDATION = "VALIDATION"
    INTERNAL = "INTERNAL"


NON_RETRYABLE_CODES: frozenset[ErrorCode] = frozenset({
    ErrorCode.AUTH_REQUIRED,
    ErrorCode.REAUTH_REQUIRED,
    ErrorCode.INVALID_CREDENTIALS,
    ErrorCode.CAPTCHA_REQUIRED,
    ErrorCode.OTP_INVALID,
    ErrorCode.OTP_EXPIRED,
    ErrorCode.PERMISSION_DENIED,
    ErrorCode.TARGET_NOT_FOUND,
    ErrorCode.TARGET_AMBIGUOUS,
    ErrorCode.FOREIGN_TUNNEL_ACTIVE,
    ErrorCode.KEY_REJECTED,
    ErrorCode.CREDENTIALS_INSECURE,
    ErrorCode.VALIDATION,
})


class SslError(Exception):
    """Base exception for all Surf Shark Ultra Lite typed errors."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        details: dict[str, Any] | None = None,
        http_status: int = 400,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details) if details else {}
        self.http_status = http_status

    def to_envelope(self) -> dict[str, Any]:
        return {
            "error": {
                "code": self.code.value,
                "message": self.message,
                "details": self.details,
            }
        }

    @property
    def retryable(self) -> bool:
        return self.code not in NON_RETRYABLE_CODES


class AuthRequiredError(SslError):
    def __init__(self, message: str = "Authentication required. Run 'surfshark-lite login'.") -> None:
        super().__init__(ErrorCode.AUTH_REQUIRED, message, http_status=401)


class ReauthRequiredError(SslError):
    def __init__(self, message: str = "Session expired or revoked. Please log in again.") -> None:
        super().__init__(ErrorCode.REAUTH_REQUIRED, message, http_status=401)


class InvalidCredentialsError(SslError):
    def __init__(self, message: str = "Invalid email or password.") -> None:
        super().__init__(ErrorCode.INVALID_CREDENTIALS, message, http_status=401)


class CaptchaRequiredError(SslError):
    def __init__(self, message: str = "Captcha challenge required by API; try login with code or wait.") -> None:
        super().__init__(ErrorCode.CAPTCHA_REQUIRED, message, http_status=403)


class RateLimitedError(SslError):
    def __init__(self, retry_after: int | None = None, message: str = "API rate limit exceeded.") -> None:
        details = {"retry_after": retry_after} if retry_after is not None else {}
        super().__init__(ErrorCode.RATE_LIMITED, message, details=details, http_status=429)
        self.retry_after = retry_after


class OtpInvalidError(SslError):
    def __init__(self, message: str = "Invalid 2FA verification code.") -> None:
        super().__init__(ErrorCode.OTP_INVALID, message, http_status=401)


class OtpExpiredError(SslError):
    def __init__(self, message: str = "2FA challenge expired or maximum attempts exceeded.") -> None:
        super().__init__(ErrorCode.OTP_EXPIRED, message, http_status=410)


class NetworkError(SslError):
    def __init__(self, kind: str, message: str) -> None:
        super().__init__(
            ErrorCode.NETWORK_UNAVAILABLE,
            message,
            details={"kind": kind},
            http_status=503,
        )
        self.kind = kind


class ApiStatusError(SslError):
    def __init__(self, status: int, message: str, path: str = "") -> None:
        super().__init__(
            ErrorCode.API_ERROR,
            message,
            details={"status": status, "path": path},
            http_status=502 if status >= 500 else 400,
        )
        self.status = status
        self.path = path


class TargetNotFoundError(SslError):
    def __init__(self, query: str) -> None:
        super().__init__(
            ErrorCode.TARGET_NOT_FOUND,
            f"No WireGuard server matched '{query}'.",
            details={"query": query},
            http_status=404,
        )


class TargetAmbiguousError(SslError):
    def __init__(self, query: str, candidates: list[dict[str, Any]]) -> None:
        super().__init__(
            ErrorCode.TARGET_AMBIGUOUS,
            f"Target '{query}' matches multiple locations.",
            details={"query": query, "candidates": candidates},
            http_status=409,
        )
        self.candidates = candidates


class DriverError(SslError):
    def __init__(
        self,
        code: ErrorCode = ErrorCode.DRIVER_UNAVAILABLE,
        message: str = "Tunnel driver error.",
        details: dict[str, Any] | None = None,
        http_status: int = 500,
    ) -> None:
        super().__init__(code, message, details=details, http_status=http_status)


class CredentialsInsecureError(SslError):
    def __init__(self, path: str, fix_cmd: str) -> None:
        super().__init__(
            ErrorCode.CREDENTIALS_INSECURE,
            f"Insecure permissions on {path}. Fix with: {fix_cmd}",
            details={"path": path, "fix": fix_cmd},
            http_status=500,
        )


class ValidationError(SslError):
    def __init__(self, message: str, field: str | None = None) -> None:
        details = {"field": field} if field else {}
        super().__init__(ErrorCode.VALIDATION, message, details=details, http_status=422)
