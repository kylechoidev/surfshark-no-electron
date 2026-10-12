"""Pure-Python X25519 (RFC 7748 §5). Fallback only — used to derive the WireGuard public key
from a locally generated private key when neither `cryptography` nor `wg` is available."""

from __future__ import annotations

P = 2**255 - 19
_A24 = 121665
_BASE = (9).to_bytes(32, "little")


def _decode_scalar(k: bytes) -> int:
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def _decode_u(u: bytes) -> int:
    b = bytearray(u)
    b[31] &= 127
    return int.from_bytes(b, "little") % P


def x25519(k: bytes, u: bytes) -> bytes:
    if len(k) != 32 or len(u) != 32:
        raise ValueError("x25519 inputs must be 32 bytes")
    scalar, x1 = _decode_scalar(k), _decode_u(u)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        bit = (scalar >> t) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) * (da + cb) % P
        z3 = x1 * (da - cb) * (da - cb) % P
        x2 = aa * bb % P
        z2 = e * (aa + _A24 * e) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def public_key(private_key: bytes) -> bytes:
    return x25519(private_key, _BASE)


def _self_test() -> None:
    h = bytes.fromhex
    # RFC 7748 §5.2
    assert x25519(
        h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    ) == h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    # RFC 7748 §6.1
    a = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    pa, pb = public_key(a), public_key(b)
    assert pa == h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    assert pb == h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    assert x25519(a, pb) == x25519(b, pa) == h(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    )


_self_test()  # raise at import: a broken fallback must never produce keys
