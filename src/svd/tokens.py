"""Firma y verificación de tokens ``exp=...~acl=...~hmac=...``.

Formato idéntico al token-auth de Akamai EdgeAuth / Uploadcare:

    exp=1791240149~acl=/<id>/adaptive_video/*~hmac=<hex-sha256>

El HMAC-SHA256 se calcula sobre el mensaje ``exp=<ts>~acl=<pattern>`` (todos los
campos salvo el propio ``hmac``), con una clave secreta que SOLO conocen el backend
y la CDN. Sin la clave no se puede falsificar la firma (RFC 2104).

Puntos de seguridad implementados acá:
- Comparación en tiempo constante (``hmac.compare_digest``) para evitar timing attacks.
- La clave jamás se expone al frontend: vive sólo en el servidor (acá, en env).
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import time
from dataclasses import dataclass

FIELD_SEP = "~"


@dataclass(frozen=True)
class Token:
    exp: int
    acl: str
    hmac: str

    def to_string(self) -> str:
        return f"exp={self.exp}{FIELD_SEP}acl={self.acl}{FIELD_SEP}hmac={self.hmac}"


def _message(exp: int, acl: str) -> str:
    """Mensaje canónico que se firma (sin el campo hmac)."""
    return f"exp={exp}{FIELD_SEP}acl={acl}"


def _digest(secret: str, exp: int, acl: str) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        _message(exp, acl).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def sign(secret: str, acl: str, *, ttl: int | None = None, expires_at: int | None = None) -> str:
    """Genera un token firmado.

    Pasá ``ttl`` (segundos desde ahora) o un ``expires_at`` (epoch Unix) absoluto.
    """
    if (ttl is None) == (expires_at is None):
        raise ValueError("Pasá exactamente uno: ttl o expires_at")
    exp = expires_at if expires_at is not None else int(time.time()) + int(ttl)
    mac = _digest(secret, exp, acl)
    return Token(exp=exp, acl=acl, hmac=mac).to_string()


def parse(token: str) -> Token:
    """Parsea un token string a sus campos. Lanza ValueError si está malformado."""
    fields: dict[str, str] = {}
    for part in token.split(FIELD_SEP):
        key, _, value = part.partition("=")
        if not _ or not key:
            raise ValueError(f"Campo malformado en token: {part!r}")
        fields[key] = value
    missing = {"exp", "acl", "hmac"} - fields.keys()
    if missing:
        raise ValueError(f"Faltan campos en el token: {sorted(missing)}")
    try:
        exp = int(fields["exp"])
    except ValueError as exc:
        raise ValueError(f"exp no es un entero: {fields['exp']!r}") from exc
    return Token(exp=exp, acl=fields["acl"], hmac=fields["hmac"])


def acl_matches(acl: str, path: str) -> bool:
    """¿La ruta pedida entra en el patrón acl? Soporta el wildcard ``*``.

    El ``*`` matchea cualquier cosa, incluidas las ``/`` (igual que Akamai/Uploadcare),
    así que ``/<id>/adaptive_video/*`` cubre todos los segmentos del video.
    """
    return fnmatch.fnmatchcase(path, acl)


class VerifyResult:
    """Resultado detallado de una verificación, para poder loguear el porqué del 403."""

    def __init__(self, ok: bool, reason: str = "ok") -> None:
        self.ok = ok
        self.reason = reason

    def __bool__(self) -> bool:  # permite `if verify(...):`
        return self.ok

    def __repr__(self) -> str:
        return f"VerifyResult(ok={self.ok}, reason={self.reason!r})"


def verify(secret: str, token: str, path: str, *, now: int | None = None) -> VerifyResult:
    """Valida un token para una ruta dada: firma, vencimiento y acl.

    Replica lo que haría la CDN en cada pedido. Devuelve un VerifyResult que es
    truthy/falsy y además trae el motivo del rechazo.
    """
    now = int(time.time()) if now is None else now
    try:
        parsed = parse(token)
    except ValueError as exc:
        return VerifyResult(False, f"malformed: {exc}")

    expected = _digest(secret, parsed.exp, parsed.acl)
    if not hmac.compare_digest(expected, parsed.hmac):
        return VerifyResult(False, "bad_signature")
    if parsed.exp < now:
        return VerifyResult(False, "expired")
    if not acl_matches(parsed.acl, path):
        return VerifyResult(False, "acl_mismatch")
    return VerifyResult(True, "ok")


def _main(argv: list[str] | None = None) -> int:
    """CLI mínimo para generar/verificar tokens a mano.

    La clave se lee de --secret o del env SVD_SECRET (preferido: no queda en el historial).
    """
    import argparse
    import os

    parser = argparse.ArgumentParser(prog="svd.tokens", description="Firma/verifica tokens HMAC exp~acl~hmac")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_sign = sub.add_parser("sign", help="Genera un token firmado")
    p_sign.add_argument("--acl", required=True, help="Patrón de rutas, ej: /<id>/adaptive_video/*")
    g = p_sign.add_mutually_exclusive_group(required=True)
    g.add_argument("--ttl", type=int, help="Segundos de validez desde ahora")
    g.add_argument("--expires-at", type=int, help="Epoch Unix absoluto de vencimiento")
    p_sign.add_argument("--secret", help="Clave HMAC (si no, usa env SVD_SECRET)")

    p_ver = sub.add_parser("verify", help="Verifica un token contra una ruta")
    p_ver.add_argument("--token", required=True)
    p_ver.add_argument("--path", required=True, help="Ruta pedida, ej: /<id>/adaptive_video/-/variant/480p/4/")
    p_ver.add_argument("--secret", help="Clave HMAC (si no, usa env SVD_SECRET)")

    args = parser.parse_args(argv)
    secret = args.secret or os.environ.get("SVD_SECRET")
    if not secret:
        parser.error("Falta la clave: pasá --secret o seteá el env SVD_SECRET")

    if args.cmd == "sign":
        print(sign(secret, args.acl, ttl=args.ttl, expires_at=args.expires_at))
        return 0

    result = verify(secret, args.token, args.path)
    print(f"{'OK' if result.ok else 'FAIL'}: {result.reason}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(_main())
