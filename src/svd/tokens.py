"""Firma y verificación de tokens ``exp=...~acl=...~hmac=...``.

Formato base, idéntico al token-auth de Akamai EdgeAuth / Uploadcare:

    exp=1791240149~acl=/<id>/adaptive_video/*~hmac=<hex-sha256>

El HMAC-SHA256 se calcula sobre el mensaje canónico (todos los campos salvo el
propio ``hmac``), con una clave secreta que SOLO conocen el backend y la CDN.
Sin la clave no se puede falsificar la firma (RFC 2104).

Puntos de seguridad implementados acá:
- Comparación en tiempo constante (``hmac.compare_digest``) para evitar timing attacks.
- La clave jamás se expone al frontend: vive sólo en el servidor (acá, en env).

## Extensiones de la Etapa 2 (binding)

Además de ``exp`` y ``acl``, el token puede llevar campos *firmados* opcionales
que lo atan a una sesión o a una IP concreta. Como entran en el material
firmado, no se pueden alterar sin romper el HMAC:

    exp=..~acl=..~session=<sid>~ip=<addr>~hmac=..

El origen, además de validar la firma, compara ``session``/``ip`` contra la
sesión y la IP reales del pedido (ver ``lab_origin``). Un token "compartido" a
otra IP o sesión deja de servir.

## Rotación de clave

``verify`` acepta una clave o una lista de claves. Durante una rotación se pasan
``[clave_nueva, clave_vieja]`` y el token sigue validando con cualquiera de las
dos hasta que expiren los emitidos con la anterior.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import time
from collections.abc import Sequence
from dataclasses import dataclass

FIELD_SEP = "~"

# Campos firmados, en el ORDEN canónico en que entran al mensaje y al token.
# ``hmac`` nunca entra al mensaje (es el resultado). ``exp`` y ``acl`` son
# obligatorios; ``session`` e ``ip`` son opcionales (Etapa 2, binding).
_SIGNED_FIELDS = ("exp", "acl", "session", "ip")


@dataclass(frozen=True)
class Token:
    exp: int
    acl: str
    hmac: str
    session: str | None = None
    ip: str | None = None

    def _signed_pairs(self) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = [("exp", str(self.exp)), ("acl", self.acl)]
        if self.session is not None:
            pairs.append(("session", self.session))
        if self.ip is not None:
            pairs.append(("ip", self.ip))
        return pairs

    def to_string(self) -> str:
        parts = [f"{k}={v}" for k, v in self._signed_pairs()]
        parts.append(f"hmac={self.hmac}")
        return FIELD_SEP.join(parts)


def _message(pairs: Sequence[tuple[str, str]]) -> str:
    """Mensaje canónico que se firma (campos presentes, en orden, sin el hmac)."""
    return FIELD_SEP.join(f"{k}={v}" for k, v in pairs)


def _digest(secret: str, pairs: Sequence[tuple[str, str]]) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        _message(pairs).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def sign(
    secret: str,
    acl: str,
    *,
    ttl: int | None = None,
    expires_at: int | None = None,
    session: str | None = None,
    ip: str | None = None,
) -> str:
    """Genera un token firmado.

    Pasá ``ttl`` (segundos desde ahora) o un ``expires_at`` (epoch Unix) absoluto.
    Opcionalmente atá el token a una ``session`` y/o a una ``ip`` (Etapa 2): esos
    campos entran al material firmado y el origen los compara contra el pedido.
    """
    if (ttl is None) == (expires_at is None):
        raise ValueError("Pasá exactamente uno: ttl o expires_at")
    exp = expires_at if expires_at is not None else int(time.time()) + int(ttl)
    tok = Token(exp=exp, acl=acl, hmac="", session=session, ip=ip)
    mac = _digest(secret, tok._signed_pairs())
    return Token(exp=exp, acl=acl, hmac=mac, session=session, ip=ip).to_string()


def parse(token: str) -> Token:
    """Parsea un token string a sus campos. Lanza ValueError si está malformado."""
    fields: dict[str, str] = {}
    for part in token.split(FIELD_SEP):
        key, sep, value = part.partition("=")
        if not sep or not key:
            raise ValueError(f"Campo malformado en token: {part!r}")
        fields[key] = value
    missing = {"exp", "acl", "hmac"} - fields.keys()
    if missing:
        raise ValueError(f"Faltan campos en el token: {sorted(missing)}")
    try:
        exp = int(fields["exp"])
    except ValueError as exc:
        raise ValueError(f"exp no es un entero: {fields['exp']!r}") from exc
    return Token(
        exp=exp,
        acl=fields["acl"],
        hmac=fields["hmac"],
        session=fields.get("session"),
        ip=fields.get("ip"),
    )


def acl_matches(acl: str, path: str) -> bool:
    """¿La ruta pedida entra en el patrón acl? Soporta el wildcard ``*``.

    El ``*`` matchea cualquier cosa, incluidas las ``/`` (igual que Akamai/Uploadcare),
    así que ``/<id>/adaptive_video/*`` cubre todos los segmentos del video.
    """
    return fnmatch.fnmatchcase(path, acl)


class VerifyResult:
    """Resultado detallado de una verificación, para poder loguear el porqué del 403."""

    def __init__(self, ok: bool, reason: str = "ok", token: Token | None = None) -> None:
        self.ok = ok
        self.reason = reason
        self.token = token

    def __bool__(self) -> bool:  # permite `if verify(...):`
        return self.ok

    def __repr__(self) -> str:
        return f"VerifyResult(ok={self.ok}, reason={self.reason!r})"


def _as_secrets(secret: str | Sequence[str]) -> list[str]:
    if isinstance(secret, str):
        return [secret]
    keys = [s for s in secret if s]
    if not keys:
        raise ValueError("No se pasó ninguna clave para verificar")
    return keys


def verify(
    secret: str | Sequence[str],
    token: str,
    path: str | None,
    *,
    now: int | None = None,
    session: str | None = None,
    client_ip: str | None = None,
) -> VerifyResult:
    """Valida un token para una ruta dada: firma, vencimiento, acl y binding.

    Replica lo que haría la CDN/origen en cada pedido. Devuelve un VerifyResult
    truthy/falsy que además trae el motivo del rechazo y el token parseado.

    - ``secret`` puede ser una clave o una lista (rotación): vale si firma con cualquiera.
    - ``path=None`` salta el chequeo de acl (se usa al renovar, donde sólo
      importa que la firma, el exp y el binding sigan válidos).
    - Si el token trae ``session``/``ip``, se exige que coincidan con los
      ``session``/``client_ip`` del pedido (Etapa 2, binding). Un token sin esos
      campos no impone binding (compatibilidad con la Etapa 1).
    """
    now = int(time.time()) if now is None else now
    try:
        parsed = parse(token)
    except ValueError as exc:
        return VerifyResult(False, f"malformed: {exc}")

    expected_any = False
    for key in _as_secrets(secret):
        expected = _digest(key, parsed._signed_pairs())
        if hmac.compare_digest(expected, parsed.hmac):
            expected_any = True
            break
    if not expected_any:
        return VerifyResult(False, "bad_signature", parsed)
    if parsed.exp < now:
        return VerifyResult(False, "expired", parsed)
    if path is not None and not acl_matches(parsed.acl, path):
        return VerifyResult(False, "acl_mismatch", parsed)
    # Binding: el token exige una sesión/IP y el pedido tiene que traerla igual.
    if parsed.session is not None and session != parsed.session:
        return VerifyResult(False, "session_mismatch", parsed)
    if parsed.ip is not None and client_ip != parsed.ip:
        return VerifyResult(False, "ip_mismatch", parsed)
    return VerifyResult(True, "ok", parsed)


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
    p_sign.add_argument("--session", help="Atar el token a un id de sesión (binding)")
    p_sign.add_argument("--ip", help="Atar el token a una IP (binding)")
    p_sign.add_argument("--secret", help="Clave HMAC (si no, usa env SVD_SECRET)")

    p_ver = sub.add_parser("verify", help="Verifica un token contra una ruta")
    p_ver.add_argument("--token", required=True)
    p_ver.add_argument("--path", required=True, help="Ruta pedida, ej: /<id>/adaptive_video/-/variant/480p/4/")
    p_ver.add_argument("--session", help="Sesión del pedido (para binding)")
    p_ver.add_argument("--client-ip", dest="client_ip", help="IP del pedido (para binding)")
    p_ver.add_argument("--secret", help="Clave HMAC (si no, usa env SVD_SECRET)")

    args = parser.parse_args(argv)
    secret = args.secret or os.environ.get("SVD_SECRET")
    if not secret:
        parser.error("Falta la clave: pasá --secret o seteá el env SVD_SECRET")

    if args.cmd == "sign":
        print(sign(secret, args.acl, ttl=args.ttl, expires_at=args.expires_at,
                   session=args.session, ip=args.ip))
        return 0

    result = verify(secret, args.token, args.path, session=args.session, client_ip=args.client_ip)
    print(f"{'OK' if result.ok else 'FAIL'}: {result.reason}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(_main())
