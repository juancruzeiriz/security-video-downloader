"""Origen-fixture del lab: sirve HLS validando el token como lo haria una CDN.

Etapa 1: validaba firma HMAC + vencimiento (exp) + acl en cada pedido.
Etapa 2 (este archivo): ademas de eso, aplica los controles de abuso del modelo
de amenazas cuando ``SVD_DEFENSE=1``:

  - binding del token a sesion/IP (campos firmados ``session``/``ip``),
  - rotacion de clave (SVD_SECRET + SVD_SECRET_PREVIOUS),
  - renovacion de tokens cortos (POST /token/renew),
  - rate limiting, pacing (anti-rafaga), reuso multi-IP y gate de playback
    (via lab_origin.defense, alimentado por la telemetria).

Sigue siendo un arnes para el lab, no un servicio de produccion. La clave HMAC se
lee del entorno (SVD_SECRET); nunca se hardcodea ni se expone.

Correr:  uvicorn lab_origin.app:app --port 8000 --app-dir src
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from svd import tokens

from . import defense

SEGMENT_EXTS = (".ts", ".m4s")


def _media_root() -> str:
    return os.path.abspath(os.environ.get("SVD_MEDIA_ROOT", "media/hls"))


def _secrets() -> list[str]:
    """Clave(s) HMAC vigentes. Durante una rotacion valen la nueva y la vieja."""
    keys = [os.environ.get("SVD_SECRET", "")]
    prev = os.environ.get("SVD_SECRET_PREVIOUS")
    if prev:
        keys.append(prev)
    return [k for k in keys if k]


def _primary_secret() -> str:
    keys = _secrets()
    return keys[0] if keys else ""


def _protected_prefix() -> str:
    # Prefijo cuyas rutas requieren token. Fuera de el, se sirve libre (ej. assets).
    return os.environ.get("SVD_PROTECTED_PREFIX", "/")


def _renew_ttl() -> int:
    try:
        return int(os.environ.get("SVD_RENEW_TTL", "120"))
    except ValueError:
        return 120


def _trust_xff() -> bool:
    # SOLO lab: confiar en X-Forwarded-For para simular IPs de cliente en los tests.
    # En produccion esto seria spoofeable; la IP real la pone el edge/reverse-proxy.
    return (os.environ.get("SVD_TRUST_XFF", "") or "").strip().lower() in ("1", "true", "yes", "on")


CONTENT_TYPES = {
    ".m3u8": "application/vnd.apple.mpegurl",
    ".ts": "video/mp2t",
    ".m4s": "video/iso.segment",
    ".mp4": "video/mp4",
    ".key": "application/octet-stream",
}

app = FastAPI(title="svd lab origin", docs_url=None, redoc_url=None)


def _content_type(path: str) -> str:
    _, ext = os.path.splitext(path)
    return CONTENT_TYPES.get(ext.lower(), "application/octet-stream")


def _client_ip(request: Request) -> str | None:
    if _trust_xff():
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else None


def _request_session(request: Request) -> str | None:
    return request.headers.get("X-Session-Id") or request.query_params.get("session")


def _safe_file(url_path: str) -> str | None:
    """Mapea la ruta URL a un archivo dentro de MEDIA_ROOT, bloqueando traversal."""
    root = _media_root()
    rel = url_path.lstrip("/")
    candidate = os.path.abspath(os.path.join(root, rel))
    if not (candidate == root or candidate.startswith(root + os.sep)):
        return None
    return candidate


@app.post("/video-diagnostic/event")
async def video_diagnostic_event(request: Request) -> Response:
    """Endpoint de telemetria. Acepta el evento, lo usa para el gate/anomalias y responde 204."""
    try:
        payload = await request.json()
    except Exception:
        payload = None
    event = session = None
    if isinstance(payload, dict):
        event = payload.get("event")
        session = payload.get("session_id")
    # Alimenta la deteccion de abuso: marca playback_started y registra la IP.
    defense.get_engine().note_telemetry(session, event, _client_ip(request))
    print(f"[telemetry] event={event} session={session} from={_client_ip(request)}")
    return Response(status_code=204)


@app.post("/token/renew")
async def token_renew(request: Request) -> Response:
    """Renueva un token corto: dado uno aun valido, emite otro con TTL corto.

    Mantiene acl/session/ip del original. Asi el reproductor pide un token nuevo
    antes de que venza el actual, sin tener que volver a autenticar al usuario.
    """
    secrets = _secrets()
    if not secrets:
        return PlainTextResponse("server misconfigured: SVD_SECRET not set", status_code=500)
    token = request.query_params.get("token") or request.headers.get("X-Svd-Token")
    if not token:
        return PlainTextResponse("400: missing token", status_code=400)
    result = tokens.verify(
        secrets, token, None,
        session=_request_session(request), client_ip=_client_ip(request),
    )
    if not result:
        return PlainTextResponse(f"403: {result.reason}", status_code=403)
    parsed = result.token
    assert parsed is not None
    fresh = tokens.sign(
        _primary_secret(), parsed.acl, ttl=_renew_ttl(),
        session=parsed.session, ip=parsed.ip,
    )
    return JSONResponse({"token": fresh, "ttl": _renew_ttl()})


@app.get("/healthz")
async def healthz() -> JSONResponse:
    return JSONResponse({
        "ok": True,
        "media_root": _media_root(),
        "secret_set": bool(_primary_secret()),
        "defense": defense.get_engine().config.enabled,
    })


@app.get("/debug/defense")
async def debug_defense() -> Response:
    """Estado del motor de defensa (solo lab; util para tests y para ver alertas)."""
    if (os.environ.get("SVD_DEBUG", "") or "").strip().lower() not in ("1", "true", "yes", "on"):
        return PlainTextResponse("404: not found", status_code=404)
    return JSONResponse(defense.get_engine().snapshot())


@app.get("/{url_path:path}")
async def serve(url_path: str, request: Request) -> Response:
    full_path = "/" + url_path
    _, ext = os.path.splitext(full_path)
    is_segment = ext.lower() in SEGMENT_EXTS

    if full_path.startswith(_protected_prefix()):
        secrets = _secrets()
        if not secrets:
            return PlainTextResponse("server misconfigured: SVD_SECRET not set", status_code=500)
        token = request.query_params.get("token")
        if not token:
            return PlainTextResponse("403: missing token", status_code=403)

        client_ip = _client_ip(request)
        req_session = _request_session(request)
        result = tokens.verify(secrets, token, full_path, session=req_session, client_ip=client_ip)
        if not result:
            # El motivo (expired / acl_mismatch / bad_signature / session|ip_mismatch).
            return PlainTextResponse(f"403: {result.reason}", status_code=403)

        # Identidad de sesion para rate/concurrencia: la del token (firmada) o la del pedido.
        sid = (result.token.session if result.token else None) or req_session
        decision = defense.get_engine().check_request(sid, client_ip, is_segment=is_segment)
        if not decision.allowed:
            return PlainTextResponse(f"{decision.status}: {decision.reason}", status_code=decision.status)

    file_path = _safe_file(full_path)
    if file_path is None:
        return PlainTextResponse("403: path traversal", status_code=403)
    if not os.path.isfile(file_path):
        return PlainTextResponse("404: not found", status_code=404)

    with open(file_path, "rb") as fh:
        body = fh.read()
    return Response(content=body, media_type=_content_type(file_path))
