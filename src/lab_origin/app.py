"""Origen-fixture del lab: sirve HLS validando el token como lo haria una CDN.

NO es el "defensor" de produccion: es un arnes minimo para poder atacar el
descargador contra localhost. Valida en cada pedido:
  - firma HMAC del token,
  - vencimiento (exp),
  - que la ruta pedida entre en el acl.
Si algo falla -> 403. Si pasa -> 200 y sirve el archivo.

La clave HMAC se lee del entorno (SVD_SECRET). Nunca se hardcodea ni se expone.

Correr:  uvicorn lab_origin.app:app --port 8000
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from svd import tokens


def _media_root() -> str:
    return os.path.abspath(os.environ.get("SVD_MEDIA_ROOT", "media/hls"))


def _secret() -> str:
    return os.environ.get("SVD_SECRET", "")


def _protected_prefix() -> str:
    # Prefijo cuyas rutas requieren token. Fuera de el, se sirve libre (ej. assets).
    return os.environ.get("SVD_PROTECTED_PREFIX", "/")


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
    """Endpoint de telemetria. Acepta el evento y responde 204 (como el ejemplo real)."""
    try:
        payload = await request.json()
    except Exception:
        payload = None
    # En el lab solo lo logueamos; en produccion aca se detectarian patrones de abuso.
    if payload is not None:
        event = payload.get("event") if isinstance(payload, dict) else None
        print(f"[telemetry] event={event} from={request.client.host if request.client else '?'}")
    return Response(status_code=204)


@app.get("/healthz")
async def healthz() -> JSONResponse:
    return JSONResponse({"ok": True, "media_root": _media_root(), "secret_set": bool(_secret())})


@app.get("/{url_path:path}")
async def serve(url_path: str, request: Request) -> Response:
    full_path = "/" + url_path

    secret = _secret()
    if full_path.startswith(_protected_prefix()):
        if not secret:
            return PlainTextResponse("server misconfigured: SVD_SECRET not set", status_code=500)
        token = request.query_params.get("token")
        if not token:
            return PlainTextResponse("403: missing token", status_code=403)
        result = tokens.verify(secret, token, full_path)
        if not result:
            # El motivo (expired / acl_mismatch / bad_signature) ayuda a entender el lab.
            return PlainTextResponse(f"403: {result.reason}", status_code=403)

    file_path = _safe_file(full_path)
    if file_path is None:
        return PlainTextResponse("403: path traversal", status_code=403)
    if not os.path.isfile(file_path):
        return PlainTextResponse("404: not found", status_code=404)

    with open(file_path, "rb") as fh:
        body = fh.read()
    return Response(content=body, media_type=_content_type(file_path))
