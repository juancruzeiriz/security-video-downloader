"""Cliente del endpoint de telemetria del reproductor (POST /video-diagnostic/event).

Replica el payload del ejemplo real. Todos los campos son parametrizables: podes
pasar un dict armado a mano, cargar un JSON, o dejar que ``build_payload`` complete
los que falten con defaults razonables.

Util para emular un reproductor real durante las pruebas (el origen puede requerir
haber visto un 'playback_started' antes de servir segmentos, o usar la telemetria
para detectar patrones de abuso).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import requests

DEFAULT_EVENT_PATH = "/video-diagnostic/event"

# Campos del payload de ejemplo. Sirven de plantilla; cualquiera se puede sobreescribir.
PAYLOAD_TEMPLATE: dict[str, Any] = {
    "video_id": None,
    "page_url": None,
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
    ),
    "event": "playback_started",
    "session_id": None,
    "provider": "uploadcare",
    "source_host": None,
    "using_fallback": False,
    "current_time": 0.0,
    "timestamp": None,
    "attempt_id": None,
    "player_version": "1.0.0",
    "playback_engine": "hlsjs",
    "fallback_reason": None,
    "elapsed_ms": 0,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_payload(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Arma un payload completo a partir de la plantilla + overrides del usuario.

    Rellena ``session_id``, ``attempt_id`` y ``timestamp`` si no vienen dados.
    """
    payload = dict(PAYLOAD_TEMPLATE)
    if overrides:
        payload.update(overrides)
    payload.setdefault("session_id", None)
    if not payload.get("session_id"):
        payload["session_id"] = uuid.uuid4().hex
    if not payload.get("attempt_id"):
        payload["attempt_id"] = uuid.uuid4().hex
    if not payload.get("timestamp"):
        payload["timestamp"] = _now_iso()
    return payload


def load_payload_file(path: str) -> dict[str, Any]:
    """Carga un payload (o overrides parciales) desde un archivo JSON."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("El JSON de telemetria debe ser un objeto {}")
    return data


def send_event(
    base_url: str,
    payload: dict[str, Any],
    *,
    event_path: str = DEFAULT_EVENT_PATH,
    user_agent: str | None = None,
    timeout: float = 10.0,
) -> requests.Response:
    """Envia el evento de telemetria. Devuelve la respuesta (se espera 204)."""
    url = base_url.rstrip("/") + event_path
    headers = {"Content-Type": "application/json"}
    if user_agent:
        headers["User-Agent"] = user_agent
    return requests.post(url, json=payload, headers=headers, timeout=timeout)
