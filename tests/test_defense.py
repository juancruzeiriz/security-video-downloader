"""Suite de abuso de la Etapa 2: una prueba por fila del modelo de amenazas.

Dos capas:
  - Tests unitarios del motor (``DefenseEngine``) con ``now`` inyectado:
    rate limit, pacing (anti-rafaga), reuso multi-IP, concurrencia.
  - Tests HTTP contra el origen-fixture: binding de sesion/IP, gate de playback,
    rotacion de clave, renovacion de token.

Cada uno intenta el abuso y verifica que la respuesta sea 403/429 o que salte una
alerta. Es lo que suma al CI para que no haya regresiones en las defensas.
"""

from __future__ import annotations

import os
import socket
import threading
import time

import pytest
import requests
import uvicorn

from lab_origin import defense
from lab_origin.defense import DefenseConfig, DefenseEngine
from svd.tokens import sign

VIDEO_ID = "demo0001-0000-0000-0000-000000000001"
ACL = f"/{VIDEO_ID}/adaptive_video/*"
SECRET = "clave-de-prueba-super-larga-1234567890"

MASTER = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-STREAM-INF:BANDWIDTH=1400000,RESOLUTION=854x480
variant_0/index.m3u8
"""

MEDIA = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:2
#EXTINF:2.000,
seg_000.ts
#EXTINF:2.000,
seg_001.ts
#EXT-X-ENDLIST
"""


# ===========================================================================
# Capa 1: motor de defensa (unit, deterministico con now inyectado)
# ===========================================================================

def test_rate_limit_blocks_after_max():
    eng = DefenseEngine(DefenseConfig(enabled=True, rate_max=3, rate_window=60, max_ips=99))
    t = 1000.0
    for _ in range(3):
        assert eng.check_request("S", "1.1.1.1", is_segment=False, now=t).allowed
    blocked = eng.check_request("S", "1.1.1.1", is_segment=False, now=t)
    assert not blocked.allowed
    assert blocked.reason == "rate_limited"
    assert blocked.status == 429


def test_rate_limit_recovers_after_window():
    eng = DefenseEngine(DefenseConfig(enabled=True, rate_max=2, rate_window=10, max_ips=99))
    assert eng.check_request("S", "1.1.1.1", is_segment=False, now=0).allowed
    assert eng.check_request("S", "1.1.1.1", is_segment=False, now=1).allowed
    assert not eng.check_request("S", "1.1.1.1", is_segment=False, now=2).allowed
    # pasada la ventana, vuelve a pasar
    assert eng.check_request("S", "1.1.1.1", is_segment=False, now=20).allowed


def test_pacing_blocks_faster_than_realtime():
    # Pedir muchos segmentos al instante (lo que hace un ripper) dispara too_fast.
    eng = DefenseEngine(DefenseConfig(
        enabled=True, rate_max=999, max_ips=99, segment_duration=2.0, burst_allowance=3,
    ))
    allowed = 0
    for _ in range(20):
        d = eng.check_request("S", "1.1.1.1", is_segment=True, now=1000.0)  # mismo instante
        if d.allowed:
            allowed += 1
        else:
            assert d.reason == "too_fast"
            assert d.status == 429
            break
    else:
        pytest.fail("nunca se disparo too_fast")
    # Con allowance=3 y elapsed=0, deja pasar ~4 (3 + 0 + 1) y bloquea el 5to.
    assert allowed == 4


def test_pacing_allows_realtime_playback():
    # Un reproductor real pide 1 segmento cada ~2s: nunca se bloquea.
    eng = DefenseEngine(DefenseConfig(
        enabled=True, rate_max=999, max_ips=99, segment_duration=2.0, burst_allowance=3,
    ))
    for i in range(30):
        d = eng.check_request("S", "1.1.1.1", is_segment=True, now=1000.0 + i * 2.0)
        assert d.allowed, f"segmento {i} bloqueado: {d.reason}"


def test_multi_ip_reuse_blocked():
    eng = DefenseEngine(DefenseConfig(enabled=True, rate_max=999, max_ips=1))
    assert eng.check_request("S", "1.1.1.1", is_segment=False, now=0).allowed
    d = eng.check_request("S", "2.2.2.2", is_segment=False, now=1)  # mismo token, otra IP
    assert not d.allowed
    assert d.reason == "multi_ip"
    assert d.status == 403
    assert any(a["kind"] == "multi_ip" for a in eng.alerts)


def test_concurrency_limit_blocks_extra_sessions():
    eng = DefenseEngine(DefenseConfig(enabled=True, max_sessions=2, rate_max=999, max_ips=99))
    assert eng.check_request("S1", "1.1.1.1", is_segment=False, now=0).allowed
    assert eng.check_request("S2", "1.1.1.2", is_segment=False, now=0).allowed
    d = eng.check_request("S3", "1.1.1.3", is_segment=False, now=0)
    assert not d.allowed
    assert d.reason == "too_many_sessions"
    assert d.status == 429


def test_playback_gate_requires_telemetry():
    eng = DefenseEngine(DefenseConfig(enabled=True, require_playback=True, rate_max=999, max_ips=99))
    # Segmento antes del evento -> bloqueado.
    d = eng.check_request("S", "1.1.1.1", is_segment=True, now=0)
    assert not d.allowed and d.reason == "no_playback" and d.status == 403
    # Llega la telemetria -> ahora si.
    eng.note_telemetry("S", "playback_started", "1.1.1.1", now=1)
    assert eng.check_request("S", "1.1.1.1", is_segment=True, now=2).allowed


def test_disabled_engine_allows_everything():
    eng = DefenseEngine(DefenseConfig(enabled=False, rate_max=1, max_ips=1))
    for _ in range(10):
        assert eng.check_request("S", "1.1.1.1", is_segment=True, now=0).allowed


# ===========================================================================
# Capa 2: HTTP contra el origen-fixture
# ===========================================================================

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _write_tree(root: str) -> None:
    base = os.path.join(root, VIDEO_ID, "adaptive_video", "variant_0")
    os.makedirs(base, exist_ok=True)
    top = os.path.join(root, VIDEO_ID, "adaptive_video")
    with open(os.path.join(top, "master.m3u8"), "w") as fh:
        fh.write(MASTER)
    with open(os.path.join(base, "index.m3u8"), "w") as fh:
        fh.write(MEDIA)
    for i in range(2):
        with open(os.path.join(base, f"seg_{i:03d}.ts"), "wb") as fh:
            fh.write(f"segment-{i}".encode() * 50)


@pytest.fixture(scope="module")
def origin(tmp_path_factory):
    root = str(tmp_path_factory.mktemp("hls_def"))
    _write_tree(root)
    os.environ["SVD_SECRET"] = SECRET
    os.environ["SVD_MEDIA_ROOT"] = root
    os.environ["SVD_PROTECTED_PREFIX"] = "/"
    os.environ["SVD_TRUST_XFF"] = "1"   # lab: permite simular IPs de cliente en los tests
    os.environ["SVD_DEBUG"] = "1"

    from lab_origin.app import app

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            if requests.get(base_url + "/healthz", timeout=1).status_code == 200:
                break
        except requests.RequestException:
            time.sleep(0.1)
    else:
        raise RuntimeError("el origen-fixture no levanto a tiempo")

    yield base_url, root
    server.should_exit = True
    thread.join(timeout=5)


def _master_url(base_url: str, token: str, *, session: str | None = None) -> str:
    url = f"{base_url}/{VIDEO_ID}/adaptive_video/master.m3u8?token={token}"
    if session is not None:
        url += f"&session={session}"
    return url


def test_session_binding_blocks_wrong_session(origin, monkeypatch):
    base_url, _ = origin
    monkeypatch.setenv("SVD_DEFENSE", "1")
    defense.reset_engine()
    token = sign(SECRET, ACL, ttl=3600, session="S1")

    # sesion correcta -> 200
    assert requests.get(_master_url(base_url, token, session="S1")).status_code == 200
    # sesion equivocada -> 403 session_mismatch
    r = requests.get(_master_url(base_url, token, session="S2"))
    assert r.status_code == 403 and "session_mismatch" in r.text
    # sin sesion -> 403
    assert requests.get(_master_url(base_url, token)).status_code == 403


def test_ip_binding_blocks_other_ip(origin, monkeypatch):
    base_url, _ = origin
    monkeypatch.setenv("SVD_DEFENSE", "1")
    monkeypatch.setenv("SVD_MAX_IPS", "99")  # aislar: queremos ver ip_mismatch, no multi_ip
    defense.reset_engine()
    token = sign(SECRET, ACL, ttl=3600, ip="203.0.113.7")

    ok = requests.get(_master_url(base_url, token), headers={"X-Forwarded-For": "203.0.113.7"})
    assert ok.status_code == 200
    bad = requests.get(_master_url(base_url, token), headers={"X-Forwarded-For": "198.51.100.9"})
    assert bad.status_code == 403 and "ip_mismatch" in bad.text


def test_require_playback_gate_http(origin, monkeypatch):
    base_url, _ = origin
    monkeypatch.setenv("SVD_DEFENSE", "1")
    monkeypatch.setenv("SVD_REQUIRE_PLAYBACK", "1")
    monkeypatch.setenv("SVD_MAX_IPS", "99")
    defense.reset_engine()
    token = sign(SECRET, ACL, ttl=3600, session="PB")
    seg = f"{base_url}/{VIDEO_ID}/adaptive_video/variant_0/seg_000.ts?token={token}&session=PB"

    # segmento antes de la telemetria -> 403 no_playback
    r = requests.get(seg)
    assert r.status_code == 403 and "no_playback" in r.text

    # mandamos el evento de telemetria para esa sesion
    requests.post(base_url + "/video-diagnostic/event",
                  json={"event": "playback_started", "session_id": "PB"})
    # ahora el segmento se sirve
    assert requests.get(seg).status_code == 200


def test_key_rotation_accepts_previous_secret(origin, monkeypatch):
    base_url, _ = origin
    # Claves de PRUEBA (no son secretos reales): se arman en runtime y con baja
    # entropia a proposito. La rotacion no depende del valor concreto.
    new_key = "rotation-primary-key-" + "n" * 8
    old_key = "rotation-previous-key-" + "o" * 8
    bogus_key = "rotation-unused-key-" + "u" * 8

    # token firmado con la clave VIEJA
    token_old = sign(old_key, ACL, ttl=3600)
    # el origen ahora tiene clave nueva como primaria y la vieja como previous
    monkeypatch.setenv("SVD_SECRET", new_key)
    monkeypatch.setenv("SVD_SECRET_PREVIOUS", old_key)
    defense.reset_engine()

    assert requests.get(_master_url(base_url, token_old)).status_code == 200
    # un token firmado con una clave random (no vigente) -> 403
    token_bogus = sign(bogus_key, ACL, ttl=3600)
    assert requests.get(_master_url(base_url, token_bogus)).status_code == 403


def test_token_renew_issues_fresh_short_token(origin, monkeypatch):
    base_url, _ = origin
    monkeypatch.setenv("SVD_SECRET", SECRET)
    monkeypatch.delenv("SVD_SECRET_PREVIOUS", raising=False)
    monkeypatch.setenv("SVD_RENEW_TTL", "120")
    defense.reset_engine()

    token = sign(SECRET, ACL, ttl=3600, session="RS")
    r = requests.post(base_url + f"/token/renew?token={token}&session=RS")
    assert r.status_code == 200
    fresh = r.json()["token"]
    assert fresh != token
    # el token renovado sirve para bajar
    assert requests.get(_master_url(base_url, fresh, session="RS")).status_code == 200

    # un token vencido NO se renueva
    expired = sign(SECRET, ACL, expires_at=int(time.time()) - 10, session="RS")
    r2 = requests.post(base_url + f"/token/renew?token={expired}&session=RS")
    assert r2.status_code == 403 and "expired" in r2.text
