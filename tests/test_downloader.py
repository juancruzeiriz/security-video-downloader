"""End-to-end: el descargador ataca al origen-fixture en localhost.

Usa un arbol HLS sintetico (sin ffmpeg) para que corra en cualquier maquina.
Levanta uvicorn en un hilo y verifica 200 con token valido y 403 con tokens
vencidos / de otro acl.
"""

import os
import socket
import threading
import time

import pytest
import requests
import uvicorn

from svd import downloader as dl
from svd.tokens import sign

VIDEO_ID = "demo0001-0000-0000-0000-000000000001"
ACL = f"/{VIDEO_ID}/adaptive_video/*"
SECRET = "clave-de-prueba-super-larga-1234567890"

MASTER = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-STREAM-INF:BANDWIDTH=1400000,RESOLUTION=854x480
variant_0/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=600000,RESOLUTION=640x360
variant_1/index.m3u8
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


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _write_tree(root: str) -> None:
    base = os.path.join(root, VIDEO_ID, "adaptive_video")
    os.makedirs(os.path.join(base, "variant_0"), exist_ok=True)
    os.makedirs(os.path.join(base, "variant_1"), exist_ok=True)
    with open(os.path.join(base, "master.m3u8"), "w") as fh:
        fh.write(MASTER)
    for variant in ("variant_0", "variant_1"):
        with open(os.path.join(base, variant, "index.m3u8"), "w") as fh:
            fh.write(MEDIA)
        for i in range(2):
            with open(os.path.join(base, variant, f"seg_{i:03d}.ts"), "wb") as fh:
                fh.write(f"{variant}-segment-{i}".encode() * 100)


@pytest.fixture(scope="module")
def origin(tmp_path_factory):
    root = str(tmp_path_factory.mktemp("hls"))
    _write_tree(root)
    os.environ["SVD_SECRET"] = SECRET
    os.environ["SVD_MEDIA_ROOT"] = root
    os.environ["SVD_PROTECTED_PREFIX"] = "/"

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

    yield base_url
    server.should_exit = True
    thread.join(timeout=5)


def test_valid_token_downloads_all(origin, tmp_path):
    token = sign(SECRET, ACL, ttl=3600)
    client = dl.Downloader(base_url=origin, token=token)
    result = client.download(
        playlist_path=f"/{VIDEO_ID}/adaptive_video/master.m3u8",
        out_path=str(tmp_path / "out.mp4"),
        segments_dir=str(tmp_path / "segs"),
        variant="480p",
        reassemble=False,
    )
    assert result.all_ok, result.status_counts
    # master + media + 2 segmentos = 4 pedidos, todos 200
    assert result.status_counts == {"200": 4}


def test_expired_token_blocked(origin, tmp_path):
    token = sign(SECRET, ACL, expires_at=int(time.time()) - 10)
    client = dl.Downloader(base_url=origin, token=token)
    result = client.download(
        playlist_path=f"/{VIDEO_ID}/adaptive_video/master.m3u8",
        out_path=str(tmp_path / "out.mp4"),
        segments_dir=str(tmp_path / "segs"),
        reassemble=False,
    )
    assert not result.all_ok
    assert result.status_counts.get("403") == 1  # ni siquiera baja la master
    assert result.output_path is None


def test_foreign_acl_blocked(origin, tmp_path):
    token = sign(SECRET, "/otro-id/adaptive_video/*", ttl=3600)
    client = dl.Downloader(base_url=origin, token=token)
    result = client.download(
        playlist_path=f"/{VIDEO_ID}/adaptive_video/master.m3u8",
        out_path=str(tmp_path / "out.mp4"),
        segments_dir=str(tmp_path / "segs"),
        reassemble=False,
    )
    assert result.status_counts.get("403") == 1


def test_no_token_blocked(origin, tmp_path):
    client = dl.Downloader(base_url=origin, token=None)
    result = client.download(
        playlist_path=f"/{VIDEO_ID}/adaptive_video/master.m3u8",
        out_path=str(tmp_path / "out.mp4"),
        segments_dir=str(tmp_path / "segs"),
        reassemble=False,
    )
    assert result.status_counts.get("403") == 1


def test_reassemble_binary_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(dl, "_ffmpeg_available", lambda: False)
    segs = []
    for i in range(3):
        p = tmp_path / f"s{i}.ts"
        p.write_bytes(f"chunk{i}".encode())
        segs.append(str(p))
    out = dl.reassemble_segments(segs, str(tmp_path / "joined.mp4"))
    assert out.endswith(".ts")  # fallback cambia la extension
    assert open(out, "rb").read() == b"chunk0chunk1chunk2"
