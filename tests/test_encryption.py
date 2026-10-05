"""Etapa 2 - cifrado AES-128: el salto de dificultad.

Con los segmentos cifrados (#EXT-X-KEY METHOD=AES-128), el downloader de la Etapa 1
los baja igual (son bytes), pero NO los descifra a proposito: el .mp4 que saldria
es basura. Este test deja esa propiedad clavada:

  - la media playlist se detecta como cifrada,
  - lo que baja el downloader es el CIPHERTEXT (no el plaintext),
  - solo con la clave AES (servida por el backend bajo token) se recupera el video.

La clave se sirve como un recurso protegido mas: pedirla sin token -> 403.
"""

from __future__ import annotations

import os
import socket
import threading
import time

import pytest
import requests
import uvicorn

from svd import downloader as dl
from svd import hls
from svd.tokens import sign

crypto = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from cryptography.hazmat.primitives import padding  # noqa: E402

VIDEO_ID = "enc00001-0000-0000-0000-000000000001"
ACL = f"/{VIDEO_ID}/adaptive_video/*"
SECRET = "clave-de-prueba-super-larga-1234567890"

KEY = bytes(range(16))            # clave AES-128 de 16 bytes
IV = bytes(range(16, 32))         # IV de 16 bytes
PLAINTEXT = b"PLAINTEXT-TS-PAYLOAD-" * 20


def _aes128_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


def _aes128_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(data) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


CIPHERTEXT = _aes128_cbc_encrypt(PLAINTEXT, KEY, IV)

MEDIA = f"""#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:2
#EXT-X-KEY:METHOD=AES-128,URI="/{VIDEO_ID}/adaptive_video/enc.key",IV=0x{IV.hex()}
#EXTINF:2.000,
seg_000.ts
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
    os.makedirs(base, exist_ok=True)
    with open(os.path.join(base, "index.m3u8"), "w") as fh:
        fh.write(MEDIA)
    with open(os.path.join(base, "seg_000.ts"), "wb") as fh:
        fh.write(CIPHERTEXT)
    with open(os.path.join(base, "enc.key"), "wb") as fh:
        fh.write(KEY)


@pytest.fixture(scope="module")
def origin(tmp_path_factory):
    root = str(tmp_path_factory.mktemp("hls_enc"))
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


def test_playlist_detected_as_encrypted():
    media = hls.parse_media(MEDIA)
    assert media.is_encrypted
    assert media.segments[0].key is not None
    assert media.segments[0].key.method.upper() == "AES-128"


def test_downloader_fetches_ciphertext_not_plaintext(origin, tmp_path):
    token = sign(SECRET, ACL, ttl=3600)
    client = dl.Downloader(base_url=origin, token=token)
    result = client.download(
        playlist_path=f"/{VIDEO_ID}/adaptive_video/index.m3u8",
        out_path=str(tmp_path / "out.mp4"),
        segments_dir=str(tmp_path / "segs"),
        reassemble=False,
    )
    assert result.all_ok, result.status_counts
    saved = tmp_path / "segs" / "seg_00000.ts"
    downloaded = saved.read_bytes()
    # Lo que bajo es ciphertext: NO es el plaintext...
    assert downloaded == CIPHERTEXT
    assert downloaded != PLAINTEXT
    # ...y solo con la clave AES se recupera el video.
    assert _aes128_cbc_decrypt(downloaded, KEY, IV) == PLAINTEXT


def test_key_requires_token(origin):
    key_url = f"{origin}/{VIDEO_ID}/adaptive_video/enc.key"
    assert requests.get(key_url).status_code == 403          # sin token
    token = sign(SECRET, ACL, ttl=3600)
    assert requests.get(key_url + f"?token={token}").status_code == 200
