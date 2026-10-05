"""Descarga y reensamblado de un stream HLS protegido por token.

Es el "atacante" del lab: dado un host + token + playlist, intenta bajar todos
los segmentos y rearmarlos en un archivo, reportando el status HTTP de cada pedido
para medir la proteccion (cuantos 200 vs 403).

El token se adjunta VERBATIM como query ``?token=...`` (sin percent-encoding de
``~`` ``=`` ``*``), igual que esperan Akamai/Uploadcare.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

import requests

from . import hls

DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
)


def attach_token(url: str, token: str | None, session: str | None = None) -> str:
    """Pega el token (y opcionalmente la sesion) a la URL sin codificar el token.

    El token va VERBATIM (exp=..~acl=..~hmac=..). La ``session`` emula la que el
    reproductor presentaria (cookie/header) para satisfacer el binding del token.
    """
    parts: list[str] = []
    if token:
        parts.append(f"token={token}")
    if session:
        parts.append(f"session={session}")
    if not parts:
        return url
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}" + "&".join(parts)


@dataclass
class RequestLog:
    url: str
    status: int | None
    bytes: int = 0
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == 200 and self.error is None


@dataclass
class DownloadResult:
    logs: list[RequestLog] = field(default_factory=list)
    output_path: str | None = None
    segments_dir: str | None = None

    @property
    def status_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for log in self.logs:
            key = "error" if log.error else str(log.status)
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def all_ok(self) -> bool:
        return bool(self.logs) and all(log.ok for log in self.logs)


class Downloader:
    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        token: str | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        concurrency: int = 1,
        timeout: float = 30.0,
        session: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.token = token
        self.session_id = session
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = user_agent

    # -- fetch helpers -----------------------------------------------------

    def _get(self, url: str) -> tuple[requests.Response | None, RequestLog]:
        tokened = attach_token(url, self.token, self.session_id)
        start = time.perf_counter()
        try:
            resp = self.session.get(tokened, timeout=self.timeout)
        except requests.RequestException as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return None, RequestLog(url=url, status=None, elapsed_ms=elapsed, error=str(exc))
        elapsed = (time.perf_counter() - start) * 1000
        log = RequestLog(
            url=url,
            status=resp.status_code,
            bytes=len(resp.content),
            elapsed_ms=elapsed,
        )
        return resp, log

    def fetch_text(self, path_or_url: str) -> tuple[str | None, RequestLog]:
        url = hls.resolve(self.base_url, path_or_url)
        resp, log = self._get(url)
        if resp is not None and resp.status_code == 200:
            return resp.text, log
        return None, log

    # -- main flow ---------------------------------------------------------

    def select_variant(self, variants: list[hls.Variant], prefer: str | None) -> hls.Variant:
        """Elige una variante: por etiqueta (ej '480p'), 'highest', 'lowest', o la primera."""
        if not variants:
            raise ValueError("La master playlist no tiene variantes")
        if prefer in (None, "first"):
            return variants[0]
        if prefer == "highest":
            return max(variants, key=lambda v: v.bandwidth or 0)
        if prefer == "lowest":
            return min(variants, key=lambda v: v.bandwidth or 0)
        # match por resolucion tipo "480p" o "480"
        want = prefer.lower().rstrip("p")
        for v in variants:
            if v.height is not None and str(v.height) == want:
                return v
        for v in variants:
            if want in v.uri.lower():
                return v
        raise ValueError(
            f"No encontre la variante {prefer!r}; disponibles: {[v.uri for v in variants]}"
        )

    def download(
        self,
        playlist_path: str,
        out_path: str,
        segments_dir: str,
        variant: str | None = None,
        reassemble: bool = True,
    ) -> DownloadResult:
        result = DownloadResult(segments_dir=segments_dir)
        os.makedirs(segments_dir, exist_ok=True)

        text, log = self.fetch_text(playlist_path)
        result.logs.append(log)
        if text is None:
            return result  # no pudimos ni bajar la playlist (ej 403)

        playlist_url = hls.resolve(self.base_url, playlist_path)

        if hls.is_master(text):
            chosen = self.select_variant(hls.parse_master(text), variant)
            media_url = hls.resolve(playlist_url, chosen.uri)
            text, log = self.fetch_text(media_url)
            result.logs.append(log)
            if text is None:
                return result
            playlist_url = media_url

        media = hls.parse_media(text)
        if media.is_encrypted:
            # No desciframos: la Etapa 2 introduce AES-128 a proposito.
            print(
                "[aviso] La media playlist esta cifrada (#EXT-X-KEY). "
                "Se bajan los segmentos cifrados; el reensamblado no los descifra."
            )

        seg_urls = [hls.resolve(playlist_url, seg.uri) for seg in media.segments]
        saved: dict[int, str] = {}

        def worker(index_url: tuple[int, str]) -> tuple[int, RequestLog, str | None]:
            idx, url = index_url
            resp, slog = self._get(url)
            path = None
            if resp is not None and resp.status_code == 200:
                path = os.path.join(segments_dir, f"seg_{idx:05d}.ts")
                with open(path, "wb") as fh:
                    fh.write(resp.content)
            return idx, slog, path

        indexed = list(enumerate(seg_urls))
        if self.concurrency == 1:
            for item in indexed:
                idx, slog, path = worker(item)
                result.logs.append(slog)
                if path:
                    saved[idx] = path
        else:
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                futures = [pool.submit(worker, item) for item in indexed]
                for fut in as_completed(futures):
                    idx, slog, path = fut.result()
                    result.logs.append(slog)
                    if path:
                        saved[idx] = path

        # Reensamblar solo si bajamos TODOS los segmentos.
        if reassemble and saved and len(saved) == len(seg_urls):
            ordered = [saved[i] for i in sorted(saved)]
            result.output_path = reassemble_segments(ordered, out_path)
        return result


def _ffmpeg_available() -> bool:
    return shutil.which("ffmpeg") is not None


def reassemble_segments(segment_paths: list[str], out_path: str) -> str:
    """Une los segmentos en un archivo. Usa ffmpeg si esta; si no, concat binario .ts."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    if _ffmpeg_available():
        list_file = out.with_suffix(".segments.txt")
        with open(list_file, "w", encoding="utf-8") as fh:
            for seg in segment_paths:
                abspath = os.path.abspath(seg).replace("'", r"'\''")
                fh.write("file '" + abspath + "'\n")
        cmd = [
            "ffmpeg", "-y", "-f", "concat", "-safe", "0",
            "-i", str(list_file), "-c", "copy", str(out),
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        list_file.unlink(missing_ok=True)
        return str(out)

    # Fallback: concatenacion binaria (valida para MPEG-TS sin cifrar).
    ts_out = out.with_suffix(".ts")
    with open(ts_out, "wb") as dst:
        for seg in segment_paths:
            with open(seg, "rb") as src:
                shutil.copyfileobj(src, dst)
    return str(ts_out)
