"""Parseo de playlists HLS (.m3u8): master y media.

No depende de librerías externas: parsea las etiquetas que importan para el lab.
Referencia: RFC 8216 (tags #EXT-X-STREAM-INF, #EXTINF, #EXT-X-KEY, etc.).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin


@dataclass
class Variant:
    """Una entrada de una master playlist (#EXT-X-STREAM-INF)."""

    uri: str
    bandwidth: int | None = None
    resolution: str | None = None
    codecs: str | None = None

    @property
    def height(self) -> int | None:
        if not self.resolution:
            return None
        try:
            return int(self.resolution.lower().split("x")[1])
        except (IndexError, ValueError):
            return None


@dataclass
class SegmentKey:
    """#EXT-X-KEY — cifrado del segmento (aparece en la Etapa 2 con AES-128)."""

    method: str
    uri: str | None = None
    iv: str | None = None


@dataclass
class Segment:
    uri: str
    duration: float | None = None
    key: SegmentKey | None = None


@dataclass
class MediaPlaylist:
    segments: list[Segment] = field(default_factory=list)
    target_duration: int | None = None
    keys: list[SegmentKey] = field(default_factory=list)

    @property
    def is_encrypted(self) -> bool:
        return any(k.method and k.method.upper() != "NONE" for k in self.keys)


_ATTR_RE = re.compile(r'([A-Z0-9\-]+)=("[^"]*"|[^,]*)')


def _parse_attrs(line: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for key, value in _ATTR_RE.findall(line):
        attrs[key] = value.strip('"')
    return attrs


def is_master(text: str) -> bool:
    return "#EXT-X-STREAM-INF" in text


def parse_master(text: str) -> list[Variant]:
    """Extrae las variantes de una master playlist, en orden de aparición."""
    variants: list[Variant] = []
    lines = [ln.strip() for ln in text.splitlines()]
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("#EXT-X-STREAM-INF:"):
            attrs = _parse_attrs(line[len("#EXT-X-STREAM-INF:"):])
            uri = ""
            j = i + 1
            while j < len(lines):
                if lines[j] and not lines[j].startswith("#"):
                    uri = lines[j]
                    break
                j += 1
            bw = attrs.get("BANDWIDTH")
            variants.append(
                Variant(
                    uri=uri,
                    bandwidth=int(bw) if bw and bw.isdigit() else None,
                    resolution=attrs.get("RESOLUTION"),
                    codecs=attrs.get("CODECS"),
                )
            )
            i = j
        i += 1
    return variants


def parse_media(text: str) -> MediaPlaylist:
    """Extrae los segmentos (en orden) de una media playlist y sus claves."""
    pl = MediaPlaylist()
    current_key: SegmentKey | None = None
    pending_duration: float | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#EXT-X-TARGETDURATION:"):
            val = line.split(":", 1)[1]
            pl.target_duration = int(val) if val.isdigit() else None
        elif line.startswith("#EXT-X-KEY:"):
            attrs = _parse_attrs(line[len("#EXT-X-KEY:"):])
            current_key = SegmentKey(
                method=attrs.get("METHOD", "NONE"),
                uri=attrs.get("URI"),
                iv=attrs.get("IV"),
            )
            pl.keys.append(current_key)
        elif line.startswith("#EXTINF:"):
            dur = line[len("#EXTINF:"):].split(",", 1)[0]
            try:
                pending_duration = float(dur)
            except ValueError:
                pending_duration = None
        elif not line.startswith("#"):
            pl.segments.append(
                Segment(uri=line, duration=pending_duration, key=current_key)
            )
            pending_duration = None
    return pl


def resolve(base_url: str, uri: str) -> str:
    """Resuelve una URI de playlist (relativa o absoluta) contra la URL base.

    Normaliza backslashes a "/" porque algunos empaquetadores (ffmpeg en Windows)
    escriben separadores de Windows en las playlists.
    """
    return urljoin(base_url, uri.replace("\\", "/"))
