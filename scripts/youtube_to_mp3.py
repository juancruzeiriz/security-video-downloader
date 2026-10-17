"""Baja videos de YouTube y los convierte a MP3 listo para subir a una plataforma.

Pensado para recuperar el audio de videos PROPIOS (p. ej. cuando perdiste el
acceso a la cuenta del canal). Formato de salida, segun lo que piden las
plataformas de distribucion:

    MP3, 44.1 kHz, 128 kbps CBR, estereo, tamano maximo 30 MB.

Uso:
    python scripts/youtube_to_mp3.py URL [URL ...] [--out carpeta]
    python scripts/youtube_to_mp3.py --file urls.txt

Si no pasas URLs, usa la lista DEFAULT_URLS de abajo.

Requisitos: ``pip install yt-dlp`` y ``ffmpeg`` en el PATH.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import yt_dlp
except ImportError:  # pragma: no cover - mensaje amigable
    sys.exit("Falta yt-dlp: pip install yt-dlp")

# Videos de The Blues Ayres Band.
DEFAULT_URLS = [
    "https://youtu.be/2FByk4bM7Ts",
    "https://youtu.be/hK-2qCBRzBs",
    "https://youtu.be/GqYaR5XKleI",
    "https://youtu.be/G8x7UGF09Lk",
]

SAMPLE_RATE = 44100
BITRATE = "128k"
CHANNELS = 2
MAX_BYTES = 30 * 1024 * 1024


def safe_filename(name: str) -> str:
    """Saca caracteres que Windows/Mac no aceptan en nombres de archivo."""
    name = re.sub(r'[\\/:*?"<>|]+', "", name).strip().rstrip(".")
    return name or "audio"


def download_audio(url: str, workdir: Path) -> tuple[Path, str]:
    """Baja la mejor pista de audio disponible. Devuelve (archivo, titulo)."""
    opts = {
        "format": "bestaudio/best",
        "outtmpl": str(workdir / "%(id)s.%(ext)s"),
        "noplaylist": True,
        "quiet": True,
        "no_warnings": True,
    }
    with yt_dlp.YoutubeDL(opts) as ydl:
        info = ydl.extract_info(url, download=True)
        return Path(ydl.prepare_filename(info)), info.get("title") or info["id"]


def to_mp3(src: Path, dst: Path) -> None:
    """Convierte a MP3 44.1 kHz / 128 kbps CBR / estereo, sin video."""
    cmd = [
        "ffmpeg", "-y", "-loglevel", "error",
        "-i", str(src),
        "-vn",
        "-map_metadata", "-1",
        "-ar", str(SAMPLE_RATE),
        "-ac", str(CHANNELS),
        "-c:a", "libmp3lame",
        "-b:a", BITRATE,
        str(dst),
    ]
    subprocess.run(cmd, check=True)


def process(url: str, out_dir: Path) -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        src, title = download_audio(url, Path(tmp))
        dst = out_dir / f"{safe_filename(title)}.mp3"
        to_mp3(src, dst)

    size = dst.stat().st_size
    mb = size / (1024 * 1024)
    if size > MAX_BYTES:
        print(f"  ! {dst.name}: {mb:.1f} MB supera el maximo de 30 MB "
              "(a 128 kbps entran ~32 minutos). Recortalo antes de subirlo.")
    else:
        print(f"  ok {dst.name} ({mb:.1f} MB)")
    return dst


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("urls", nargs="*", help="URLs de YouTube (default: DEFAULT_URLS)")
    p.add_argument("--file", type=Path, help="archivo de texto con una URL por linea")
    p.add_argument("--out", type=Path, default=Path("media/mp3"), help="carpeta de salida")
    args = p.parse_args(argv)

    if shutil.which("ffmpeg") is None:
        print("Falta ffmpeg en el PATH (https://ffmpeg.org/download.html).", file=sys.stderr)
        return 1

    urls = list(args.urls)
    if args.file:
        urls += [ln.strip() for ln in args.file.read_text().splitlines()
                 if ln.strip() and not ln.startswith("#")]
    urls = urls or DEFAULT_URLS

    args.out.mkdir(parents=True, exist_ok=True)
    failed = 0
    for url in urls:
        print(f"-> {url}")
        try:
            process(url, args.out)
        except Exception as exc:  # seguimos con el resto aunque uno falle
            failed += 1
            print(f"  x error: {exc}", file=sys.stderr)

    print(f"\nListo: {len(urls) - failed}/{len(urls)} archivos en {args.out.resolve()}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
