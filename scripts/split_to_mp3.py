"""Convierte un video (archivo o link de YouTube) a MP3 y lo corta en temas.

Formato de salida, igual que ``youtube_to_mp3.py``:

    MP3, 44.1 kHz, 128 kbps CBR, estereo, tamano maximo 30 MB por archivo.

Uso:
    python scripts/split_to_mp3.py
    python scripts/split_to_mp3.py otro_video.mp4 --tracks temas.txt [--out carpeta]
    python scripts/split_to_mp3.py "https://www.youtube.com/watch?v=..." [--tracks temas.txt]

Si la entrada es un link, primero baja el video en MP4 a ``convert_to_audio/``
(solo ese video, aunque el link sea de una lista).

De donde salen los temas, en este orden:
  1. ``--tracks``: archivo con una linea ``MM:SS - Titulo`` (o ``H:MM:SS``) por tema;
  2. los capitulos del video de YouTube, si tiene;
  3. DEFAULT_TRACKLIST, si la entrada es ``convert_to_audio/videoplayback.mp4``;
  4. si no, un solo MP3 con el video entero.
Cada tema termina donde empieza el siguiente y el ultimo va hasta el final.

Requisitos: ``ffmpeg`` y ``ffprobe`` en el PATH; ``pip install yt-dlp`` para links.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_INPUT = Path("convert_to_audio/videoplayback.mp4")

# Show de The Blues Ayres Band.
DEFAULT_TRACKLIST = """\
00:00 - Tren de carga
04:16 - Dra Vega
07:40 - Blues de la plantacion
12:17 - Zona roja
16:12 - Aire de niña
20:10 - Maniatado blues
28:11 - Cruento motin
32:25 - Blues local
35:55 - The thrill is gone
40:09 - Ven esta noche
47:42 - Chicken snack
49:12 - Rock del amanecer
52:53 - Hueso sabroso (Toma 2)
"""

SAMPLE_RATE = 44100
BITRATE = "128k"
CHANNELS = 2
MAX_BYTES = 30 * 1024 * 1024

LINE_RE = re.compile(r"^\s*((?:\d+:)?\d{1,2}:\d{2})\s*[-–—]\s*(.+?)\s*$")


@dataclass
class Track:
    number: int
    title: str
    start: float
    end: float | None  # None = hasta el final del video


def to_seconds(stamp: str) -> int:
    secs = 0
    for part in stamp.split(":"):
        secs = secs * 60 + int(part)
    return secs


def parse_tracklist(text: str) -> list[Track]:
    """Lee lineas ``MM:SS - Titulo``. Ignora vacias y las que empiezan con #."""
    entries = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = LINE_RE.match(line)
        if not m:
            raise ValueError(f"linea {n} no tiene el formato 'MM:SS - Titulo': {line!r}")
        entries.append((to_seconds(m.group(1)), m.group(2)))

    if not entries:
        raise ValueError("la lista de temas esta vacia")
    for (prev, _), (cur, title) in zip(entries, entries[1:]):
        if cur <= prev:
            raise ValueError(f"'{title}' empieza antes que el tema anterior")

    tracks = []
    for i, (start, title) in enumerate(entries):
        end = entries[i + 1][0] if i + 1 < len(entries) else None
        tracks.append(Track(i + 1, title, start, end))
    return tracks


def safe_filename(name: str) -> str:
    """Saca caracteres que Windows/Mac no aceptan en nombres de archivo."""
    name = re.sub(r'[\\/:*?"<>|]+', "", name)
    name = re.sub(r"\s+", " ", name).strip().rstrip(".")
    return name or "audio"


def tracks_from_chapters(chapters: list[dict]) -> list[Track]:
    return [Track(i + 1, c.get("title") or f"Tema {i + 1}", float(c["start_time"]),
                  float(c["end_time"]) if i + 1 < len(chapters) else None)
            for i, c in enumerate(chapters)]


def download_mp4(url: str, dest: Path) -> tuple[Path, str, list[Track]]:
    """Baja el video en MP4. Devuelve (archivo, titulo, temas por capitulos)."""
    try:
        import yt_dlp
    except ImportError:
        sys.exit("Falta yt-dlp: pip install yt-dlp")
    opts = {
        "format": "bv*[ext=mp4]+ba[ext=m4a]/b[ext=mp4]/bv*+ba/b",
        "merge_output_format": "mp4",
        "outtmpl": str(dest / "%(id)s.%(ext)s"),
        "noplaylist": True,
        "quiet": True,
        "no_warnings": True,
    }
    with yt_dlp.YoutubeDL(opts) as ydl:
        info = ydl.extract_info(url, download=True)
    path = Path(info["requested_downloads"][0]["filepath"])
    title = info.get("title") or info["id"]
    return path, title, tracks_from_chapters(info.get("chapters") or [])


def probe(src: Path) -> tuple[float, bool]:
    """Devuelve (duracion en segundos, tiene pista de audio)."""
    out = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration:stream=codec_type",
         "-of", "json", str(src)],
        check=True, capture_output=True, text=True,
    ).stdout
    info = json.loads(out)
    has_audio = any(s.get("codec_type") == "audio" for s in info.get("streams", []))
    return float(info["format"]["duration"]), has_audio


def cut_to_mp3(src: Path, dst: Path, track: Track, total: int) -> None:
    """Corta [start, end) y lo pasa a MP3 44.1 kHz / 128 kbps CBR / estereo."""
    cmd = ["ffmpeg", "-y", "-loglevel", "error", "-ss", str(track.start)]
    if track.end is not None:
        cmd += ["-t", str(track.end - track.start)]
    cmd += [
        "-i", str(src),
        "-vn",
        "-map_metadata", "-1",
        "-metadata", f"title={track.title}",
        "-metadata", f"track={track.number}/{total}",
        "-ar", str(SAMPLE_RATE),
        "-ac", str(CHANNELS),
        "-c:a", "libmp3lame",
        "-b:a", BITRATE,
        str(dst),
    ]
    subprocess.run(cmd, check=True)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("input", nargs="?", default=str(DEFAULT_INPUT),
                   help=f"video o link de YouTube (default: {DEFAULT_INPUT})")
    p.add_argument("--tracks", type=Path, help="archivo con 'MM:SS - Titulo' por linea")
    p.add_argument("--out", type=Path, help="carpeta de salida (default: media/mp3/<video>)")
    args = p.parse_args(argv)

    for tool in ("ffmpeg", "ffprobe"):
        if shutil.which(tool) is None:
            print(f"Falta {tool} en el PATH (https://ffmpeg.org/download.html).", file=sys.stderr)
            return 1
    chapters: list[Track] = []
    if re.match(r"https?://", args.input):
        DEFAULT_INPUT.parent.mkdir(parents=True, exist_ok=True)
        print(f"-> bajando {args.input}", flush=True)
        try:
            src, title, chapters = download_mp4(args.input, DEFAULT_INPUT.parent)
        except Exception as exc:  # yt-dlp tira errores de varios tipos
            print(f"  x no se pudo bajar: {exc}", file=sys.stderr)
            return 1
        print(f"  ok {src} ({title})")
    else:
        src = Path(args.input)
        title = src.stem
        if not src.is_file():
            print(f"No encuentro el video: {src.resolve()}", file=sys.stderr)
            return 1

    try:
        if args.tracks:
            tracks = parse_tracklist(args.tracks.read_text(encoding="utf-8"))
        elif chapters:
            print(f"  usando los {len(chapters)} capitulos del video")
            tracks = chapters
        elif src.resolve() == DEFAULT_INPUT.resolve():
            tracks = parse_tracklist(DEFAULT_TRACKLIST)
        else:
            print("  sin lista de temas ni capitulos: un solo MP3 con el video entero")
            tracks = [Track(1, title, 0, None)]
    except ValueError as exc:
        print(f"Lista de temas invalida: {exc}", file=sys.stderr)
        return 1

    duration, has_audio = probe(src)
    if not has_audio:
        print(f"{src.name} no tiene pista de audio.", file=sys.stderr)
        return 1
    late = [t for t in tracks if t.start >= duration]
    if late:
        print(f"El video dura {duration / 60:.1f} min y estos temas empiezan despues: "
              + ", ".join(t.title for t in late), file=sys.stderr)
        return 1

    out_dir = args.out or Path("media/mp3") / safe_filename(title)
    out_dir.mkdir(parents=True, exist_ok=True)

    failed = 0
    for t in tracks:
        name = safe_filename(t.title)
        dst = out_dir / (f"{t.number:02d} - {name}.mp3" if len(tracks) > 1 else f"{name}.mp3")
        try:
            cut_to_mp3(src, dst, t, len(tracks))
        except subprocess.CalledProcessError as exc:
            failed += 1
            print(f"  x {dst.name}: ffmpeg fallo ({exc.returncode})", file=sys.stderr)
            continue
        expected = (t.end if t.end is not None else duration) - t.start
        got, _ = probe(dst)
        if abs(got - expected) > 1:
            print(f"  ! {dst.name}: dura {got:.0f} s y deberia durar {expected:.0f} s")
        size = dst.stat().st_size
        mb = size / (1024 * 1024)
        if size > MAX_BYTES:
            print(f"  ! {dst.name}: {mb:.1f} MB supera el maximo de 30 MB. Recortalo antes de subirlo.")
        else:
            print(f"  ok {dst.name} ({mb:.1f} MB)")

    print(f"\nListo: {len(tracks) - failed}/{len(tracks)} temas en {out_dir.resolve()}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
