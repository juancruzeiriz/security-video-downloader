"""Genera un HLS multi-calidad de muestra para el lab.

Usa ffmpeg con fuentes sinteticas (testsrc + tono) para NO depender de un video
real. Produce, bajo MEDIA_ROOT/<id>/adaptive_video/:

    master.m3u8
    variant_0/index.m3u8 + seg_###.ts   (480p)
    variant_1/index.m3u8 + seg_###.ts   (360p)

El acl /<id>/adaptive_video/* cubre todo el arbol.

Correr:  python -m lab_origin.make_sample [--id <uuid>] [--duration 6]
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

DEFAULT_ID = "demo0001-0000-0000-0000-000000000001"


def ffmpeg_available() -> bool:
    return shutil.which("ffmpeg") is not None


def build(media_root: str, video_id: str, duration: int = 6) -> str:
    out_dir = os.path.join(media_root, video_id, "adaptive_video")
    os.makedirs(out_dir, exist_ok=True)

    if not ffmpeg_available():
        raise RuntimeError(
            "ffmpeg no esta en el PATH. Instalalo o genera los segmentos a mano; "
            "el fixture solo necesita archivos .m3u8/.ts validos bajo " + out_dir
        )

    seg_pattern = os.path.join(out_dir, "variant_%v", "seg_%03d.ts")
    var_playlist = os.path.join(out_dir, "variant_%v", "index.m3u8")

    cmd = [
        "ffmpeg", "-y",
        "-f", "lavfi", "-i", f"testsrc=duration={duration}:size=854x480:rate=25",
        "-f", "lavfi", "-i", f"sine=frequency=1000:duration={duration}",
        "-map", "0:v", "-map", "1:a", "-map", "0:v", "-map", "1:a",
        "-c:v", "libx264", "-preset", "veryfast", "-g", "25", "-keyint_min", "25",
        "-sc_threshold", "0", "-c:a", "aac",
        "-b:v:0", "1400k", "-s:v:0", "854x480",
        "-b:v:1", "600k", "-s:v:1", "640x360",
        "-var_stream_map", "v:0,a:0 v:1,a:1",
        "-master_pl_name", "master.m3u8",
        "-f", "hls", "-hls_time", "2", "-hls_playlist_type", "vod",
        "-hls_segment_filename", seg_pattern,
        var_playlist,
    ]
    subprocess.run(cmd, check=True)
    _normalize_separators(out_dir)
    return out_dir


def _normalize_separators(out_dir: str) -> None:
    r"""ffmpeg en Windows escribe 'variant_0\index.m3u8' en el master; pasar a '/'."""
    for root, _dirs, files in os.walk(out_dir):
        for name in files:
            if name.endswith(".m3u8"):
                fp = os.path.join(root, name)
                with open(fp, "r", encoding="utf-8") as fh:
                    text = fh.read()
                with open(fp, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text.replace("\\", "/"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lab_origin.make_sample", description=__doc__.split("\n", 1)[0])
    parser.add_argument("--media-root", default=os.environ.get("SVD_MEDIA_ROOT", "media/hls"))
    parser.add_argument("--id", dest="video_id", default=DEFAULT_ID)
    parser.add_argument("--duration", type=int, default=6)
    args = parser.parse_args(argv)

    out_dir = build(args.media_root, args.video_id, args.duration)
    print(f"HLS de muestra generado en: {out_dir}")
    print(f"Playlist master: /{args.video_id}/adaptive_video/master.m3u8")
    print(f"acl sugerido:    /{args.video_id}/adaptive_video/*")
    return 0


if __name__ == "__main__":
    sys.exit(main())
