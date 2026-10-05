"""CLI del lab: descargar un HLS protegido y/o mandar telemetria.

Todo lo sensible/variable se puede pasar por flag o por variable de entorno (.env):

    SVD_BASE_URL   host del origen            (default http://localhost:8000)
    SVD_TOKEN      token exp=..~acl=..~hmac=..
    SVD_USER_AGENT user-agent a enviar
    SVD_EVENT_PATH ruta del endpoint de telemetria (default /video-diagnostic/event)
    SVD_SECRET     clave HMAC (solo para generar tokens; ver `python -m svd.tokens`)

Las flags tienen prioridad sobre el entorno. Si existe un archivo .env en el
directorio actual, se carga automaticamente.

USO PREVISTO: probar TU PROPIO origen (localhost o un host que controlas).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import downloader as dl
from . import telemetry as tm


def _load_dotenv() -> None:
    """Carga .env si esta python-dotenv; si no, parser minimo KEY=VALUE."""
    env_path = os.path.join(os.getcwd(), ".env")
    if not os.path.exists(env_path):
        return
    try:
        from dotenv import load_dotenv  # type: ignore

        load_dotenv(env_path)
        return
    except Exception:
        pass
    with open(env_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _env(name: str, default: str | None = None) -> str | None:
    val = os.environ.get(name)
    return val if val not in (None, "") else default


def _print_summary(result: dl.DownloadResult) -> None:
    print("\n== Resumen de descarga ==")
    print(f"pedidos: {len(result.logs)}  ->  {result.status_counts}")
    for log in result.logs:
        tag = "OK " if log.ok else "XX "
        status = log.status if log.status is not None else f"ERR({log.error})"
        print(f"  {tag}{status}  {log.bytes:>9} B  {log.elapsed_ms:7.1f} ms  {log.url}")
    if result.output_path:
        print(f"\nArchivo reensamblado: {result.output_path}")
    elif result.all_ok:
        print("\n(todos los pedidos OK pero no se reensamblo: revisa --no-reassemble)")
    else:
        print("\nNo se reensamblo: no se bajaron todos los segmentos (proteccion efectiva?).")


def _cmd_download(args: argparse.Namespace) -> int:
    base_url = args.base_url or _env("SVD_BASE_URL") or dl.DEFAULT_BASE_URL
    token = args.token if args.token is not None else _env("SVD_TOKEN")
    user_agent = args.user_agent or _env("SVD_USER_AGENT") or dl.DEFAULT_USER_AGENT

    client = dl.Downloader(
        base_url=base_url,
        token=token,
        user_agent=user_agent,
        concurrency=args.concurrency,
        timeout=args.timeout,
        session=args.session,
    )

    # Telemetria opcional ANTES de bajar (emula al reproductor real).
    if args.telemetry:
        overrides = {}
        if args.telemetry_payload:
            overrides.update(tm.load_payload_file(args.telemetry_payload))
        for key in ("video_id", "page_url", "session_id", "provider", "source_host", "event"):
            val = getattr(args, key, None)
            if val is not None:
                overrides[key] = val
        payload = tm.build_payload(overrides)
        event_path = args.event_path or _env("SVD_EVENT_PATH") or tm.DEFAULT_EVENT_PATH
        try:
            resp = tm.send_event(base_url, payload, event_path=event_path, user_agent=user_agent)
            print(f"[telemetria] POST {event_path} -> {resp.status_code}")
        except Exception as exc:  # noqa: BLE001  (no bloquear la descarga por telemetria)
            print(f"[telemetria] fallo: {exc}")

    result = client.download(
        playlist_path=args.playlist,
        out_path=args.out,
        segments_dir=args.segments_dir,
        variant=args.variant,
        reassemble=not args.no_reassemble,
    )
    _print_summary(result)
    return 0 if (result.all_ok or not args.strict) else 2


def _cmd_telemetry(args: argparse.Namespace) -> int:
    base_url = args.base_url or _env("SVD_BASE_URL") or dl.DEFAULT_BASE_URL
    user_agent = args.user_agent or _env("SVD_USER_AGENT") or dl.DEFAULT_USER_AGENT
    overrides = {}
    if args.telemetry_payload:
        overrides.update(tm.load_payload_file(args.telemetry_payload))
    for key in ("video_id", "page_url", "session_id", "provider", "source_host", "event"):
        val = getattr(args, key, None)
        if val is not None:
            overrides[key] = val
    payload = tm.build_payload(overrides)
    event_path = args.event_path or _env("SVD_EVENT_PATH") or tm.DEFAULT_EVENT_PATH
    resp = tm.send_event(base_url, payload, event_path=event_path, user_agent=user_agent)
    print(f"POST {event_path} -> {resp.status_code}")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if resp.status_code in (200, 201, 204) else 2


def _add_telemetry_overrides(p: argparse.ArgumentParser) -> None:
    p.add_argument("--video-id", dest="video_id")
    p.add_argument("--page-url", dest="page_url")
    p.add_argument("--session-id", dest="session_id")
    p.add_argument("--provider")
    p.add_argument("--source-host", dest="source_host")
    p.add_argument("--event", help="ej: playback_started")
    p.add_argument("--event-path", dest="event_path", help="default /video-diagnostic/event")
    p.add_argument(
        "--telemetry-payload",
        dest="telemetry_payload",
        help="JSON con el payload (o overrides parciales) del evento",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="svd", description=__doc__.split("\n", 1)[0])

    # Flags comunes a los subcomandos. Van en un parser PADRE para que funcionen
    # DESPUES del subcomando (svd download --base-url ... --token ...).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--base-url", help="Host del origen (o env SVD_BASE_URL)")
    common.add_argument("--token", help="Token exp=..~acl=..~hmac=.. (o env SVD_TOKEN)")
    common.add_argument("--user-agent", dest="user_agent", help="User-Agent (o env SVD_USER_AGENT)")

    sub = parser.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("download", parents=[common], help="Baja y reensambla un HLS protegido")
    d.add_argument("--playlist", required=True, help="Ruta/URL de la playlist (master o media)")
    d.add_argument("--out", default="media/out/video.mp4", help="Archivo de salida")
    d.add_argument("--segments-dir", dest="segments_dir", default="media/out/segments")
    d.add_argument("--variant", help="480p | highest | lowest | first (para master playlists)")
    d.add_argument("--concurrency", type=int, default=1, help="Workers de descarga (default 1)")
    d.add_argument("--timeout", type=float, default=30.0)
    d.add_argument("--session", help="Id de sesion a presentar (para tokens con binding a sesion)")
    d.add_argument("--no-reassemble", dest="no_reassemble", action="store_true")
    d.add_argument("--strict", action="store_true", help="Exit code 2 si algun pedido no fue 200")
    d.add_argument("--telemetry", action="store_true", help="Manda un evento antes de bajar")
    _add_telemetry_overrides(d)
    d.set_defaults(func=_cmd_download)

    t = sub.add_parser("telemetry", parents=[common], help="Solo manda un evento de telemetria")
    _add_telemetry_overrides(t)
    t.set_defaults(func=_cmd_telemetry)

    return parser


def main(argv: list[str] | None = None) -> int:
    _load_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)
    # las flags globales pueden venir despues del subcomando tambien
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
