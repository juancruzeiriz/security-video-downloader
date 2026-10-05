"""Motor de defensa del origen (Etapa 2): control de abuso por sesión.

El origen-fixture de la Etapa 1 sólo validaba firma/exp/acl. Acá sumamos los
controles de comportamiento que faltaban en el modelo de amenazas:

- **Rate limiting** por sesión: demasiados pedidos en una ventana -> 429.
- **Pacing / ráfaga**: pedir segmentos MÁS RÁPIDO que su duración real
  (lo que hace ``svd download --concurrency N`` o un ripper) -> 429 + alerta.
- **Reuso del token desde varias IP** (token compartido) -> 403 + alerta.
- **Concurrencia**: demasiadas sesiones activas a la vez -> 429.
- **Gate de playback**: exigir un evento de telemetría ``playback_started``
  antes de servir segmentos (opcional).

Es un arnés en memoria para el lab, no un servicio de producción: en real esto
vive en Redis/base con expiración y detrás de un WAF. Pero alcanza para escribir
una prueba de abuso por cada fila de la tabla de amenazas.

Todo el motor es **opt-in**: si ``SVD_DEFENSE`` no está en "1", ``check_request``
deja pasar todo (así el E2E de la Etapa 1 sigue midiendo el ataque "sin defensas").
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field


def _truthy(val: str | None) -> bool:
    return (val or "").strip().lower() in ("1", "true", "yes", "on")


@dataclass
class DefenseConfig:
    enabled: bool = False
    max_sessions: int = 3           # sesiones activas simultáneas permitidas
    rate_max: int = 120             # pedidos por ventana y por sesión
    rate_window: float = 60.0       # segundos de la ventana de rate limit
    max_ips: int = 1                # IPs distintas permitidas por sesión
    segment_duration: float = 2.0   # duración nominal de un segmento (#EXTINF)
    burst_allowance: int = 3        # segmentos que se pueden pedir "adelantados"
    require_playback: bool = False  # exigir telemetría playback_started antes de servir
    session_ttl: float = 300.0      # segundos para considerar una sesión "activa"

    @classmethod
    def from_env(cls) -> DefenseConfig:
        def num(name: str, default: float, cast=float):
            raw = os.environ.get(name)
            if raw in (None, ""):
                return default
            try:
                return cast(raw)
            except ValueError:
                return default

        return cls(
            enabled=_truthy(os.environ.get("SVD_DEFENSE")),
            max_sessions=int(num("SVD_MAX_SESSIONS", 3, int)),
            rate_max=int(num("SVD_RATE_MAX", 120, int)),
            rate_window=num("SVD_RATE_WINDOW", 60.0),
            max_ips=int(num("SVD_MAX_IPS", 1, int)),
            segment_duration=num("SVD_SEGMENT_DURATION", 2.0),
            burst_allowance=int(num("SVD_BURST_ALLOWANCE", 3, int)),
            require_playback=_truthy(os.environ.get("SVD_REQUIRE_PLAYBACK")),
            session_ttl=num("SVD_SESSION_TTL", 300.0),
        )


@dataclass
class Decision:
    allowed: bool
    reason: str = "ok"
    status: int = 200  # status HTTP sugerido cuando allowed=False (403 / 429)


@dataclass
class _SessionState:
    first_seen: float
    last_seen: float
    ips: set[str] = field(default_factory=set)
    requests: "deque[float]" = field(default_factory=deque)  # timestamps (rate limit)
    segments: int = 0            # segmentos servidos a esta sesión
    first_segment_at: float | None = None
    playback_started: bool = False


class DefenseEngine:
    """Estado de abuso en memoria, thread-safe (uvicorn sirve en varios hilos)."""

    def __init__(self, config: DefenseConfig | None = None) -> None:
        self.config = config or DefenseConfig()
        self._lock = threading.Lock()
        self._sessions: dict[str, _SessionState] = {}
        self.alerts: list[dict] = []

    # -- helpers -----------------------------------------------------------

    def _alert(self, kind: str, session: str, detail: str) -> None:
        self.alerts.append({"kind": kind, "session": session, "detail": detail, "at": time.time()})
        print(f"[alerta-abuso] {kind} session={session} {detail}")

    def _active_sessions(self, now: float) -> int:
        ttl = self.config.session_ttl
        return sum(1 for s in self._sessions.values() if now - s.last_seen <= ttl)

    def _prune(self, now: float) -> None:
        ttl = self.config.session_ttl
        dead = [sid for sid, s in self._sessions.items() if now - s.last_seen > ttl]
        for sid in dead:
            del self._sessions[sid]

    # -- API ---------------------------------------------------------------

    def note_telemetry(self, session: str | None, event: str | None, ip: str | None, now: float | None = None) -> None:
        """Registra un evento del reproductor. Alimenta el gate de playback."""
        if not session:
            return
        now = time.time() if now is None else now
        with self._lock:
            st = self._sessions.get(session)
            if st is None:
                st = _SessionState(first_seen=now, last_seen=now)
                self._sessions[session] = st
            st.last_seen = now
            if ip:
                st.ips.add(ip)
            if event == "playback_started":
                st.playback_started = True

    def check_request(
        self,
        session: str | None,
        ip: str | None,
        *,
        is_segment: bool,
        now: float | None = None,
    ) -> Decision:
        """Decide si servir el pedido. ``is_segment`` marca pedidos de .ts/.m4s.

        Devuelve una Decision; cuando ``allowed`` es False trae el motivo y el
        status HTTP sugerido (403 para binding/gate, 429 para abuso de ritmo).
        """
        if not self.config.enabled:
            return Decision(True)
        now = time.time() if now is None else now
        cfg = self.config
        sid = session or f"anon:{ip or '?'}"

        with self._lock:
            self._prune(now)
            st = self._sessions.get(sid)
            is_new = st is None
            if is_new:
                # ¿Entra una sesión más sin pasar el límite de concurrencia?
                if self._active_sessions(now) >= cfg.max_sessions:
                    self._alert("too_many_sessions", sid, f"activas>={cfg.max_sessions}")
                    return Decision(False, "too_many_sessions", 429)
                st = _SessionState(first_seen=now, last_seen=now)
                self._sessions[sid] = st

            st.last_seen = now
            if ip:
                st.ips.add(ip)

            # 1) Token reusado desde varias IP (compartido).
            if len(st.ips) > cfg.max_ips:
                self._alert("multi_ip", sid, f"ips={sorted(st.ips)}")
                return Decision(False, "multi_ip", 403)

            # 2) Rate limit por ventana deslizante.
            window_start = now - cfg.rate_window
            while st.requests and st.requests[0] < window_start:
                st.requests.popleft()
            if len(st.requests) >= cfg.rate_max:
                self._alert("rate_limited", sid, f"{len(st.requests)}/{cfg.rate_window}s")
                return Decision(False, "rate_limited", 429)
            st.requests.append(now)

            if is_segment:
                # 3) Gate de playback: exigir telemetría antes del primer segmento.
                if cfg.require_playback and not st.playback_started:
                    self._alert("no_playback", sid, "segmento pedido sin playback_started")
                    return Decision(False, "no_playback", 403)

                # 4) Pacing: no se puede ir más rápido que el tiempo real del video.
                if st.first_segment_at is None:
                    st.first_segment_at = now
                st.segments += 1
                elapsed = now - st.first_segment_at
                # Cuántos segmentos "deberían" haberse consumido a tiempo real,
                # más un colchón de arranque (buffer del reproductor).
                allowed_so_far = cfg.burst_allowance + int(elapsed / cfg.segment_duration) + 1
                if st.segments > allowed_so_far:
                    self._alert(
                        "too_fast",
                        sid,
                        f"segmentos={st.segments} en {elapsed:.2f}s (permitido~{allowed_so_far})",
                    )
                    return Decision(False, "too_fast", 429)

            return Decision(True)

    def snapshot(self) -> dict:
        """Estado resumido (para /debug y tests)."""
        with self._lock:
            now = time.time()
            return {
                "enabled": self.config.enabled,
                "active_sessions": self._active_sessions(now),
                "sessions": {
                    sid: {
                        "ips": sorted(s.ips),
                        "segments": s.segments,
                        "playback_started": s.playback_started,
                        "requests": len(s.requests),
                    }
                    for sid, s in self._sessions.items()
                },
                "alerts": list(self.alerts),
            }


# Singleton del proceso. ``reset`` lo reconstruye desde el entorno (útil en tests).
_engine: DefenseEngine | None = None
_engine_lock = threading.Lock()


def get_engine() -> DefenseEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = DefenseEngine(DefenseConfig.from_env())
        return _engine


def reset_engine(config: DefenseConfig | None = None) -> DefenseEngine:
    """Reconstruye el motor (desde ``config`` o desde el entorno). Para tests."""
    global _engine
    with _engine_lock:
        _engine = DefenseEngine(config or DefenseConfig.from_env())
        return _engine
