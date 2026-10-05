# Modelo de amenazas y diseño de la Etapa 2

Este documento mapea cada ataque contra un esquema "HLS + URL firmada HMAC" a la
contramedida que lo frena. La **Etapa 1** demostró que, sin defensas extra, el
video se puede bajar con un script. La **Etapa 2** (ya implementada en este repo,
salvo lo marcado como "fuera del lab") agrega, una por una, las defensas de abajo,
cada una con su test de abuso en `tests/test_defense.py` / `tests/test_encryption.py`.

## Estado de implementación (Etapa 2)

| Control | Estado | Dónde |
|---------|--------|-------|
| Binding del token a sesión / IP (campos firmados) | ✅ | `svd.tokens` (`session`/`ip`), verificado en `lab_origin.app` |
| Tokens cortos + endpoint de renovación | ✅ | `POST /token/renew`, `SVD_RENEW_TTL` |
| Rotación de clave (2 claves válidas) | ✅ | `SVD_SECRET` + `SVD_SECRET_PREVIOUS` |
| Rate limiting por sesión | ✅ | `lab_origin.defense` (`SVD_RATE_MAX`/`SVD_RATE_WINDOW`) |
| Pacing / anti-ráfaga (más rápido que tiempo real) | ✅ | `lab_origin.defense` (`SVD_SEGMENT_DURATION`/`SVD_BURST_ALLOWANCE`) |
| Reuso del token desde varias IP | ✅ | `lab_origin.defense` (`SVD_MAX_IPS`) + alerta |
| Límite de sesiones simultáneas | ✅ | `lab_origin.defense` (`SVD_MAX_SESSIONS`) |
| Gate de playback vía telemetría | ✅ | `SVD_REQUIRE_PLAYBACK`, alimentado por `/video-diagnostic/event` |
| Cifrado AES-128 de HLS | ✅ | `make_sample --encrypt`; clave servida bajo token |
| DRM (Widevine/FairPlay/PlayReady) | ⛔ fuera del lab | requiere CDM + packager/licencia comercial |
| Marca de agua por usuario | ⛔ fuera del lab | requiere pipeline de transcodificación/overlay |

> Todas las defensas de comportamiento son **opt-in**: con `SVD_DEFENSE=1` el
> origen las aplica. Sin esa variable, el origen se comporta como en la Etapa 1
> (sólo firma/exp/acl) para poder seguir midiendo el ataque "sin defensas".

## Tabla de amenazas → controles

| Ataque | Qué debilidad aprovecha | Cómo se mitiga |
|--------|-------------------------|----------------|
| **Reutilizar el token de un usuario legítimo** | El token vale para todo el video (`acl` con `*`) y dura mucho | Tokens de pocos minutos que se renuevan; atados a sesión o IP |
| **Compartir el token / la URL con terceros** | La firma no sabe quién la usa | Vincular el token al usuario; limitar sesiones simultáneas; detectar el mismo token desde varias IP |
| **Juntar los segmentos en un archivo** (lo que hace la Fase 1) | Los segmentos viajan sin cifrar | Cifrado AES-128 de HLS como mínimo; DRM (Widevine/FairPlay) para protección real |
| **Sacar la clave AES del cliente** | Con AES-128 la clave termina en el navegador | DRM: la clave queda dentro de un módulo protegido (CDM) y no se expone |
| **Descarga masiva o automatizada** | No hay límites de ritmo | Rate limiting por sesión; alertas cuando se piden segmentos más rápido que en tiempo real o en paralelo |
| **Falsificar la firma** | Clave débil o filtrada, comparación insegura | Clave larga en Key Vault; rotación; comparación en tiempo constante; nunca firmar en el frontend |
| **Grabar la pantalla** | Inevitable si el usuario puede ver el video | Marca de agua visible o forense por usuario, para rastrear filtraciones |
| **Abuso de cuenta (compartir contraseña)** | Una cuenta, muchas personas | Límite de dispositivos; detección de ubicaciones imposibles; 2FA opcional |

## Diseño de las contramedidas (a implementar en Etapa 2)

### 1. Tokens cortos y renovables
- TTL de **minutos**, no horas. El `exp` largo del ejemplo (`exp=1791240149`) es el agujero principal.
- Endpoint de renovación: mientras dura el playback, el reproductor pide un token nuevo antes de que venza.
- Atar el token a un `session_id` firmado y, opcionalmente, a la IP del cliente.
- *En este repo:* `svd.tokens.sign(..., ttl=..., session=..., ip=...)` firma el binding; el origen lo verifica y `POST /token/renew` emite tokens cortos renovados.

### 2. Binding a usuario / sesión y control de concurrencia
- Incluir un identificador de sesión en el material firmado (ej. `acl` + `session`).
- Llevar en el backend un registro de sesiones activas por usuario; rechazar cuando se excede el límite.
- Alertar/bloquear si el mismo token aparece desde IPs/geografías incompatibles.
- *En este repo:* `lab_origin.defense` lleva el registro de sesiones activas (`SVD_MAX_SESSIONS`) y bloquea el reuso del token desde varias IP (`SVD_MAX_IPS`), con alerta.

### 3. Cifrado AES-128 de HLS
- Transcodificar con `#EXT-X-KEY:METHOD=AES-128,URI=...,IV=...`.
- La URI de la clave también va protegida por token y servida por el backend (no por la CDN pública).
- *En este repo:* `make_sample --encrypt` genera HLS AES-128 con la clave servida bajo token; `svd.hls` detecta `#EXT-X-KEY` y el downloader NO descifra a propósito, para que se vea el salto de dificultad.

### 4. DRM (protección real)
- Widevine / FairPlay / PlayReady: la clave de descifrado vive dentro del CDM del navegador y nunca se expone al JS.
- Es el único control que frena de verdad "juntar los segmentos" y "sacar la clave".

### 5. Rate limiting y detección de anomalías
- Límite de pedidos por sesión/IP por ventana de tiempo.
- Señal de abuso: segmentos pedidos **más rápido que su duración** (`#EXTINF`) o en paralelo masivo — justo lo que hace `svd download --concurrency N`.
- Alimentar esto con el endpoint de telemetría (`/video-diagnostic/event`).
- *En este repo:* `lab_origin.defense` hace rate limiting (`SVD_RATE_MAX`/`SVD_RATE_WINDOW`) y detecta el pedido de segmentos por encima del ritmo real (`too_fast`); la telemetría habilita el gate `SVD_REQUIRE_PLAYBACK`.

### 6. Higiene de la clave de firma
- Clave larga y aleatoria en **Key Vault** (en Azure, dado tu stack); nunca en el frontend ni en el repo.
- Rotación periódica (soportar 2 claves válidas durante la transición).
- Comparación en **tiempo constante** al verificar (ya implementado con `hmac.compare_digest`).
- *En este repo:* la verificación acepta una lista de claves (`SVD_SECRET` + `SVD_SECRET_PREVIOUS`) para rotar sin invalidar los tokens ya emitidos.

### 7. Marca de agua
- Visible (overlay con el id/email del usuario) o forense (modulación imperceptible por usuario).
- No evita la copia, pero permite rastrear quién filtró una grabación de pantalla.

## Cómo se valida cada control (suite de abuso — implementada)

Por cada fila de la tabla hay un test que intenta el abuso y verifica que la
respuesta sea **403/429** o que salte una alerta. Corren en CI (GitHub Actions,
`.github/workflows/ci.yml`) para que no haya regresiones:

| Abuso | Resultado esperado | Test |
|-------|--------------------|------|
| token vencido | 403 `expired` | `test_tokens` / `test_downloader` |
| ruta fuera del `acl` | 403 `acl_mismatch` | `test_tokens` / `test_downloader` |
| token de otra sesión | 403 `session_mismatch` | `test_defense::test_session_binding_blocks_wrong_session` |
| token desde otra IP | 403 `ip_mismatch` | `test_defense::test_ip_binding_blocks_other_ip` |
| token compartido (varias IP) | 403 `multi_ip` + alerta | `test_defense::test_multi_ip_reuse_blocked` |
| ráfaga más rápida que tiempo real | 429 `too_fast` + alerta | `test_defense::test_pacing_blocks_faster_than_realtime` |
| demasiados pedidos | 429 `rate_limited` | `test_defense::test_rate_limit_blocks_after_max` |
| demasiadas sesiones simultáneas | 429 `too_many_sessions` | `test_defense::test_concurrency_limit_blocks_extra_sessions` |
| segmento sin playback previo | 403 `no_playback` | `test_defense::test_require_playback_gate_http` |
| segmento cifrado sin la clave | no se descifra (ciphertext) | `test_encryption::test_downloader_fetches_ciphertext_not_plaintext` |
| clave rotada | token viejo sigue válido en la ventana | `test_defense::test_key_rotation_accepts_previous_secret` |

Un reproductor legítimo (1 segmento cada ~2s, 1 IP, con telemetría) nunca se
bloquea: ver `test_defense::test_pacing_allows_realtime_playback`.
