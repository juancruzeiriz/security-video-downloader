# security-video-downloader

Laboratorio para **aprender y endurecer** la protección de video en streaming
(HLS adaptativo + URLs firmadas con HMAC, estilo Akamai/Uploadcare), **sobre tu
propio contenido**.

La idea es montar el esquema que vas a usar en tu app real y después atacarlo vos
mismo en un entorno controlado, para medir qué tan fuerte es y, en una segunda
etapa, cerrar cada agujero.

> ⚠️ **Uso previsto: tu propio sistema.** El descargador apunta por defecto a
> `localhost` y toma el host/token como parámetros que *vos* generás. Usalo
> únicamente contra servidores que controlás o tenés permiso explícito para probar.

## Qué hay adentro

| Pieza | Rol | Dónde |
|------|-----|-------|
| `svd.tokens` | Firma/verifica tokens `exp=..~acl=..~hmac=..` (HMAC-SHA256, comparación en tiempo constante) | [src/svd/tokens.py](src/svd/tokens.py) |
| `svd.hls` | Parsea playlists HLS (master/media, `#EXT-X-KEY`) | [src/svd/hls.py](src/svd/hls.py) |
| `svd.downloader` | **El script que probás en la Fase 1**: baja los segmentos con el token y los junta en un `.mp4` | [src/svd/downloader.py](src/svd/downloader.py) |
| `svd.telemetry` | Manda el evento del reproductor (`/video-diagnostic/event`) | [src/svd/telemetry.py](src/svd/telemetry.py) |
| `svd.cli` | CLI `svd` (todo parametrizable por flag o `.env`) | [src/svd/cli.py](src/svd/cli.py) |
| `lab_origin.app` | **Origen-fixture local**: sirve el HLS validando el token (403 si falla) | [src/lab_origin/app.py](src/lab_origin/app.py) |
| `lab_origin.defense` | **Defensas Etapa 2**: rate limit, pacing, binding multi-IP, concurrencia, gate de playback | [src/lab_origin/defense.py](src/lab_origin/defense.py) |
| threat-model | La tabla de amenazas + el estado de cada contramedida (**Etapa 2**) | [docs/threat-model.md](docs/threat-model.md) |

## Requisitos

- Python 3.10+
- [ffmpeg](https://ffmpeg.org/) en el `PATH` (para generar el HLS de muestra y para
  reensamblar prolijo; si no está, el reensamblado cae a concatenación binaria `.ts`).

## Setup

```bash
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# (Linux/Mac: source .venv/bin/activate)

pip install -r requirements.txt
pip install -e .          # expone el comando `svd` y los paquetes
```

### Variables sensibles / parametrizables (`.env`)

Copiá `.env.example` a `.env` y completá los valores. El archivo `.env` está
gitignoreado y se carga solo al correr el CLI.

```bash
cp .env.example .env
```

| Variable | Qué es |
|----------|--------|
| `SVD_SECRET` | Clave HMAC que comparten backend y CDN/origen. Generala con `python -c "import secrets;print(secrets.token_hex(32))"` |
| `SVD_BASE_URL` | Host del origen (default `http://localhost:8000`). Acá ponés tu server real cuando lo pruebes |
| `SVD_TOKEN` | Token firmado `exp=..~acl=..~hmac=..` (podés pasarlo por `--token` en vez del `.env`) |
| `SVD_USER_AGENT` | User-Agent a enviar |
| `SVD_EVENT_PATH` | Ruta del endpoint de telemetría (default `/video-diagnostic/event`) |
| `SVD_MEDIA_ROOT` | (solo fixture) carpeta donde se genera/sirve el HLS |
| `SVD_PROTECTED_PREFIX` | (solo fixture) prefijo de rutas que exigen token |

## Paso a paso (Fase 1: bajar el video con un script)

### 1. Generá un HLS de muestra

```bash
python -m lab_origin.make_sample
```

Crea, bajo `media/hls/<id>/adaptive_video/`, un `master.m3u8` con dos calidades
(480p/360p), cada una con su `index.m3u8` y segmentos `.ts`. Te imprime el `acl`
sugerido.

### 2. Levantá el origen-fixture (valida el token como una CDN)

```bash
# necesita SVD_SECRET en el entorno/.env
uvicorn lab_origin.app:app --port 8000 --app-dir src
```

### 3. Generá un token firmado "a mano"

```bash
python -m svd.tokens sign --acl "/demo0001-0000-0000-0000-000000000001/adaptive_video/*" --ttl 3600
# -> exp=...~acl=...~hmac=...
```

(usa `SVD_SECRET` del entorno, o pasá `--secret`).

### 4. Corré el descargador — junta los segmentos en un `.mp4`

```bash
svd download \
  --base-url http://localhost:8000 \
  --token "exp=...~acl=/demo0001-0000-0000-0000-000000000001/adaptive_video/*~hmac=..." \
  --playlist "/demo0001-0000-0000-0000-000000000001/adaptive_video/master.m3u8" \
  --variant 480p \
  --out media/out/video.mp4
```

Imprime el status HTTP de **cada** pedido (para ver 200 vs 403) y, si bajó todos
los segmentos, reensambla el `.mp4`.

> Con tu app real: cambiás `--base-url` por tu host y `--token` por el que te
> devuelve tu backend. Nada más cambia.

### (Opcional) Emular la telemetría del reproductor

Todo el payload es parametrizable por flags o por un JSON (`--telemetry-payload`):

```bash
svd download ... --telemetry --video-id 1054602 --page-url "https://tu-app.com/curso/x" --provider uploadcare
# o solo el evento:
svd telemetry --base-url http://localhost:8000 --telemetry-payload payload.json
```

### 5. Probá que la protección funciona (casos de abuso)

Repetí el paso 4 con:
- un token **vencido** (`--expires-at` en el pasado al firmar), o
- un `acl` que **no** cubre la ruta (firmá con otro id),

y vas a ver **403** en todos los pedidos y ningún `.mp4`. Eso confirma que el
origen valida bien y que el script mide la protección.

## Tests

```bash
pytest
```

Cubre firma/verificación de tokens, parseo de playlists y un end-to-end del
descargador contra el origen-fixture (token válido → 200 + archivo; vencido /
ajeno / sin token → 403).

## Fase 2: evitar que esto pase (implementada)

Una vez confirmado que el video se puede bajar con un script, la Fase 2 cierra
cada agujero. El mapa ataque→control y el estado de cada uno están en
**[docs/threat-model.md](docs/threat-model.md)**. Las defensas de comportamiento
del origen son **opt-in**: se activan con `SVD_DEFENSE=1`.

```bash
# Origen con defensas activas (rate limit, pacing, binding multi-IP, etc.)
SVD_SECRET=... SVD_DEFENSE=1 SVD_MAX_IPS=1 SVD_REQUIRE_PLAYBACK=1 \
  uvicorn lab_origin.app:app --port 8000 --app-dir src
```

### Token atado a sesión / IP (binding)

```bash
# Token que sólo sirve para la sesión "abc123" y desde una IP concreta
python -m svd.tokens sign --acl "/<id>/adaptive_video/*" --ttl 120 \
  --session abc123 --ip 203.0.113.7

# El reproductor legítimo presenta su sesión; el downloader lo emula con --session
svd download --token "..." --session abc123 --playlist "/<id>/adaptive_video/master.m3u8"
```

Si copiás ese token a otra sesión u otra IP, el origen responde **403**
(`session_mismatch` / `ip_mismatch`): el campo va firmado, no se puede alterar.

### Tokens cortos + renovación

```bash
# El reproductor pide un token nuevo antes de que venza el actual
curl -X POST "http://localhost:8000/token/renew?token=<token-actual>&session=abc123"
# -> {"token": "<token-nuevo>", "ttl": 120}
```

### Rotación de clave sin cortar el servicio

```bash
# Clave nueva como primaria, la anterior sigue validando lo ya emitido
SVD_SECRET=<clave-nueva> SVD_SECRET_PREVIOUS=<clave-vieja> \
  uvicorn lab_origin.app:app --port 8000 --app-dir src
```

### Cifrado AES-128

```bash
python -m lab_origin.make_sample --encrypt   # genera HLS con #EXT-X-KEY AES-128
```

El downloader baja los segmentos cifrados pero **no** los descifra a propósito:
vas a ver el salto de dificultad (necesitás la clave AES, servida bajo token). El
único control que frena esto de verdad es DRM, que queda fuera del lab (requiere
un CDM y un packager comerciales).

### Suite de abuso

`pytest` corre, además de la Fase 1, una prueba por cada defensa (403/429/alerta):
rate limit, pacing anti-ráfaga, reuso multi-IP, concurrencia, gate de playback,
binding, rotación y el salto AES. Corre también en CI
(**[.github/workflows/ci.yml](.github/workflows/ci.yml)**).
