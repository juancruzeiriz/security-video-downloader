# Modelo de amenazas y diseño de la Etapa 2

Este documento mapea cada ataque contra un esquema "HLS + URL firmada HMAC" a la
contramedida que lo frena. La **Etapa 1** (este repo) demuestra que, sin defensas
extra, el video se puede bajar con un script. La **Etapa 2** implementa, una por
una, las defensas de abajo — recién después de confirmar el ataque en local.

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
- *En este repo:* `svd.tokens.sign(..., ttl=...)` ya soporta TTL corto; falta el endpoint de renovación y el binding.

### 2. Binding a usuario / sesión y control de concurrencia
- Incluir un identificador de sesión en el material firmado (ej. `acl` + `session`).
- Llevar en el backend un registro de sesiones activas por usuario; rechazar cuando se excede el límite.
- Alertar/bloquear si el mismo token aparece desde IPs/geografías incompatibles.

### 3. Cifrado AES-128 de HLS
- Transcodificar con `#EXT-X-KEY:METHOD=AES-128,URI=...,IV=...`.
- La URI de la clave también va protegida por token y servida por el backend (no por la CDN pública).
- *En este repo:* `svd.hls` ya detecta `#EXT-X-KEY` (`MediaPlaylist.is_encrypted`); el downloader NO descifra a propósito, para que se vea el salto de dificultad.

### 4. DRM (protección real)
- Widevine / FairPlay / PlayReady: la clave de descifrado vive dentro del CDM del navegador y nunca se expone al JS.
- Es el único control que frena de verdad "juntar los segmentos" y "sacar la clave".

### 5. Rate limiting y detección de anomalías
- Límite de pedidos por sesión/IP por ventana de tiempo.
- Señal de abuso: segmentos pedidos **más rápido que su duración** (`#EXTINF`) o en paralelo masivo — justo lo que hace `svd download --concurrency N`.
- Alimentar esto con el endpoint de telemetría (`/video-diagnostic/event`).

### 6. Higiene de la clave de firma
- Clave larga y aleatoria en **Key Vault** (en Azure, dado tu stack); nunca en el frontend ni en el repo.
- Rotación periódica (soportar 2 claves válidas durante la transición).
- Comparación en **tiempo constante** al verificar (ya implementado con `hmac.compare_digest`).

### 7. Marca de agua
- Visible (overlay con el id/email del usuario) o forense (modulación imperceptible por usuario).
- No evita la copia, pero permite rastrear quién filtró una grabación de pantalla.

## Cómo se valida cada control (suite de abuso — pendiente)

Para la Etapa 2, por cada fila de la tabla escribir un test que intente el abuso y
verifique que la respuesta sea **403** o que salte una alerta:

- token vencido → 403
- token de otro usuario/sesión → 403
- ruta fuera del `acl` → 403
- ráfaga de pedidos por encima del ritmo real → rate-limited / alerta
- segmento cifrado sin la clave → no se puede reensamblar

Y sumarlo al CI (GitHub Actions) para que no haya regresiones.
