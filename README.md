# webguardjs

Детектор подозрительной активности на веб-странице, сервер приёма инцидентов на Fastify с PostgreSQL, минимальный dashboard и демо-страница. Алгоритм реализован как чистые функции в `packages/detector-core`.

## Структура

```
packages/
  detector-core/   # признаки / нормализация / скоринг
  detector-web/    # браузерные события / отправка инцидентов
  server/          # Fastify API + dashboard + Postgres
  demo/            # демка
infra/
  docker-compose.yml
  db/init.sql
```

## Алгоритм (core)

- Окно: скользящее окно, по умолчанию W=60 секунд.
- Признаки (F1..F8, F9 опционально): частота событий, регулярность интервалов, доля повторов, частота copy/cut, частота paste, скорость скролла (включает события и дистанцию), всплески навигации, экспорт/печать, отсутствие мыши.
- Нормализация: кусочно-линейное приведение к [0;1].

```
norm(x; a,b) = 0                 если x <= a
             = (x-a)/(b-a)       если a < x < b
             = 1                 если x >= b

norm_inv(cv; a,b) = 1 - norm(cv; a,b)
```

- Скоринг: взвешенная сумма нормализованных признаков.
- Веса: event_rate 0.14, interval_regularity 0.18, repetition_ratio 0.10,
  copy_activity 0.20, navigation_burst 0.12, export_intent 0.12,
  scroll_velocity 0.07, paste_activity 0.07.
- mouse_absence_factor есть, по умолчанию вес 0, переключаемое.
- Сглаживание: экспоненциальная скользящая средняя с alpha=0.35, risk = clamp01(ema).
- Пороги: warn 0.70, incident 0.85, cooldown 30s.
- Объяснимость: topSignals (топ-3 вклада), snapshot признаков, counters, reasonCodes.
- Конфиг по умолчанию в `packages/detector-core/src/config.ts`.

## Собираемые данные

Тип события, timestamp, тип элемента, длина выделения, delta скролла, попытки навигации и экспорта.

## Запуск

```
cp .env.example .env
docker compose -f infra/docker-compose.yml up --build
```

Сервер: `http://localhost:3000`

Dashboard: `http://localhost:3000/dashboard`

## Демка

```
npm install
npm run build -w @webguard/detector-web
npm run build -w @webguard/demo
```

Откройте `packages/demo/dist/index.html` в браузере. Демо отправляет инциденты на
`http://localhost:3000/api/v1/incidents` с `API_KEY=changeme` по умолчанию.
Для переопределения задайте `window.WEBGUARD_ENDPOINT` или `window.WEBGUARD_API_KEY` до `demo.js`.
Сервер должен быть запущен, чтобы записи появлялись в `/dashboard`.

## API

- `POST /api/v1/incidents`
  - Заголовок: `X-API-Key`
  - Тело: payload инцидента с risk, features, counters и top signals.
- `GET /api/v1/incidents?minRisk=&from=&to=&pageId=&sessionId=&limit=&offset=`
- `GET /dashboard`

## Тесты

```
npm test
npm run lint
npm run typecheck
```

Unit-тесты: нормализация, CV, расчёт признаков, скоринг, объяснимость.
Интеграционные тесты: Fastify API, запись в Postgres, фильтры. Укажите `DATABASE_URL`
или `PGHOST/PGUSER/PGPASSWORD/PGDATABASE`, если проект запущен без докера.

## MITRE ATT&CK

- Collection (T1114/T1213): copy/cut/paste, экспорт.
- Discovery (T1083): всплески навигации.
- Exfiltration (T1048): попытки print/download/export.
- Automation/Scripting (T1059): регулярность интервалов, повторяемость, отсутствие мыши.

## Server request analyzer

Server now keeps an in-memory request profile per key:

- `key = sessionId` from `x-webguard-session` or cookie `wg_sid`
- fallback: `ip|user-agent`

The analyzer computes `riskServer` in range `0..1` from request-side signals:

- `rps60`
- `burst5s`
- `cvInterArrival`
- `uniquePathRatio`
- `errorRatio`
- `telemetryAgeSec` (from heartbeat)
- `browserHeadersScore`

Risk is normalized with piecewise linear functions and smoothed with EMA (`alpha=0.35`).
Server decision ladder:

- `allow` for `< 0.55`
- `delay` for `0.55..0.70`
- `challenge` for `0.70..0.85`
- `ban` for `>= 0.85` (temporary, adaptive TTL 5-30 minutes)

`WEBGUARD_ENFORCE=0` (default): detect-only mode, no blocking effects.
`WEBGUARD_ENFORCE=1`: enable delay/challenge/ban enforcement on `/api/*` (except telemetry/risk).

For incidents, final score is fused with client risk:

`riskTotal = clamp01(max(riskClient, riskServer) + 0.15 * min(riskClient, riskServer))`

`incidents.risk` stores `riskTotal`, while server details are saved into `features.server`.

### New endpoints

- `POST /api/v1/telemetry/heartbeat`
  - Headers: `X-API-Key`, `x-webguard-session`
  - Body: `{ sessionId, pageId, ts }`
- `GET /api/v1/risk`

### Quick curl examples

Get current server risk for a key:

```bash
curl -i http://localhost:3000/api/v1/risk \
  -H "x-webguard-session: demo-session" \
  -H "User-Agent: Mozilla/5.0" \
  -H "Accept-Language: en-US" \
  -H "sec-ch-ua: \"Chromium\";v=\"121\"" \
  -H "sec-fetch-site: same-origin"
```

Send heartbeat telemetry:

```bash
curl -i -X POST http://localhost:3000/api/v1/telemetry/heartbeat \
  -H "content-type: application/json" \
  -H "X-API-Key: changeme" \
  -H "x-webguard-session: demo-session" \
  -d '{"sessionId":"demo-session","pageId":"p_demo","ts":1730000000000}'
```

Responses include:

- `X-WebGuard-Risk-Server`
- `X-WebGuard-Decision`

## WebGuard hardening config

### `wg_sid` cookie correlation

`detector-web` now ensures a `wg_sid` cookie exists.

- If cookie is missing, detector creates a session id and sets:
  - `Path=/`
  - `SameSite=Lax`
  - `Secure` only on HTTPS
- `x-webguard-session` is still sent for incident/heartbeat requests.
- On server key resolution priority is:
  1) `x-webguard-session`
  2) cookie `wg_sid`
  3) fallback `ip|user-agent`

### Config source

Server WebGuard settings are loaded from:

1. Built-in defaults
2. Optional JSON file via `WEBGUARD_CONFIG_PATH`
3. Env overrides

Example:

```bash
WEBGUARD_CONFIG_PATH=./config/webguard.json
WEBGUARD_ENFORCE=1
WEBGUARD_DEBUG=0
WEBGUARD_ENFORCE_ALLOWLIST=/api/v1/data,/api/v1/export,/api/v1/search
WEBGUARD_THRESHOLD_ALLOW=0.55
WEBGUARD_THRESHOLD_DELAY=0.70
WEBGUARD_THRESHOLD_CHALLENGE=0.85
```

### Enforcement path targeting

`shouldEnforceRequest` never applies enforcement to:

- `OPTIONS`
- `/api/v1/telemetry/heartbeat`
- `/api/v1/risk`
- `/dashboard`
- static prefixes (`/assets`, `/static`, `/demo`, `/favicon.ico`, `/robots.txt`)

Then:

- if `allowlist` is non-empty: enforce only matching prefixes
- otherwise: enforce on `/api/*`
- any `denylist` prefix is always excluded

### Debug endpoint gating

`/api/v1/risk` is gated by `WEBGUARD_DEBUG`:

- `WEBGUARD_DEBUG=1` (default): endpoint is available
- `WEBGUARD_DEBUG=0`: endpoint returns `404`
