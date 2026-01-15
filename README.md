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
