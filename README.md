# webguardjs

`webguardjs` это учебный проект для Всероссийской олимпиады школьников по информатике, профиль Информационная безопасность.

Идея: на клиенте считаем риск подозрительной активности, на сервере дополняем его поведенческими сигналами и сохраняем инциденты в PostgreSQL. Плюс есть простой dashboard для разбора случаев.

## Что внутри

- `packages/detector-core` - алгоритмы и скоринг
- `packages/detector-web` - сбор клиентских событий и отправка телеметрии
- `packages/server` - Fastify API, серверный анализ и dashboard
- `packages/demo` - демо-страница для локального прогона
- `db/init.sql` - схема БД
- `docker-compose.yml` и `docker-compose.test.yml` - dev и test окружение
- `scripts/` - нагрузка и генерация графиков

## Быстрый старт

```bash
cp .env.example .env
docker compose up --build
```

После старта:

- API: `http://localhost:3000`
- Dashboard: `http://localhost:3000/dashboard`

## Запуск демо

```bash
npm install
npm run build -w @webguard/detector-web
npm run build -w @webguard/demo
```

Открой `packages/demo/dist/index.html` в браузере.

По умолчанию демо шлет данные в `http://localhost:3000/api/v1/incidents` с `API_KEY=changeme`.

## Основные API

- `POST /api/v1/incidents`
- `GET /api/v1/incidents`
- `POST /api/v1/telemetry/heartbeat`
- `GET /api/v1/risk`
- `GET /dashboard`

## Локальная разработка

```bash
npm run build
npm run test
npm run lint
npm run typecheck
```

Разделение тестов:

```bash
npm run test:unit
npm run test:integration
```

Изолированная интеграционная среда:

```bash
npm run test:env:up
npm run test:integration:isolated
npm run test:env:down
```

## Нагрузочные прогоны

```bash
npm run load:risk
npm run load:incidents
```

Пример с параметрами:

```bash
node scripts/load-test.mjs --target incidents --baseUrl http://127.0.0.1:3300 --concurrency 50 --durationSec 60
```

## Артефакты для графиков риска

```bash
npm run risk:artifacts
```

Результаты будут в `docs/`.

## Статус проекта

Проект уже почти закончен, сейчас нужны только мелкие корректировки. Прототип протестирован в реальной среде: модуль ставили на сайт школы по согласованию.
