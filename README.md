# FinTrack — Фінансовий облік

Веб-сервіс для фінансового обліку: Node.js + Express бекенд, JSON-файлова БД, **bcrypt** для хешування паролів і **httpOnly cookie-сесії**.

## Що змінилось у цій версії

Раніше форма логіну не з'являлась, бо на клієнті `currentUser` відновлювався з `localStorage` без перевірки на сервері — будь-хто міг підставити `ft8_user=1` і одразу стати адміном. Тепер:

- Паролі зберігаються як bcrypt-хеші, ніколи не повертаються клієнту.
- Сесія тримається у httpOnly cookie `ft_session` з TTL 7 днів. Клієнт не має доступу до токена через JS.
- Усі API-ендпоінти захищені middleware `requireAuth` / `requireAdmin`.
- На клієнті при старті виконується `GET /api/me` — якщо не авторизований, рендериться форма логіну. Інакше — дашборд.
- Rate-limit на `/api/login` (10 спроб/хвилину з одного IP).

## Запуск локально

```bash
npm install
npm start
# Відкрити http://localhost:3000
```

## Деплой на Render.com (безкоштовно)

1. Push цього коду на GitHub.
2. New → Blueprint → підключіть репозиторій. Render підхопить `render.yaml`.
3. Або вручну: New → Web Service, Build Command `npm install`, Start Command `node server.js`, Plan Free.
4. Додайте Disk: Mount Path `/opt/render/project/src/db`, Size 1 GB.

## Запуск у Docker

```bash
docker build -t fintrack .
docker run -p 3000:3000 -v $(pwd)/db:/app/db fintrack
```

## Логін за замовчуванням

- Email: `admin@fintrack.local`
- Пароль: `admin`

**Одразу після першого входу зайдіть у Налаштування → Зміна пароля.**

## API

| Метод | Шлях | Хто | Що робить |
|---|---|---|---|
| POST | `/api/login` | будь-хто | Логін, виставляє cookie `ft_session` |
| POST | `/api/logout` | auth | Видаляє сесію |
| GET | `/api/me` | auth | Поточний юзер |
| POST | `/api/change-password` | auth | Зміна свого пароля |
| GET | `/api/db` | auth | Повний DB (без `passwordHash`) |
| PUT | `/api/db` | admin | Замінити DB цілком |
| POST | `/api/users` | admin | Створити юзера |
| PUT | `/api/users/:id` | admin | Оновити юзера |
| DELETE | `/api/users/:id` | admin | Видалити юзера + його сесії |

## Структура

```
.
├── package.json         # express, bcryptjs, cookie-parser
├── server.js            # API + статика
├── index.html           # SPA: login, dashboard, transactions, sites, analytics, users, settings
├── Dockerfile
├── render.yaml          # Render.com Blueprint
└── db/                  # створюється автоматично
    ├── db.json          # дані
    └── sessions.json    # активні сесії
```

## Що ще варто додати

- HTTPS у проді (Render надає автоматично).
- Бекапи `db/` (cron + S3, наприклад).
- 2FA через TOTP.
- Логування дій користувачів (audit log).
- Міграція з JSON на SQLite, коли транзакцій стане > ~10k.
