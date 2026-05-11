# FinTrack — Фінансовий облік

Самохостова веб-аплікація для фінансового обліку арбітражних/SEO команд. Замінює потребу у Finmap (та сумісна з його експортом): транзакції, сайти, SEO-спеціалісти, команди, P&L-аналітика, права доступу, мульти-юзер з ролями.

## Що це за сервіс

FinTrack — single-page application (Node.js + Express бекенд, vanilla JS фронт в `index.html`, JSON-файлова БД на диску) для обліку фінансових операцій у структурі «сайт → команда → SEO». Основні можливості:

- **Транзакції** — додавання/редагування доходів і витрат у USD або EUR (з конвертацією за курсом, який задається у Налаштуваннях). Підтримка розподілу однієї транзакції між кількома командами або SEO у відсотках/сумах.
- **Сайти** — каталог доменів, прив'язаних до команди й SEO; бекенд автоматично роздає сайти між юзерами за їх правами.
- **SEO-спеціалісти й команди** — довідники з кольоровими бейджами; зміна назви/прив'язки масово оновлює всі залежні транзакції та сайти.
- **Аналітика (P&L)** — дашборд з прибутком, доходом, витратами, маржою та ROI у розрізі команди → SEO → сайт. Маржа і ROI видимі тільки адміністратору.
- **Імпорт/експорт** — `.xlsx` у форматі Finmap (всі 16 колонок) або `.json` бекап усієї БД. Імпорт автоматично розгортає split-групи Finmap у окремі транзакції та зливає дублікати команд/категорій (case-insensitive).
- **Користувачі й права** — ролі `admin` / `custom`. Кастомні юзери можуть мати whitelist команд, категорій, SEO, сайтів і окремі прапорці (додавати/редагувати/видаляти транзакції, доступ до аналітики, доступ до імпорту). Адмін бачить кнопку 👁 «Переглянути як» для емуляції чужого набору прав без перевходу.
- **Сесії й безпека** — bcrypt-хеші паролів, httpOnly cookie-сесії з TTL 7 днів, файлові сесії з cleanup-таймером, rate-limits на логін/запис/імпорт, audit log, atomic write з `.bak` бекапом БД, strict whitelisted static (не віддає `server.js` / `db.json`).

## Запуск локально

```bash
npm install
npm start
# Відкрити http://localhost:3000
```

## Деплой на Render.com

1. Push коду на GitHub.
2. New → Blueprint → підключіть репозиторій, Render підхопить `render.yaml`.
3. Або вручну: New → Web Service, Build Command `npm install`, Start Command `node server.js`, Plan Free.
4. Додайте Disk: Mount Path `/opt/render/project/src/db`, Size 1 GB.

## Docker

```bash
docker build -t fintrack .
docker run -p 3000:3000 -v $(pwd)/db:/app/db fintrack
```

## Логін за замовчуванням

- Email: `admin@fintrack.local`
- Пароль: `admin`

**Одразу після першого входу:** Налаштування → Зміна пароля. У проді задайте `ADMIN_PASSWORD` через env, щоб не виводилися дефолтні креди в логах.

## Змінні середовища (env vars)

Усі змінні читаються з `process.env` у `server.js`. Жодна не є обов'язковою — у кожної є sensible default.

| Змінна | Default | Опис |
|---|---|---|
| `PORT` | `3000` | TCP-порт, на якому слухає Express. На Render підставляється платформою. |
| `DB_DIR` | `<project>/db` | Каталог, де лежать `db.json`, `db.json.bak`, `sessions.json`, `audit.log`. На Render: `/opt/render/project/src/db` (примонтований Persistent Disk). |
| `BCRYPT_ROUNDS` | `12` | Cost-фактор bcrypt при хешуванні паролів. Збільшуй для більшої безпеки ціною CPU при логіні. |
| `COOKIE_SECURE` | `true` (`!== 'false'`) | Виставляє атрибут `Secure` на cookie `ft_session`. Лиши `true` у проді за HTTPS. Постав `false` тільки для локального HTTP-тестування. |
| `COOKIE_SAMESITE` | `strict` | Атрибут `SameSite` для cookie. `strict` блокує крос-сайтові запити; `lax` — м'якше; `none` — лише разом із `Secure=true`. |
| `TRUST_PROXY` | `1` | Скільки proxy-хопів довіряти (`app.set('trust proxy', N)`). Потрібно для коректного `req.ip` у rate-limit за reverse-proxy типу Render/Cloudflare. |
| `ADMIN_EMAIL` | `admin@fintrack.local` | Email першого адміна, який створюється при першому старті, якщо БД ще не існує. Зберігається lowercase. |
| `ADMIN_PASSWORD` | `admin` | Пароль першого адміна. **У проді обов'язково перевизнач** — інакше у консольному лозі буде попередження з відкритими дефолтними кредами. |
| `NODE_ENV` | — | Стандартна змінна Node. У `render.yaml` виставлена `production`. |

### Внутрішні константи (не env, але впливають на поведінку)

| Константа | Значення | Опис |
|---|---|---|
| `SESSION_TTL` | 7 діб | Час життя cookie-сесії та запису в `sessions.json`. |
| `MAX_PASSWORD_LEN` | 72 | Bcrypt усе одно truncate-ить далі; обмеження валідації на вході. |
| `EMAIL_REGEX` | `/^[^\s@]+@[^\s@]+\.[^\s@]+$/` | Перевірка формату email. |
| `VALID_ROLES` | `admin`, `user`, `custom` | Допустимі значення поля `role` користувача. |
| Rate-limits | login: 10/хв, write: 120/хв, import: 5/5хв | Налаштовуються у коді через `makeRateLimiter`. |
| Body limits | звичайний JSON: 10 MB, `/api/import`: 60 MB | `express.json({ limit })`. |

## Структура файлів

```
.
├── package.json         # express, bcryptjs, cookie-parser
├── server.js            # API + статика + сесії
├── index.html           # SPA: login, dashboard, transactions, sites, analytics, users, settings
├── Dockerfile
├── render.yaml          # Render.com Blueprint
└── db/                  # створюється автоматично за шляхом DB_DIR
    ├── db.json          # вся бізнес-БД: users, sites, transactions, seos, teams, categories
    ├── db.json.bak      # бекап перед кожним записом (atomic rename)
    ├── sessions.json    # активні httpOnly-сесії
    └── audit.log        # JSON-line аудит (логін, зміни користувачів, імпорти)
```

## API

| Метод | Шлях | Хто | Що робить |
|---|---|---|---|
| POST | `/api/login` | будь-хто (10/хв) | Логін email+password, виставляє cookie `ft_session` |
| POST | `/api/logout` | auth | Видаляє сесію, чистить cookie |
| GET | `/api/me` | auth | Повертає поточного юзера (без `passwordHash`) |
| POST | `/api/change-password` | auth (120/хв) | Зміна свого пароля; інвалідує всі ІНШІ сесії юзера |
| GET | `/api/db` | auth | Повний DB (без `passwordHash`), відфільтрований правами на клієнті |
| PUT | `/api/db` | admin (120/хв) | Замінити дозволені поля DB цілком (whitelist; users не зачіпається) |
| POST | `/api/users` | admin (120/хв) | Створити юзера |
| PUT | `/api/users/:id` | admin (120/хв) | Оновити юзера; перевірка «не зняти останнього адміна» |
| DELETE | `/api/users/:id` | admin (120/хв) | Видалити юзера + усі його сесії |
| POST | `/api/import` | admin (5/5хв) | Bulk-імпорт транзакцій з Finmap (`.xlsx`/`.json`) |

## Що ще варто додати

- HTTPS у проді (Render надає автоматично).
- Зовнішні бекапи `db/` (cron + S3, наприклад).
- 2FA через TOTP.
- Логування дій користувачів (audit-log вже є, потрібен UI-перегляд).
- Міграція з JSON на SQLite, коли транзакцій стане > ~10k.
