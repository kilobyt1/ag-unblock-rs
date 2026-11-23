# ag-unblock-rs

Компактная (~640 строк) Rust-версия утилиты для снятия клиентской региональной блокировки Google Antigravity (2.0 Desktop, IDE, CLI) на Linux и Windows 10.

Без локального прокси и без изменения системного DNS — сетевой уровень (DNS-подмена или системный VPN) настраивается отдельно на стороне ОС, а утилита патчит клиентский гейт и проверяет прохождение трафика до gate-хостов.

## Возможности

- Единый бинарь без внешних зависимостей (на Windows требуются только штатные системные DLL).
- **Клиентский патч бинарей**: переименование литерала `ineligible` → `inexigible` (10 байт → 10 байт, смещения и размер файла сохраняются) в `language_server` / `language_server*.exe` и `agy` / `agy.exe`.
- **Патч IDE (`main.js`)**: переписывает обработчик входа до `AUTH_SUCCESS` с `userTier: pro`, проверяет баланс `{}` и синтаксис через `node --check` (при отсутствии Node.js на Windows есть флаг `--no-node`).
- **Бэкапы и атомарный откат**: сохраняет оригиналы в `backup/` рядом с бинарником (`<файл>.<sha1 пути[:12]>`), перезапись через временный файл (`write_atomic`).
- **Проверка сети (`verify`)**: системный DNS + TLS-проверка через `rustls` / `webpki-roots` / `x509-parser` + пробный запрос `POST /v1internal:loadCodeAssist` (ожидается HTTP 401 `UNAUTHENTICATED`).

## Использование

```bash
ag-unblock status              # состояние целей и DNS
ag-unblock apply [--no-node]   # наложить патчи (с сохранением оригиналов в backup/)
ag-unblock revert              # откатить все файлы из backup/
ag-unblock verify              # проверить DNS-подмену, сертификаты Google и 401 от gate-хоста
```

На Windows перед `apply` / `revert` закройте Antigravity / Antigravity IDE / `agy.exe`.

## Сборка

```bash
cargo build --release
```

Готовые бинарники под Linux и Windows x64 доступны в [Releases](../../releases).
