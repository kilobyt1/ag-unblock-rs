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

Запуск без аргументов (или двойным кликом по `ag-unblock.exe` на Windows) открывает интерактивное меню в консоли:

```text
=== ag-unblock ===
  1. Статус (файлы и DNS)
  2. Применить патч (apply)
  3. Применить патч без проверки Node.js (apply --no-node)
  4. Откатить патч (revert)
  5. Проверить сеть и сертификаты (verify)
  0. Выход
```

Также поддерживается прямой CLI-режим:

```bash
ag-unblock status              # состояние целей и DNS
ag-unblock apply [--no-node]   # наложить патчи (с сохранением оригиналов в backup/)
ag-unblock revert              # откатить все файлы из backup/
ag-unblock verify              # проверить DNS-подмену, сертификаты Google и 401 от gate-хоста
```

На Windows перед `apply` / `revert` закройте Antigravity / Antigravity IDE / `agy.exe`.

## Сборка

### Linux

```bash
cargo build --release
```

### Windows (x86_64-pc-windows-gnu)

На Windows без установленного MSVC проект компилируется с помощью [w64devkit](https://github.com/skeeto/w64devkit) (нужен для сборки C-части `ring`). Чтобы не перехватывать штатный линкер `rust-mingw`, передавайте `CC` и `AR` напрямую без добавления `w64devkit\bin` в `PATH`:

```powershell
$env:CC = 'C:\w64devkit\bin\gcc.exe'
$env:AR = 'C:\w64devkit\bin\ar.exe'
cargo build --release
```

Готовые бинарники под Linux и Windows x64 доступны в [Releases](../../releases).

## Контрибьюторы

- **Google Gemini** — кроссплатформенный порт на Rust, сборка под Linux/Windows 10 и отладка.
