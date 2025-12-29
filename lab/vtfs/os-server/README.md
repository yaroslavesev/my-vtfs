## Запуск

1. Поднять Postgres: `docker-compose up -d` из каталога `lab/vtfs/os-server`. Всё захардкожено: база `test`, логин `test`, пароль `test`, порт `5432`.
2. Собрать и запустить приложение: `./gradlew bootRun` (порт 8089). Java 17 обязателен.

Таблица `files` создаётся автоматически через `schema.sql`.

## Эндпоинты (GET, префикс `/api`, все ответы — 8 байт retVal LE + payload)

- `/list?token=...&parent_ino=...` → retVal=0, payload JSON массива `{ino, name, is_dir}`.
- `/read?token=...&parent_ino=...&name=...` → retVal=0, payload = байты файла; при отсутствии retVal=-1, payload `"File not found"`.
- `/create?token=...&parent_ino=...&name=...&data=...` → retVal=0, payload `{"ok":true}`; если уже есть такой объект — retVal=-1, payload `{"ok":false}`.
- `/write?token=...&parent_ino=...&name=...&data=...` → retVal=0/ -1, payload `{"ok":<bool>}`.
- `/mkdir?token=...&parent_ino=...&name=...` → retVal=0/ -1, payload `{"ok":<bool>}`.
- `/unlink?token=...&parent_ino=...&name=...` → retVal=0/ -1, payload `{"ok":<bool>}`.

Ключ поиска в БД: `(token, parent_ino, name)`. `parent_ino` по умолчанию 0.
