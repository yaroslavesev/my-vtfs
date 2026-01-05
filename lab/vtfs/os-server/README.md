## Запуск

1. Поднять Postgres: `docker-compose up -d` из каталога `lab/vtfs/os-server`. 
2. Собрать и запустить приложение: `./gradlew bootRun` (порт 8089). 

Таблица `files` создаётся автоматически через `schema.sql`.