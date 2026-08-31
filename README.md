# GophKeeper

GophKeeper — клиент-серверный менеджер приватных данных. Пользователь может хранить пары логин/пароль, тексты, файлы и банковские карты с произвольной метаинформацией. CLI работает на Windows, Linux и macOS, а изменения синхронизируются между клиентами через gRPC.

## Возможности

- регистрация и аутентификация пользователей;
- клиентское шифрование данных AES-256-GCM;
- вывод ключа из мастер-пароля с помощью Argon2id;
- хранение паролей пользователей в виде bcrypt-хешей;
- защищённый gRPC-транспорт с TLS 1.3;
- создание, просмотр, изменение и удаление приватных данных;
- синхронизация по монотонному курсору с передачей удалённых записей;
- защита от конфликтов при одновременном изменении записи;
- PostgreSQL-хранилище с автоматической миграцией;
- корректное завершение сервера по `SIGINT`, `SIGTERM` и `SIGQUIT`.

## Архитектура

Сервер хранит учётные записи, зашифрованные блоки и метаданные синхронизации. Содержимое записи, её название и пользовательская метаинформация шифруются на клиенте и не передаются серверу в открытом виде. Ключ шифрования выводится из мастер-пароля и индивидуальной соли пользователя и существует только в памяти клиента.

Протокол описан в [`proto/gophkeeper.proto`](proto/gophkeeper.proto). Для обмена используется бинарный протокол gRPC. Обновления защищены optimistic locking: клиент передаёт известную версию записи, а сервер отклоняет устаревшее изменение кодом `Aborted`.

## Запуск

Для сервера нужны PostgreSQL и секрет подписи токенов длиной не менее 32 символов.

```bash
docker compose up -d postgres
export DATABASE_URI='postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable'
export AUTH_SECRET='replace-this-with-a-random-32-byte-secret'
go run ./cmd/gophkeeper-server
```

Для локального запуска без TLS клиенту нужно явно передать `--insecure`:

```bash
go run ./cmd/gophkeeper --insecure register alice --password 'strong-password'
go run ./cmd/gophkeeper --insecure add credentials \
  --name 'Рабочая почта' --metadata 'example.com' \
  --login 'alice@example.com' --secret 'mail-password' \
  --password 'strong-password'
go run ./cmd/gophkeeper --insecure list --password 'strong-password'
```

Вместо флага мастер-пароль можно передать через `GOPHKEEPER_PASSWORD`. Если ни один вариант не задан, CLI безопасно запросит пароль в терминале без отображения введённых символов.

## Команды клиента

```text
register LOGIN                         регистрация и создание локальной сессии
login LOGIN                            аутентификация и обновление сессии
add credentials|text|binary|card      добавление записи
update TYPE ID VERSION                 изменение известной версии записи
list                                   список актуальных записей
get ID                                 просмотр записи
delete ID VERSION                      удаление известной версии записи
sync --since CURSOR                    получение изменений после курсора
version                                версия, дата и коммит сборки
```

Для бинарной записи используются `add binary --file PATH` и `get ID --output PATH`. Полный список параметров доступен через `gophkeeper COMMAND --help`.

## Конфигурация сервера

| Флаг | Переменная окружения | Назначение |
|---|---|---|
| `-a` | `RUN_ADDRESS` | адрес gRPC-сервера, по умолчанию `127.0.0.1:3200` |
| `-d` | `DATABASE_URI` | строка подключения к PostgreSQL |
| `-auth-secret` | `AUTH_SECRET` | секрет подписи токенов |
| `-tls-cert` | `TLS_CERT` | сертификат TLS |
| `-tls-key` | `TLS_KEY` | приватный ключ TLS |
| `-token-ttl` | `TOKEN_TTL` | срок действия токена, по умолчанию `24h` |

Для TLS сертификат и ключ задаются одновременно. В рабочем окружении сервер следует запускать с TLS, а клиенту передавать доверенный сертификат через `--ca` или `GOPHKEEPER_CA`.

## Конфигурация клиента

| Флаг | Переменная окружения | Назначение |
|---|---|---|
| `-a`, `--address` | `GOPHKEEPER_ADDRESS` | адрес сервера |
| `--ca` | `GOPHKEEPER_CA` | доверенный сертификат сервера |
| `--server-name` | `GOPHKEEPER_SERVER_NAME` | имя сервера в сертификате |
| `--insecure` | `GOPHKEEPER_INSECURE` | локальное подключение без TLS |
| `--timeout` | `GOPHKEEPER_TIMEOUT` | таймаут запроса |
| `--session` | `GOPHKEEPER_SESSION` | путь к файлу сессии |
| `--password` | `GOPHKEEPER_PASSWORD` | мастер-пароль |

Файл сессии хранит только токен, логин и соль. Мастер-пароль и ключ шифрования на диск не записываются.

## Сборка

```bash
make build
make build-all
```

Версия клиента задаётся на этапе сборки:

```bash
go build -ldflags "\
  -X main.buildVersion=v1.0.0 \
  -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -X main.buildCommit=$(git rev-parse --short HEAD)" \
  -o bin/gophkeeper ./cmd/gophkeeper
```

## Тестирование

```bash
make test
make cover
```

Юнит-тесты и тесты полного gRPC-сценария покрывают регистрацию, авторизацию, шифрование, синхронизацию, конфликты версий, удаление, конфигурацию и CLI. Текущее покрытие — более 80%.

