# Cloude-storage-auth
Cloud Storage Auth - это простое веб-приложение для загрузки, управления и скачивания файлов в облако с авторизацией пользователя.


```bash
go get -u ./...
git clone https://github.com/KaN0-gid/cloude-storage-auth.git
cd cloude-storage-auth
go mod tidy
go run cmd/cloud-storage-auth/main.go migrate
go run cmd/cloud-storage-auth/main.go

Для создания базы данных PostgreSQL на Linux выполните следующие шаги:

1. Установите PostgreSQL:
   ```bash
   sudo apt update
   sudo apt install postgresql postgresql-contrib
   ```
   # Создайте таблицу с помощью SQL-запроса. Вот пример создания таблицы users:
   ```bash
   # Войдите в PostgreSQL:
   sudo -i -u postgres
   # Запустите интерфейс командной строки PostgreSQL:
   psql
   ```
   
   ```sql
   CREATE TABLE users (
   ID SERIAL PRIMARY KEY,
   Username VARCHAR(255) NOT NULL,
   PasswordHash VARCHAR(255) NOT NULL
   );
   ```
### После создания таблицы вы можете выйти из интерфейса командной строки PostgreSQL:
   ```bash
   \q
   ```
### После можем запускать сервис 
   ```bash
   cd cloude-storage-auth
   go run main.go
   ```
