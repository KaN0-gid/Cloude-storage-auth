# Cloude-storage-auth
Cloud Storage Auth - это простое веб-приложение для загрузки, управления и скачивания файлов в облако с авторизацией пользователя.


```bash
go get -u ./...
git clone https://github.com/ваш-пользователь/cloude-storage-auth.git
cd cloude-storage-auth
go mod tidy
go run cmd/cloud-storage-auth/main.go migrate
go run cmd/cloud-storage-auth/main.go
