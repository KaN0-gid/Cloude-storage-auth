package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"database/sql"
	_ "github.com/lib/pq"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

const (
	dbHost     = "localhost"
	dbPort     = 5432
	dbUser     = "kano"
	dbPassword = "1972"
	dbName     = "postgres"
)

type FileInfo struct {
	Name       string    `json:"name"`
	UploadTime time.Time `json:"upload_time"`
	Size       int64     `json:"size"`
}

type User struct {
	ID           int
	Username     string
	PasswordHash string
}

func fileSize(size int64) string {
	const (
		KB int64 = 1 << 10
		MB int64 = 1 << 20
		GB int64 = 1 << 30
	)

	switch {
	case size < KB:
		return fmt.Sprintf("%d B", size)
	case size < MB:
		return fmt.Sprintf("%.2f KB", float64(size)/float64(KB))
	case size < GB:
		return fmt.Sprintf("%.2f MB", float64(size)/float64(MB))
	default:
		return fmt.Sprintf("%.2f GB", float64(size)/float64(GB))
	}
}

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"formatSize": fileSize,
}).ParseGlob("templates/*"))

var db *sql.DB

func init() {
	var err error
	db, err = sql.Open("postgres", fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", dbUser, dbPassword, dbName))
	if err != nil {
		log.Fatal(err)
	}
}

// Инициализируем хранилище сессий
var store = sessions.NewCookieStore([]byte("your-secret-key"))

func homeHandler(w http.ResponseWriter, r *http.Request) {
    // Получаем имя пользователя из сессии
    session, _ := store.Get(r, "session-name")
    username, _ := session.Values["username"].(string)

    files := listFiles("uploads")
    fileInfo := []FileInfo{}
    for _, file := range files {
        info, err := os.Stat(filepath.Join("uploads", file))
        if err == nil {
            fileInfo = append(fileInfo, FileInfo{
                Name:       file,
                UploadTime: info.ModTime(),
                Size:       info.Size(),
            })
        }
    }

    data := struct {
        Username string
    }{
        Username: username, // Передаем имя пользователя в данные для шаблона
    }

    err := templates.ExecuteTemplate(w, "index.html", struct {
        FileInfo []FileInfo
        Data     interface{}
    }{
        FileInfo: fileInfo,
        Data:     data,
    })
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		file, handler, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		filename := handler.Filename
		f, err := os.Create(filepath.Join("uploads", filename))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		go func() {
			defer f.Close()
			_, err := io.Copy(f, file)
			if err != nil {
				fmt.Println("Error uploading file:", err)
			}
		}()

		response := map[string]string{"message": "Загрузка завершена!"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	files := listFiles("uploads")
	fileInfo := []FileInfo{}

	for _, file := range files {
		info, err := os.Stat(filepath.Join("uploads", file))
		if err == nil {
			fileInfo = append(fileInfo, FileInfo{
				Name:       file,
				UploadTime: info.ModTime(),
				Size:       info.Size(),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(fileInfo)
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filename := vars["filename"]
	filePath := filepath.Join("uploads", filename)

	if _, err := os.Stat(filePath); err == nil {
		err := os.Remove(filePath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filename := vars["filename"]
	filePath := filepath.Join("uploads", filename)

	if _, err := os.Stat(filePath); err == nil {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		http.ServeFile(w, r, filePath)
	} else {
		http.Error(w, "File not found", http.StatusNotFound)
	}
}

func listFiles(directory string) []string {
	files := []string{}
	fileInfos, err := os.ReadDir(directory)
	if err != nil {
		fmt.Println("Error reading directory:", err)
		return files
	}

	for _, fileInfo := range fileInfos {
		if !fileInfo.IsDir() {
			files = append(files, fileInfo.Name())
		}
	}
	return files
}

func registrationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl := templates.Lookup("registration.html")
		if tmpl == nil {
			http.Error(w, "Template not found", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	} else if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := findUserByUsername(username)
		if err != nil {
			http.Error(w, "Error checking username", http.StatusInternalServerError)
			return
		}

		if user != nil {
			http.Error(w, "Username already exists", http.StatusBadRequest)
			return
		}

		passwordHash, err := hashPassword(password)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		err = createUser(username, passwordHash)
		if err != nil {
			http.Error(w, "Error creating user", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl := templates.Lookup("login.html")
		if tmpl == nil {
			http.Error(w, "Template not found", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	} else if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := findUserByUsername(username)
		if err != nil {
			http.Error(w, "Error finding user", http.StatusInternalServerError)
			return
		}

		if user != nil && checkPassword(user, password) {
			// Создаем сессию с именем пользователя
			session, _ := store.Get(r, "session-name")
			session.Values["username"] = username
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
}

func secureHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем имя пользователя из сессии
	session, _ := store.Get(r, "session-name")
	username, ok := session.Values["username"].(string)

	// Если имя пользователя отсутствует, перенаправляем на страницу входа
	if !ok || username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Вставьте имя пользователя в данные для отображения
	data := struct {
		Username string
	}{
		Username: username,
	}

	err := templates.ExecuteTemplate(w, "secure.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func findUserByUsername(username string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, password_hash FROM users WHERE username = $1", username).Scan(&user.ID, &user.Username, &user.PasswordHash)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &user, nil
}

func createUser(username, passwordHash string) error {
	_, err := db.Exec("INSERT INTO users (username, password_hash) VALUES ($1, $2)", username, passwordHash)
	return err
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func checkPassword(user *User, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	return err == nil
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Удаляем сессию пользователя
	session, _ := store.Get(r, "session-name")
	session.Values["username"] = ""
	session.Save(r, w)

	// Перенаправляем пользователя на страницу входа
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func isAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Получаем имя пользователя из сессии
		session, _ := store.Get(r, "session-name")
		username, ok := session.Values["username"].(string)

		// Если имя пользователя отсутствует, перенаправляем на страницу входа
		if !ok || username == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	router := mux.NewRouter()
	router.Handle("/", isAuthenticated(http.HandlerFunc(homeHandler)))
	router.HandleFunc("/upload", uploadHandler).Methods("POST")
	router.HandleFunc("/list", listHandler).Methods("GET")
	router.HandleFunc("/delete/{filename}", deleteHandler).Methods("POST")
	router.HandleFunc("/download/{filename}", downloadHandler).Methods("GET")
	router.HandleFunc("/register", registrationHandler).Methods("GET", "POST")
	router.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	router.HandleFunc("/secure", secureHandler).Methods("GET")
	router.HandleFunc("/logout", logoutHandler).Methods("GET")

	fs := http.FileServer(http.Dir("uploads"))
	router.PathPrefix("/uploads/").Handler(http.StripPrefix("/uploads/", fs))

	fsStatic := http.FileServer(http.Dir("static"))
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fsStatic))

	fmt.Println("Server is running on :8080...")
	http.ListenAndServe(":8080", router)
}
