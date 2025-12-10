package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"text/template"
	"unicode"

	"github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var tpl *template.Template
var db *sql.DB

func main() {

	var err error
	tpl, err = template.ParseGlob("*.html")
	if err != nil {
		log.Fatal(err)
	}

	err = godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	pass := os.Getenv("SQL_PASS")

	cfg := mysql.Config{
		User:                 "root",
		Passwd:               pass,
		Net:                  "tcp",
		Addr:                 "localhost:3306",
		DBName:               "testb2",
		AllowNativePasswords: true,
	}

	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal("Cannot open the database:", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Cannot connect to database:", err)
	}

	http.HandleFunc("/", IndexHandler)
	http.HandleFunc("/register", RegisterHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tpl.ExecuteTemplate(w, "register.html", nil)
		return
	}

	email := r.FormValue("email")
	username := r.FormValue("username")
	password := r.FormValue("password")

	emailRe := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRe.MatchString(email) {
		tpl.ExecuteTemplate(w, "denied.html", "Invalid email")
		return
	}

	if len(username) < 5 || len(username) > 15 {
		tpl.ExecuteTemplate(w, "denied.html", "Username must be 5–15 characters")
		return
	}

	for _, v := range username {
		if unicode.IsSymbol(v) || unicode.IsSpace(v) {
			tpl.ExecuteTemplate(w, "denied.html", "Username cannot contain symbols or spaces")
			return
		}
	}

	var hasUpper, hasLower, hasNum, hasSymbol bool

	if len(password) < 5 || len(password) > 15 {
		tpl.ExecuteTemplate(w, "denied.html", "Password must be 5–15 characters")
		return
	}

	for _, v := range password {
		switch {
		case unicode.IsUpper(v):
			hasUpper = true
		case unicode.IsLower(v):
			hasLower = true
		case unicode.IsNumber(v):
			hasNum = true
		case unicode.IsPunct(v) || unicode.IsSymbol(v):
			hasSymbol = true
		case unicode.IsSpace(v):
			tpl.ExecuteTemplate(w, "denied.html", "Password cannot contain spaces")
			return
		}
	}

	if !hasUpper || !hasLower || !hasNum || !hasSymbol {
		tpl.ExecuteTemplate(w, "denied.html", "Password must contain upper, lower, number, and symbol")
		return
	}

	var existing string
	err := db.QueryRow("SELECT Username FROM bcrypt WHERE Username = ?", username).Scan(&existing)
	if err == nil {
		tpl.ExecuteTemplate(w, "denied.html", "Username already exists!")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		tpl.ExecuteTemplate(w, "denied.html", "Hashing error")
		return
	}

	_, err = db.Exec("INSERT INTO bcrypt (Username, Email, Hash) VALUES (?, ?, ?)", username, email, hash)
	if err != nil {
		tpl.ExecuteTemplate(w, "denied.html", "Database insert error")
		return
	}

	tpl.ExecuteTemplate(w, "cregister.html", username)
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tpl.ExecuteTemplate(w, "index.html", nil)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))

	if username == "" || password == "" {
		tpl.ExecuteTemplate(w, "login.html", "Username and password cannot be empty")
		return
	}

	var dbHash []byte
	err := db.QueryRow("SELECT Hash FROM bcrypt WHERE Username = ?", username).Scan(&dbHash)
	if err == sql.ErrNoRows {
		tpl.ExecuteTemplate(w, "login.html", "Invalid username or password")
		return
	} else if err != nil {
		log.Println("DB error:", err)
		tpl.ExecuteTemplate(w, "login.html", "Server error")
		return
	}

	err = bcrypt.CompareHashAndPassword(dbHash, []byte(password))
	if err != nil {
		tpl.ExecuteTemplate(w, "login.html", "Incorrect username or password")
		return
	}

	tpl.ExecuteTemplate(w, "welcome.html", username)
}
