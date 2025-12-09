package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"

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
	http.HandleFunc("/", IndexHandler)
	http.HandleFunc("/register", RegisterHandler)

	http.ListenAndServe("localhost:8080", nil)

}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	tpl.ExecuteTemplate(w, "index.html", nil)

}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tpl.ExecuteTemplate(w, "register.html", nil)
		return
	}

	email := r.FormValue("email")
	username := r.FormValue("username")
	password := r.FormValue("password")

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	pass := os.Getenv("SQL_PASS")
	log.Println("Loaded password:", pass)

	cfg := mysql.Config{
		User:                 "root",
		Passwd:               pass,
		Net:                  "tcp",
		Addr:                 "localhost:3306",
		DBName:               "testb2",
		AllowNativePasswords: true,
	}
	var lethal error
	db, lethal = sql.Open("mysql", cfg.FormatDSN())
	if lethal != nil {
		panic("Cant open the database system!")
	}
	defer db.Close()

	emailRe := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRe.MatchString(email) {
		tpl.ExecuteTemplate(w, "denied.html", "Invalid email")
		return
	}

	if len(username) < 5 || len(username) > 15 {
		tpl.ExecuteTemplate(w, "denied.html", "Username length must be 5–15")
		return
	}

	for _, v := range username {
		if unicode.IsSymbol(v) || unicode.IsSpace(v) {
			tpl.ExecuteTemplate(w, "denied.html", "Username cannot have symbols or spaces")
			return
		}
	}

	var hasUpper, hasLower, hasNum, hasSymbol bool

	if len(password) < 5 || len(password) > 15 {
		tpl.ExecuteTemplate(w, "denied.html", "Password length must be 5–15")
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
		tpl.ExecuteTemplate(w, "denied.html", "Password must contain upper, lower, number and symbol")
		return
	} else {
		tpl.ExecuteTemplate(w, "cregister.html", nil)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("The password could not be converted to hash")
	}

	var sameuser string
	row := db.QueryRow("SELECT Username FROM bcrypt WHERE Username =?", username)
	err = row.Scan(&sameuser)

	if err == nil {
		tpl.ExecuteTemplate(w, "denied.html", "Username already exists!")
	} else {
		result, err := db.Exec("INSERT INTO bcrypt(Username,Email,Hash) VALUES(?,?,?)", username, email, hash)
		if err != nil {
			InsertError := fmt.Errorf("%v", err)
			log.Fatal(InsertError)
		}
		id, err := result.LastInsertId()
		if err != nil {
			log.Fatalf("impossible to retrieve last inserted id:%s", err)
		}
		log.Printf("inserted id %d", id)

	}
}
