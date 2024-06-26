package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	_ "github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"net/http"
	"time"
)

type MeowFactResponse struct {
	Data []string `json:"data"`
}
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type FavoriteFact struct {
	ID     int    `json:"id"`
	UserID int    `json:"userId"`
	Fact   string `json:"fact"`
}

var db *sql.DB

const (
	host     = "localhost"
	port     = 5432
	user     = "your_username"
	password = "your_password"
	dbname   = "your_database_name"
)

func initDB() {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	log.Println("Connected to PostgreSQL database")
}

func closeDB() {
	if db != nil {
		db.Close()
	}
}

var jwtKey = []byte("your_secret_key")

func generateJWT(username string) (string, error) {
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		Subject:   username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func verifyJWT(tokenString string) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}
func register(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	hashedPassword, _ := hashPassword(user.Password)
	_, err = db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", user.Username, hashedPassword)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "User created successfully")
}
func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}
func comparePasswords(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
func login(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	var dbUser User
	err = db.QueryRow("SELECT id, password FROM users WHERE username = $1", user.Username).Scan(&dbUser.ID, &dbUser.Password)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	if !comparePasswords(dbUser.Password, user.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	tokenString, err := generateJWT(user.Username)
	if err != nil {
		http.Error(w, "Failed to generate JWT token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}
func getFact(w http.ResponseWriter) {
	url := "https://meowfacts.herokuapp.com/"
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Failed to fetch data: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}
	var meowFactResponse MeowFactResponse
	if err := json.Unmarshal(body, &meowFactResponse); err != nil {
		log.Fatalf("Failed to parse JSON: %v", err)
	}
	for _, fact := range meowFactResponse.Data {
		w.Write([]byte(fact))
	}
}
func saveFavoriteFact(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Authorization header is required", http.StatusUnauthorized)
		return
	}

	claims, err := verifyJWT(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var favoriteFact FavoriteFact
	err = json.NewDecoder(r.Body).Decode(&favoriteFact)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("INSERT INTO favorites (user_id, fact) VALUES ($1, $2)", claims.Subject, favoriteFact.Fact)
	if err != nil {
		http.Error(w, "Failed to save favorite fact", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Favorite fact saved successfully")
}
func getFavoriteFacts(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Authorization header is required", http.StatusUnauthorized)
		return
	}

	claims, err := verifyJWT(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	rows, err := db.Query("SELECT id, user_id, fact FROM favorites WHERE user_id = $1", claims.Subject)
	if err != nil {
		http.Error(w, "Failed to retrieve favorite facts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var favoriteFacts []FavoriteFact
	for rows.Next() {
		var favoriteFact FavoriteFact
		err := rows.Scan(&favoriteFact.ID, &favoriteFact.UserID, &favoriteFact.Fact)
		if err != nil {
			http.Error(w, "Failed to scan favorite facts", http.StatusInternalServerError)
			return
		}
		favoriteFacts = append(favoriteFacts, favoriteFact)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(favoriteFacts)
}
func main() {
	initDB()
	defer closeDB()
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/saveFavoriteFact", saveFavoriteFact)
	http.HandleFunc("/getFavoriteFacts", getFavoriteFacts)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
