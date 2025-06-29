package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func init() {
	var err error

	// Get database connection string from environment
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	// Set default values if not provided
	if dbHost == "" {
		dbHost = "localhost"
	}
	if dbPort == "" {
		dbPort = "5432"
	}
	if dbUser == "" {
		dbUser = "postgres"
	}
	if dbPassword == "" {
		dbPassword = "password"
	}
	if dbName == "" {
		dbName = "fiberapi"
	}

	// Construct connection string
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	// Connect to database
	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}

	// Test connection
	if err = DB.Ping(); err != nil {
		log.Fatalf("Failed to ping PostgreSQL: %v", err)
	}

	fmt.Println("Connected to PostgreSQL successfully!")

	// Create users table if it doesn't exist
	createUsersTable()
}

// GetDB returns the database connection
func GetDB() *sql.DB {
	return DB
}

// Disconnect closes the database connection
func Disconnect() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}

// createUsersTable creates the users table if it doesn't exist
func createUsersTable() {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(255) UNIQUE NOT NULL,
		first_name VARCHAR(255) NOT NULL,
		last_name VARCHAR(255) NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password VARCHAR(255) NOT NULL,
		role VARCHAR(50) DEFAULT 'user',
		session_id VARCHAR(255),
		session_token TEXT,
		refresh_token TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	
	-- Create an index on email for faster lookups
	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	
	-- Create an index on username for faster lookups
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	`

	_, err := DB.Exec(query)
	if err != nil {
		log.Fatalf("Failed to create users table: %v", err)
	}

	fmt.Println("Users table created/verified successfully!")
}
