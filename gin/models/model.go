package models

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type User struct {
	ID           int       `json:"id" db:"id"`
	Username     string    `json:"username" db:"username"`
	FirstName    string    `json:"first_name" db:"first_name"`
	LastName     string    `json:"last_name" db:"last_name"`
	Email        string    `json:"email" db:"email"`
	Password     string    `json:"password" db:"password"`
	Role         string    `json:"role" db:"role"`
	SessionID    string    `json:"session_id,omitempty" db:"session_id"`
	SessionToken string    `json:"session_token,omitempty" db:"session_token"`
	RefreshToken string    `json:"refresh_token,omitempty" db:"refresh_token"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// SignupRequest represents the request body for user signup
type SignupRequest struct {
	Username  string `json:"username" db:"username"`
	FirstName string `json:"first_name" db:"first_name"`
	LastName  string `json:"last_name" db:"last_name"`
	Email     string `json:"email" db:"email"`
	Password  string `json:"password" db:"password"`
	Role      string `json:"role" db:"role"`
}

// LoginRequest represents the request body for user login
type LoginRequest struct {
	Email    string `json:"email" db:"email"`
	Password string `json:"password" db:"password"`
}

// AuthResponse represents the response for authentication
type AuthResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	User         User   `json:"user"`
	Message      string `json:"message"`
}

// ErrorResponse represents error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// SuccessResponse represents success response
type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// UserUpdateRequest represents the request body for user update
type UserUpdateRequest struct {
	Username  string `json:"username,omitempty" db:"username"`
	FirstName string `json:"first_name,omitempty" db:"first_name"`
	LastName  string `json:"last_name,omitempty" db:"last_name"`
	Email     string `json:"email,omitempty" db:"email"`
	Role      string `json:"role,omitempty" db:"role"`
}

// JWTClaims represents JWT token claims
type JWTClaims struct {
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

// Valid validates the JWT claims
func (c JWTClaims) Valid() error {
	return c.StandardClaims.Valid()
}
