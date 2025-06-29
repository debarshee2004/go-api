package controllers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/debarshee/chiapi/db"
	"github.com/debarshee/chiapi/middleware"
	"github.com/debarshee/chiapi/models"
	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

// UserSignup handles user registration
func UserSignup(w http.ResponseWriter, r *http.Request) {
	var signupReq models.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&signupReq); err != nil {
		response := models.ErrorResponse{
			Error:   "Invalid request",
			Message: "Failed to parse request body",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate required fields
	if signupReq.Email == "" || signupReq.Password == "" || signupReq.Username == "" {
		response := models.ErrorResponse{
			Error:   "Validation error",
			Message: "Email, username, and password are required",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if user already exists
	database := db.GetDB()
	var existingUser models.User
	err := database.QueryRow("SELECT id FROM users WHERE email = $1", signupReq.Email).Scan(&existingUser.ID)
	if err == nil {
		response := models.ErrorResponse{
			Error:   "User exists",
			Message: "User with this email already exists",
		}
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(signupReq.Password), bcrypt.DefaultCost)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Internal error",
			Message: "Failed to process password",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Set default role if not provided
	if signupReq.Role == "" {
		signupReq.Role = "user"
	}

	// Create new user
	var user models.User
	err = database.QueryRow(`
		INSERT INTO users (username, first_name, last_name, email, password, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, username, first_name, last_name, email, role, created_at, updated_at`,
		signupReq.Username, signupReq.FirstName, signupReq.LastName, signupReq.Email,
		string(hashedPassword), signupReq.Role, time.Now(), time.Now()).Scan(
		&user.ID, &user.Username, &user.FirstName, &user.LastName,
		&user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		response := models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to create user",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Generate tokens
	token, err := middleware.GenerateJWT(user)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Token error",
			Message: "Failed to generate token",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	refreshToken, err := middleware.GenerateRefreshToken(user)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Token error",
			Message: "Failed to generate refresh token",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Return success response
	authResponse := models.AuthResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User:         user,
		Message:      "User created successfully",
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(authResponse)
}

// UserLogin handles user authentication
func UserLogin(w http.ResponseWriter, r *http.Request) {
	var loginReq models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		response := models.ErrorResponse{
			Error:   "Invalid request",
			Message: "Failed to parse request body",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate required fields
	if loginReq.Email == "" || loginReq.Password == "" {
		response := models.ErrorResponse{
			Error:   "Validation error",
			Message: "Email and password are required",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Find user by email
	database := db.GetDB()
	var user models.User
	err := database.QueryRow(`
		SELECT id, username, first_name, last_name, email, password, role, created_at, updated_at
		FROM users WHERE email = $1`, loginReq.Email).Scan(
		&user.ID, &user.Username, &user.FirstName, &user.LastName,
		&user.Email, &user.Password, &user.Role, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		response := models.ErrorResponse{
			Error:   "Authentication failed",
			Message: "Invalid email or password",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password))
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Authentication failed",
			Message: "Invalid email or password",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Generate tokens
	token, err := middleware.GenerateJWT(user)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Token error",
			Message: "Failed to generate token",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	refreshToken, err := middleware.GenerateRefreshToken(user)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Token error",
			Message: "Failed to generate refresh token",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Don't return password
	user.Password = ""

	// Return success response
	authResponse := models.AuthResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User:         user,
		Message:      "Login successful",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(authResponse)
}

// UserLogout handles user logout (invalidate token on client side)
func UserLogout(w http.ResponseWriter, r *http.Request) {
	response := models.SuccessResponse{
		Message: "Logout successful",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetAllUsers retrieves all users (admin only)
func GetAllUsers(w http.ResponseWriter, r *http.Request) {
	database := db.GetDB()

	rows, err := database.Query(`
		SELECT id, username, first_name, last_name, email, role, created_at, updated_at
		FROM users ORDER BY created_at DESC`)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to fetch users",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Username, &user.FirstName, &user.LastName,
			&user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			response := models.ErrorResponse{
				Error:   "Database error",
				Message: "Failed to decode users",
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}
		users = append(users, user)
	}

	response := models.SuccessResponse{
		Message: "Users retrieved successfully",
		Data:    users,
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetUserByID retrieves a specific user by ID
func GetUserByID(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	id, err := strconv.Atoi(userID)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID format",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	database := db.GetDB()
	var user models.User
	err = database.QueryRow(`
		SELECT id, username, first_name, last_name, email, role, created_at, updated_at
		FROM users WHERE id = $1`, id).Scan(
		&user.ID, &user.Username, &user.FirstName, &user.LastName,
		&user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			response := models.ErrorResponse{
				Error:   "Not found",
				Message: "User not found",
			}
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(response)
			return
		}
		response := models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to fetch user",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := models.SuccessResponse{
		Message: "User retrieved successfully",
		Data:    user,
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// UpdateUser updates a user's information
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	id, err := strconv.Atoi(userID)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID format",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	var updateReq models.UserUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		response := models.ErrorResponse{
			Error:   "Invalid request",
			Message: "Failed to parse request body",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check authorization (users can only update their own profile unless admin)
	contextUserID := r.Context().Value("user_id").(string)
	contextRole := r.Context().Value("role").(string)

	if contextUserID != userID && contextRole != "admin" {
		response := models.ErrorResponse{
			Error:   "Forbidden",
			Message: "You can only update your own profile",
		}
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Build update query dynamically
	setParts := []string{"updated_at = $1"}
	args := []interface{}{time.Now()}
	argIndex := 2

	if updateReq.Username != "" {
		setParts = append(setParts, "username = $"+strconv.Itoa(argIndex))
		args = append(args, updateReq.Username)
		argIndex++
	}
	if updateReq.FirstName != "" {
		setParts = append(setParts, "first_name = $"+strconv.Itoa(argIndex))
		args = append(args, updateReq.FirstName)
		argIndex++
	}
	if updateReq.LastName != "" {
		setParts = append(setParts, "last_name = $"+strconv.Itoa(argIndex))
		args = append(args, updateReq.LastName)
		argIndex++
	}
	if updateReq.Email != "" {
		setParts = append(setParts, "email = $"+strconv.Itoa(argIndex))
		args = append(args, updateReq.Email)
		argIndex++
	}
	if updateReq.Role != "" && contextRole == "admin" {
		setParts = append(setParts, "role = $"+strconv.Itoa(argIndex))
		args = append(args, updateReq.Role)
		argIndex++
	}

	// Add WHERE clause parameter
	args = append(args, id)
	query := "UPDATE users SET " + strings.Join(setParts, ", ") + " WHERE id = $" + strconv.Itoa(argIndex)

	database := db.GetDB()
	result, err := database.Exec(query, args...)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to update user",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		response := models.ErrorResponse{
			Error:   "Not found",
			Message: "User not found",
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := models.SuccessResponse{
		Message: "User updated successfully",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// DeleteUser deletes a user (admin only)
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	id, err := strconv.Atoi(userID)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID format",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	database := db.GetDB()
	result, err := database.Exec("DELETE FROM users WHERE id = $1", id)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to delete user",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		response := models.ErrorResponse{
			Error:   "Not found",
			Message: "User not found",
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := models.SuccessResponse{
		Message: "User deleted successfully",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetProfile returns the current user's profile
func GetProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	id, err := strconv.Atoi(userID)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	database := db.GetDB()
	var user models.User
	err = database.QueryRow(`
		SELECT id, username, first_name, last_name, email, role, created_at, updated_at
		FROM users WHERE id = $1`, id).Scan(
		&user.ID, &user.Username, &user.FirstName, &user.LastName,
		&user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		response := models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to fetch profile",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := models.SuccessResponse{
		Message: "Profile retrieved successfully",
		Data:    user,
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
