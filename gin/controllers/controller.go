package controllers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/debarshee2004/ginapi/db"
	"github.com/debarshee2004/ginapi/middleware"
	"github.com/debarshee2004/ginapi/models"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// UserSignup handles user registration
func UserSignup(c *gin.Context) {
	var signupReq models.SignupRequest
	if err := c.ShouldBindJSON(&signupReq); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Invalid request",
			Message: "Failed to parse request body",
		})
		return
	}

	// Validate required fields
	if signupReq.Email == "" || signupReq.Password == "" || signupReq.Username == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Validation error",
			Message: "Email, username, and password are required",
		})
		return
	}

	database := db.GetDB()

	// Check if user already exists (check both email and username)
	var count int
	err := database.QueryRow("SELECT COUNT(*) FROM users WHERE email = $1 OR username = $2",
		signupReq.Email, signupReq.Username).Scan(&count)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to check existing user",
		})
		return
	}

	if count > 0 {
		c.JSON(http.StatusConflict, models.ErrorResponse{
			Error:   "User exists",
			Message: "User with this email or username already exists",
		})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(signupReq.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Internal error",
			Message: "Failed to process password",
		})
		return
	}

	// Set default role if not provided
	if signupReq.Role == "" {
		signupReq.Role = "user"
	}

	// Insert user into database
	now := time.Now()
	var userID int
	err = database.QueryRow(`
		INSERT INTO users (username, first_name, last_name, email, password, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, signupReq.Username, signupReq.FirstName, signupReq.LastName, signupReq.Email,
		string(hashedPassword), signupReq.Role, now, now).Scan(&userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to create user",
		})
		return
	}

	// Create user object for response
	user := models.User{
		ID:        userID,
		Username:  signupReq.Username,
		FirstName: signupReq.FirstName,
		LastName:  signupReq.LastName,
		Email:     signupReq.Email,
		Role:      signupReq.Role,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Generate tokens
	token, err := middleware.GenerateJWT(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Token error",
			Message: "Failed to generate token",
		})
		return
	}

	refreshToken, err := middleware.GenerateRefreshToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Token error",
			Message: "Failed to generate refresh token",
		})
		return
	}

	// Return success response
	c.JSON(http.StatusCreated, models.AuthResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User:         user,
		Message:      "User created successfully",
	})
}

// UserLogin handles user authentication
func UserLogin(c *gin.Context) {
	var loginReq models.LoginRequest
	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Invalid request",
			Message: "Failed to parse request body",
		})
		return
	}

	// Validate required fields
	if loginReq.Email == "" || loginReq.Password == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Validation error",
			Message: "Email and password are required",
		})
		return
	}

	// Find user by email
	database := db.GetDB()
	var user models.User
	err := database.QueryRow(`
		SELECT id, username, first_name, last_name, email, password, role, created_at, updated_at
		FROM users WHERE email = $1
	`, loginReq.Email).Scan(&user.ID, &user.Username, &user.FirstName, &user.LastName,
		&user.Email, &user.Password, &user.Role, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, models.ErrorResponse{
				Error:   "Authentication failed",
				Message: "Invalid email or password",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to fetch user",
		})
		return
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Error:   "Authentication failed",
			Message: "Invalid email or password",
		})
		return
	}

	// Generate tokens
	token, err := middleware.GenerateJWT(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Token error",
			Message: "Failed to generate token",
		})
		return
	}

	refreshToken, err := middleware.GenerateRefreshToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Token error",
			Message: "Failed to generate refresh token",
		})
		return
	}

	// Don't return password
	user.Password = ""

	// Return success response
	c.JSON(http.StatusOK, models.AuthResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User:         user,
		Message:      "Login successful",
	})
}

// UserLogout handles user logout
func UserLogout(c *gin.Context) {
	c.JSON(http.StatusOK, models.SuccessResponse{
		Message: "Logout successful",
	})
}

// GetAllUsers retrieves all users (admin only)
func GetAllUsers(c *gin.Context) {
	database := db.GetDB()

	rows, err := database.Query(`
		SELECT id, username, first_name, last_name, email, role, created_at, updated_at
		FROM users ORDER BY created_at DESC
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to fetch users",
		})
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Username, &user.FirstName, &user.LastName,
			&user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{
				Error:   "Database error",
				Message: "Failed to decode users",
			})
			return
		}
		users = append(users, user)
	}

	// Check for iteration errors
	if err = rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Database error",
			Message: "Error occurred while reading users",
		})
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse{
		Message: "Users retrieved successfully",
		Data:    users,
	})
}

// GetUserByID retrieves a specific user by ID
func GetUserByID(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID format",
		})
		return
	}

	database := db.GetDB()
	var user models.User
	err = database.QueryRow(`
		SELECT id, username, first_name, last_name, email, role, created_at, updated_at
		FROM users WHERE id = $1
	`, userID).Scan(&user.ID, &user.Username, &user.FirstName, &user.LastName,
		&user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, models.ErrorResponse{
				Error:   "Not found",
				Message: "User not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to fetch user",
		})
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse{
		Message: "User retrieved successfully",
		Data:    user,
	})
}

// UpdateUser updates a user's information
func UpdateUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID format",
		})
		return
	}

	var updateReq models.UserUpdateRequest
	if err := c.ShouldBindJSON(&updateReq); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Invalid request",
			Message: "Failed to parse request body",
		})
		return
	}

	// Check authorization (users can only update their own profile unless admin)
	contextUserID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Error:   "Unauthorized",
			Message: "User ID not found in context",
		})
		return
	}

	contextRole, exists := c.Get("role")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Error:   "Unauthorized",
			Message: "User role not found in context",
		})
		return
	}

	// Convert contextUserID to string for comparison
	var contextUserIDStr string
	switch v := contextUserID.(type) {
	case string:
		contextUserIDStr = v
	case int:
		contextUserIDStr = strconv.Itoa(v)
	default:
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Internal error",
			Message: "Invalid user ID type in context",
		})
		return
	}

	if contextUserIDStr != userIDStr && contextRole.(string) != "admin" {
		c.JSON(http.StatusForbidden, models.ErrorResponse{
			Error:   "Forbidden",
			Message: "You can only update your own profile",
		})
		return
	}

	// Check if there's anything to update
	if updateReq.Username == "" && updateReq.FirstName == "" && updateReq.LastName == "" &&
		updateReq.Email == "" && updateReq.Role == "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Validation error",
			Message: "At least one field must be provided for update",
		})
		return
	}

	// Build update query dynamically
	setParts := []string{"updated_at = $1"}
	args := []interface{}{time.Now()}
	argIndex := 2

	if updateReq.Username != "" {
		setParts = append(setParts, fmt.Sprintf("username = $%d", argIndex))
		args = append(args, updateReq.Username)
		argIndex++
	}
	if updateReq.FirstName != "" {
		setParts = append(setParts, fmt.Sprintf("first_name = $%d", argIndex))
		args = append(args, updateReq.FirstName)
		argIndex++
	}
	if updateReq.LastName != "" {
		setParts = append(setParts, fmt.Sprintf("last_name = $%d", argIndex))
		args = append(args, updateReq.LastName)
		argIndex++
	}
	if updateReq.Email != "" {
		setParts = append(setParts, fmt.Sprintf("email = $%d", argIndex))
		args = append(args, updateReq.Email)
		argIndex++
	}
	if updateReq.Role != "" && contextRole.(string) == "admin" {
		setParts = append(setParts, fmt.Sprintf("role = $%d", argIndex))
		args = append(args, updateReq.Role)
		argIndex++
	}

	// Add WHERE clause parameter
	args = append(args, userID)
	query := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d",
		strings.Join(setParts, ", "), argIndex)

	database := db.GetDB()
	result, err := database.Exec(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to update user",
		})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to check update result",
		})
		return
	}

	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.ErrorResponse{
			Error:   "Not found",
			Message: "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse{
		Message: "User updated successfully",
	})
}

// DeleteUser deletes a user (admin only)
func DeleteUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID format",
		})
		return
	}

	// Prevent admin from deleting themselves
	contextUserID, exists := c.Get("user_id")
	if exists {
		var contextUserIDStr string
		switch v := contextUserID.(type) {
		case string:
			contextUserIDStr = v
		case int:
			contextUserIDStr = strconv.Itoa(v)
		}

		if contextUserIDStr == userIDStr {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{
				Error:   "Invalid operation",
				Message: "You cannot delete your own account",
			})
			return
		}
	}

	database := db.GetDB()
	result, err := database.Exec("DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to delete user",
		})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to check delete result",
		})
		return
	}

	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.ErrorResponse{
			Error:   "Not found",
			Message: "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse{
		Message: "User deleted successfully",
	})
}

// GetProfile returns the current user's profile
func GetProfile(c *gin.Context) {
	contextUserID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Error:   "Unauthorized",
			Message: "User ID not found in context",
		})
		return
	}

	var userID int
	var err error

	switch v := contextUserID.(type) {
	case string:
		userID, err = strconv.Atoi(v)
	case int:
		userID = v
	default:
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Internal error",
			Message: "Invalid user ID type in context",
		})
		return
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID",
		})
		return
	}

	database := db.GetDB()
	var user models.User
	err = database.QueryRow(`
		SELECT id, username, first_name, last_name, email, role, created_at, updated_at
		FROM users WHERE id = $1
	`, userID).Scan(&user.ID, &user.Username, &user.FirstName, &user.LastName,
		&user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, models.ErrorResponse{
				Error:   "Not found",
				Message: "User profile not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to fetch profile",
		})
		return
	}

	c.JSON(http.StatusOK, models.SuccessResponse{
		Message: "Profile retrieved successfully",
		Data:    user,
	})
}
