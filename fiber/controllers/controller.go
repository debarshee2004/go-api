package controllers

import (
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/debarshee/fiberapi/db"
	"github.com/debarshee/fiberapi/middleware"
	"github.com/debarshee/fiberapi/models"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

// UserSignup handles user registration
func UserSignup(c *fiber.Ctx) error {
	var signupReq models.SignupRequest
	if err := c.BodyParser(&signupReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "Invalid request",
			Message: "Failed to parse request body",
		})
	}

	// Validate required fields
	if signupReq.Email == "" || signupReq.Password == "" || signupReq.Username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "Validation error",
			Message: "Email, username, and password are required",
		})
	}

	// Check if user already exists
	database := db.GetDB()
	var existingUser models.User
	err := database.QueryRow("SELECT id FROM users WHERE email = $1", signupReq.Email).Scan(&existingUser.ID)
	if err == nil {
		return c.Status(fiber.StatusConflict).JSON(models.ErrorResponse{
			Error:   "User exists",
			Message: "User with this email already exists",
		})
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(signupReq.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "Internal error",
			Message: "Failed to process password",
		})
	}

	// Set default role if not provided
	if signupReq.Role == "" {
		signupReq.Role = "user"
	}

	// Insert user into database
	var userID int
	query := `
		INSERT INTO users (username, first_name, last_name, email, password, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`
	now := time.Now()
	err = database.QueryRow(query, signupReq.Username, signupReq.FirstName, signupReq.LastName,
		signupReq.Email, string(hashedPassword), signupReq.Role, now, now).Scan(&userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to create user",
		})
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
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "Token error",
			Message: "Failed to generate token",
		})
	}

	refreshToken, err := middleware.GenerateRefreshToken(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "Token error",
			Message: "Failed to generate refresh token",
		})
	}

	// Return success response
	authResponse := models.AuthResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User:         user,
		Message:      "User created successfully",
	}
	return c.Status(fiber.StatusCreated).JSON(authResponse)
}

// UserLogin handles user authentication
func UserLogin(c *fiber.Ctx) error {
	var loginReq models.LoginRequest
	if err := c.BodyParser(&loginReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "Invalid request",
			Message: "Failed to parse request body",
		})
	}

	// Validate required fields
	if loginReq.Email == "" || loginReq.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "Validation error",
			Message: "Email and password are required",
		})
	}

	// Find user by email
	database := db.GetDB()
	var user models.User
	query := `
		SELECT id, username, first_name, last_name, email, password, role, created_at, updated_at
		FROM users WHERE email = $1
	`
	err := database.QueryRow(query, loginReq.Email).Scan(
		&user.ID, &user.Username, &user.FirstName, &user.LastName,
		&user.Email, &user.Password, &user.Role, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{
			Error:   "Authentication failed",
			Message: "Invalid email or password",
		})
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(models.ErrorResponse{
			Error:   "Authentication failed",
			Message: "Invalid email or password",
		})
	}

	// Generate tokens
	token, err := middleware.GenerateJWT(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "Token error",
			Message: "Failed to generate token",
		})
	}

	refreshToken, err := middleware.GenerateRefreshToken(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "Token error",
			Message: "Failed to generate refresh token",
		})
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
	return c.Status(fiber.StatusOK).JSON(authResponse)
}

// UserLogout handles user logout (invalidate token on client side)
func UserLogout(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(models.SuccessResponse{
		Message: "Logout successful",
	})
}

// GetAllUsers retrieves all users (admin only)
func GetAllUsers(c *fiber.Ctx) error {
	database := db.GetDB()

	query := `
		SELECT id, username, first_name, last_name, email, role, created_at, updated_at
		FROM users ORDER BY created_at DESC
	`
	rows, err := database.Query(query)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to fetch users",
		})
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Username, &user.FirstName, &user.LastName,
			&user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
				Error:   "Database error",
				Message: "Failed to decode users",
			})
		}
		users = append(users, user)
	}

	return c.Status(fiber.StatusOK).JSON(models.SuccessResponse{
		Message: "Users retrieved successfully",
		Data:    users,
	})
}

// GetUserByID retrieves a specific user by ID
func GetUserByID(c *fiber.Ctx) error {
	userID := c.Params("id")
	id, err := strconv.Atoi(userID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID format",
		})
	}

	database := db.GetDB()
	var user models.User
	query := `
		SELECT id, username, first_name, last_name, email, role, created_at, updated_at
		FROM users WHERE id = $1
	`
	err = database.QueryRow(query, id).Scan(
		&user.ID, &user.Username, &user.FirstName, &user.LastName,
		&user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(models.ErrorResponse{
				Error:   "Not found",
				Message: "User not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to fetch user",
		})
	}

	return c.Status(fiber.StatusOK).JSON(models.SuccessResponse{
		Message: "User retrieved successfully",
		Data:    user,
	})
}

// UpdateUser updates a user's information
func UpdateUser(c *fiber.Ctx) error {
	userID := c.Params("id")
	id, err := strconv.Atoi(userID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID format",
		})
	}

	var updateReq models.UserUpdateRequest
	if err := c.BodyParser(&updateReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "Invalid request",
			Message: "Failed to parse request body",
		})
	}

	// Check authorization (users can only update their own profile unless admin)
	contextUserID := c.Locals("user_id").(string)
	contextRole := c.Locals("role").(string)

	if contextUserID != userID && contextRole != "admin" {
		return c.Status(fiber.StatusForbidden).JSON(models.ErrorResponse{
			Error:   "Forbidden",
			Message: "You can only update your own profile",
		})
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

	// Add the WHERE clause parameter
	args = append(args, id)
	whereClause := "$" + strconv.Itoa(argIndex)

	query := "UPDATE users SET " + strings.Join(setParts, ", ") + " WHERE id = " + whereClause

	database := db.GetDB()
	result, err := database.Exec(query, args...)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to update user",
		})
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to check update result",
		})
	}

	if rowsAffected == 0 {
		return c.Status(fiber.StatusNotFound).JSON(models.ErrorResponse{
			Error:   "Not found",
			Message: "User not found",
		})
	}

	return c.Status(fiber.StatusOK).JSON(models.SuccessResponse{
		Message: "User updated successfully",
	})
}

// DeleteUser deletes a user (admin only)
func DeleteUser(c *fiber.Ctx) error {
	userID := c.Params("id")
	id, err := strconv.Atoi(userID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID format",
		})
	}

	database := db.GetDB()
	result, err := database.Exec("DELETE FROM users WHERE id = $1", id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to delete user",
		})
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to check delete result",
		})
	}

	if rowsAffected == 0 {
		return c.Status(fiber.StatusNotFound).JSON(models.ErrorResponse{
			Error:   "Not found",
			Message: "User not found",
		})
	}

	return c.Status(fiber.StatusOK).JSON(models.SuccessResponse{
		Message: "User deleted successfully",
	})
}

// GetProfile returns the current user's profile
func GetProfile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	id, err := strconv.Atoi(userID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID",
		})
	}

	database := db.GetDB()
	var user models.User
	query := `
		SELECT id, username, first_name, last_name, email, role, created_at, updated_at
		FROM users WHERE id = $1
	`
	err = database.QueryRow(query, id).Scan(
		&user.ID, &user.Username, &user.FirstName, &user.LastName,
		&user.Email, &user.Role, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to fetch profile",
		})
	}

	return c.Status(fiber.StatusOK).JSON(models.SuccessResponse{
		Message: "Profile retrieved successfully",
		Data:    user,
	})
}
