package controllers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/debarshee2004/mongoapi/db"
	"github.com/debarshee2004/mongoapi/middleware"
	"github.com/debarshee2004/mongoapi/models"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
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
	collection := db.GetUserCollection()
	var existingUser models.User
	err := collection.FindOne(context.TODO(), bson.M{"email": signupReq.Email}).Decode(&existingUser)
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
	user := models.User{
		Username:  signupReq.Username,
		FirstName: signupReq.FirstName,
		LastName:  signupReq.LastName,
		Email:     signupReq.Email,
		Password:  string(hashedPassword),
		Role:      signupReq.Role,
		CreatedAt: primitive.NewDateTimeFromTime(time.Now()),
		UpdatedAt: primitive.NewDateTimeFromTime(time.Now()),
	}

	// Insert user into database
	result, err := collection.InsertOne(context.TODO(), user)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to create user",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Set the ID from the insert result
	user.ID = result.InsertedID.(primitive.ObjectID)
	user.Password = "" // Don't return password

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
	collection := db.GetUserCollection()
	var user models.User
	err := collection.FindOne(context.TODO(), bson.M{"email": loginReq.Email}).Decode(&user)
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
	collection := db.GetUserCollection()

	cursor, err := collection.Find(context.TODO(), bson.M{})
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to fetch users",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}
	defer cursor.Close(context.TODO())

	var users []models.User
	if err = cursor.All(context.TODO(), &users); err != nil {
		response := models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to decode users",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Remove passwords from response
	for i := range users {
		users[i].Password = ""
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
	vars := mux.Vars(r)
	userID := vars["id"]

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID format",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	collection := db.GetUserCollection()
	var user models.User
	err = collection.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
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

	// Remove password from response
	user.Password = ""

	response := models.SuccessResponse{
		Message: "User retrieved successfully",
		Data:    user,
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// UpdateUser updates a user's information
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	objectID, err := primitive.ObjectIDFromHex(userID)
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

	// Build update document
	updateDoc := bson.M{"updated_at": primitive.NewDateTimeFromTime(time.Now())}
	if updateReq.Username != "" {
		updateDoc["username"] = updateReq.Username
	}
	if updateReq.FirstName != "" {
		updateDoc["first_name"] = updateReq.FirstName
	}
	if updateReq.LastName != "" {
		updateDoc["last_name"] = updateReq.LastName
	}
	if updateReq.Email != "" {
		updateDoc["email"] = updateReq.Email
	}
	if updateReq.Role != "" && contextRole == "admin" {
		updateDoc["role"] = updateReq.Role
	}

	collection := db.GetUserCollection()
	result, err := collection.UpdateOne(
		context.TODO(),
		bson.M{"_id": objectID},
		bson.M{"$set": updateDoc},
	)

	if err != nil {
		response := models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to update user",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	if result.MatchedCount == 0 {
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
	vars := mux.Vars(r)
	userID := vars["id"]

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID format",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	collection := db.GetUserCollection()
	result, err := collection.DeleteOne(context.TODO(), bson.M{"_id": objectID})
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to delete user",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	if result.DeletedCount == 0 {
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

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Invalid ID",
			Message: "Invalid user ID",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	collection := db.GetUserCollection()
	var user models.User
	err = collection.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		response := models.ErrorResponse{
			Error:   "Database error",
			Message: "Failed to fetch profile",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Remove password from response
	user.Password = ""

	response := models.SuccessResponse{
		Message: "Profile retrieved successfully",
		Data:    user,
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
