package routes

import (
	"net/http"

	"github.com/debarshee2004/mongoapi/controllers"
	"github.com/debarshee2004/mongoapi/middleware"
	"github.com/gorilla/mux"
)

// SetupRoutes configures all API routes
func SetupRoutes() *mux.Router {
	router := mux.NewRouter()

	// Apply global middleware
	router.Use(middleware.CORS)
	router.Use(middleware.ContentType)
	router.Use(middleware.Logger)

	// Create API subrouter
	api := router.PathPrefix("/api/v1").Subrouter()

	// Health check endpoint
	api.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "healthy", "message": "API is running"}`))
	}).Methods("GET")

	// Public routes (no authentication required)
	auth := api.PathPrefix("/auth").Subrouter()
	auth.HandleFunc("/signup", controllers.UserSignup).Methods("POST")
	auth.HandleFunc("/login", controllers.UserLogin).Methods("POST")

	// Protected routes (authentication required)
	protected := api.PathPrefix("").Subrouter()
	protected.Use(middleware.JWTAuth)

	// User profile routes
	protected.HandleFunc("/auth/logout", controllers.UserLogout).Methods("POST")
	protected.HandleFunc("/profile", controllers.GetProfile).Methods("GET")
	protected.HandleFunc("/users/{id}", controllers.GetUserByID).Methods("GET")
	protected.HandleFunc("/users/{id}", controllers.UpdateUser).Methods("PUT")

	// Admin only routes
	admin := protected.PathPrefix("").Subrouter()
	admin.Use(middleware.AdminOnly)
	admin.HandleFunc("/users", controllers.GetAllUsers).Methods("GET")
	admin.HandleFunc("/users/{id}", controllers.DeleteUser).Methods("DELETE")

	return router
}

// GetRouter returns the configured router
func GetRouter() *mux.Router {
	return SetupRoutes()
}
