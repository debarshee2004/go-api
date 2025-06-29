package routes

import (
	"net/http"

	"github.com/debarshee/chiapi/controllers"
	"github.com/debarshee/chiapi/middleware"
	"github.com/go-chi/chi/v5"
)

// SetupRoutes configures all API routes
func SetupRoutes() *chi.Mux {
	router := chi.NewRouter()

	// Apply global middleware
	router.Use(middleware.CORS)
	router.Use(middleware.ContentType)
	router.Use(middleware.Logger)

	// Create API subrouter
	router.Route("/api/v1", func(r chi.Router) {
		// Health check endpoint
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "healthy", "message": "API is running"}`))
		})

		// Public routes (no authentication required)
		r.Route("/auth", func(r chi.Router) {
			r.Post("/signup", controllers.UserSignup)
			r.Post("/login", controllers.UserLogin)
		})

		// Protected routes (authentication required)
		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTAuth)

			// User profile routes
			r.Post("/auth/logout", controllers.UserLogout)
			r.Get("/profile", controllers.GetProfile)
			r.Get("/users/{id}", controllers.GetUserByID)
			r.Put("/users/{id}", controllers.UpdateUser)

			// Admin only routes
			r.Group(func(r chi.Router) {
				r.Use(middleware.AdminOnly)
				r.Get("/users", controllers.GetAllUsers)
				r.Delete("/users/{id}", controllers.DeleteUser)
			})
		})
	})

	return router
}

// GetRouter returns the configured router
func GetRouter() *chi.Mux {
	return SetupRoutes()
}
