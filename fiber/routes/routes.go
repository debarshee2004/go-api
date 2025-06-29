package routes

import (
	"github.com/debarshee/fiberapi/controllers"
	"github.com/debarshee/fiberapi/middleware"
	"github.com/gofiber/fiber/v2"
)

// SetupRoutes configures all API routes
func SetupRoutes(app *fiber.App) {
	// Create API group
	api := app.Group("/api/v1")

	// Health check endpoint
	api.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"status":  "healthy",
			"message": "API is running",
		})
	})

	// Public routes (no authentication required)
	auth := api.Group("/auth")
	auth.Post("/signup", controllers.UserSignup)
	auth.Post("/login", controllers.UserLogin)

	// Protected routes (authentication required)
	protected := api.Group("", middleware.JWTAuth)

	// User profile routes
	protected.Post("/auth/logout", controllers.UserLogout)
	protected.Get("/profile", controllers.GetProfile)
	protected.Get("/users/:id", controllers.GetUserByID)
	protected.Put("/users/:id", controllers.UpdateUser)

	// Admin only routes
	admin := protected.Group("", middleware.AdminOnly)
	admin.Get("/users", controllers.GetAllUsers)
	admin.Delete("/users/:id", controllers.DeleteUser)
}
