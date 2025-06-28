package routes

import (
	"net/http"

	"github.com/debarshee2004/ginapi/controllers"
	"github.com/debarshee2004/ginapi/middleware"
	"github.com/gin-gonic/gin"
)

// SetupRoutes configures all API routes
func SetupRoutes() *gin.Engine {
	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()

	// Apply global middleware
	router.Use(middleware.CORS())
	router.Use(middleware.Logger())
	router.Use(gin.Recovery())

	// Create API group
	api := router.Group("/api/v1")

	// Health check endpoint
	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"message": "API is running",
		})
	})

	// Public routes (no authentication required)
	auth := api.Group("/auth")
	{
		auth.POST("/signup", controllers.UserSignup)
		auth.POST("/login", controllers.UserLogin)
	}

	// Protected routes (authentication required)
	protected := api.Group("")
	protected.Use(middleware.JWTAuth())
	{
		// User profile routes
		protected.POST("/auth/logout", controllers.UserLogout)
		protected.GET("/profile", controllers.GetProfile)
		protected.GET("/users/:id", controllers.GetUserByID)
		protected.PUT("/users/:id", controllers.UpdateUser)
	}

	// Admin only routes
	admin := protected.Group("")
	admin.Use(middleware.AdminOnly())
	{
		admin.GET("/users", controllers.GetAllUsers)
		admin.DELETE("/users/:id", controllers.DeleteUser)
	}

	return router
}

// GetRouter returns the configured router
func GetRouter() *gin.Engine {
	return SetupRoutes()
}
