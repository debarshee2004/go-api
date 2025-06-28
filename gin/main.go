package main

import (
	"fmt"
	"log"
	"os"

	"github.com/debarshee2004/ginapi/db"
	"github.com/debarshee2004/ginapi/routes"
)

func main() {
	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Setup routes
	router := routes.GetRouter()

	// Start server
	fmt.Printf("🚀 Gin API Server is running on port %s\n", port)
	fmt.Printf("📚 API Documentation:\n")
	fmt.Printf("   Health Check: GET http://localhost:%s/api/v1/health\n", port)
	fmt.Printf("   User Signup:  POST http://localhost:%s/api/v1/auth/signup\n", port)
	fmt.Printf("   User Login:   POST http://localhost:%s/api/v1/auth/login\n", port)
	fmt.Printf("   User Logout:  POST http://localhost:%s/api/v1/auth/logout\n", port)
	fmt.Printf("   Get Profile:  GET http://localhost:%s/api/v1/profile\n", port)
	fmt.Printf("   Get All Users: GET http://localhost:%s/api/v1/users (Admin only)\n", port)
	fmt.Printf("   Get User:     GET http://localhost:%s/api/v1/users/{id}\n", port)
	fmt.Printf("   Update User:  PUT http://localhost:%s/api/v1/users/{id}\n", port)
	fmt.Printf("   Delete User:  DELETE http://localhost:%s/api/v1/users/{id} (Admin only)\n", port)

	// Graceful shutdown on exit
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing PostgreSQL connection: %v", err)
		} else {
			fmt.Println("PostgreSQL connection closed.")
		}
	}()

	// Start the HTTP server
	log.Fatal(router.Run(":" + port))
}
