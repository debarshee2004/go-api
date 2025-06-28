# Gin REST API with PostgreSQL

A RESTful API built with Go's Gin framework and PostgreSQL database, featuring JWT authentication and user management.

## Features

- User registration and authentication
- JWT token-based authorization
- Role-based access control (Admin/User)
- PostgreSQL database integration
- CORS support
- Request logging middleware
- Password hashing with bcrypt

## Project Structure

```
gin/
├── main.go                 # Application entry point
├── go.mod                  # Go module file
├── controllers/
│   └── controller.go       # HTTP handlers
├── db/
│   └── database.go         # Database connection and setup
├── middleware/
│   └── middleware.go       # Authentication and other middleware
├── models/
│   └── model.go           # Data models and structs
└── routes/
    └── routes.go          # API route definitions
```

## Prerequisites

- Go 1.23.6 or later
- PostgreSQL 12 or later

## Environment Variables

Create a `.env` file or set the following environment variables:

```bash
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=password
DB_NAME=ginapi
DB_SSLMODE=disable

# JWT Configuration
JWT_SECRET=your-super-secure-jwt-secret-key

# Server Configuration
PORT=8080
```

## Database Setup

1. Create a PostgreSQL database:

```sql
CREATE DATABASE ginapi;
```

2. The application will automatically create the required tables on startup.

## Installation

1. Clone the repository
2. Navigate to the gin directory:

```bash
cd gin
```

3. Install dependencies:

```bash
go mod tidy
```

4. Set up your environment variables

5. Run the application:

```bash
go run main.go
```

## API Endpoints

### Public Endpoints

- `GET /api/v1/health` - Health check
- `POST /api/v1/auth/signup` - User registration
- `POST /api/v1/auth/login` - User login

### Protected Endpoints (Requires Authentication)

- `POST /api/v1/auth/logout` - User logout
- `GET /api/v1/profile` - Get current user profile
- `GET /api/v1/users/:id` - Get user by ID
- `PUT /api/v1/users/:id` - Update user

### Admin Only Endpoints

- `GET /api/v1/users` - Get all users
- `DELETE /api/v1/users/:id` - Delete user

## API Usage Examples

### User Registration

```bash
curl -X POST http://localhost:8080/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "password": "securepassword",
    "role": "user"
  }'
```

### User Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securepassword"
  }'
```

### Get Profile (with JWT token)

```bash
curl -X GET http://localhost:8080/api/v1/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Database Schema

### Users Table

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    session_id VARCHAR(255),
    session_token TEXT,
    refresh_token TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Testing

You can test the API using tools like:

- Postman
- curl
- HTTPie
- Insomnia

## Security Features

- Password hashing using bcrypt
- JWT token authentication
- Role-based authorization
- CORS protection
- Input validation

## Dependencies

- `github.com/gin-gonic/gin` - HTTP web framework
- `github.com/lib/pq` - PostgreSQL driver
- `github.com/dgrijalva/jwt-go` - JWT implementation
- `golang.org/x/crypto` - Cryptography packages

## License

This project is open source and available under the MIT License.
