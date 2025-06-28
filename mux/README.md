# MongoDB API Server

A complete REST API server built with Go, MongoDB, and JWT authentication featuring user management with CRUD operations.

## Features

- ✅ User Authentication (Signup, Login, Logout)
- ✅ JWT Token-based Authentication
- ✅ Password Hashing with bcrypt
- ✅ User Profile Management
- ✅ Complete CRUD Operations for Users
- ✅ Role-based Access Control (Admin/User)
- ✅ MongoDB Integration
- ✅ CORS Support
- ✅ Request Logging
- ✅ Error Handling

## Technologies Used

- **Go** - Backend programming language
- **MongoDB** - NoSQL database
- **Gorilla Mux** - HTTP router
- **JWT** - JSON Web Tokens for authentication
- **bcrypt** - Password hashing

## Prerequisites

- Go 1.19 or higher
- MongoDB running locally or remotely
- Git

## Installation

1. Clone the repository:

```bash
git clone <your-repository-url>
cd 24mongoapi
```

2. Install dependencies:

```bash
go mod tidy
```

3. Set up environment variables:

```bash
cp .env.example .env
# Edit .env with your MongoDB URI and JWT secret
```

4. Make sure MongoDB is running on your system

5. Run the application:

```bash
go run main.go
```

The server will start on `http://localhost:8080`

## API Endpoints

### Authentication Endpoints

#### User Signup

- **POST** `/api/v1/auth/signup`
- **Body:**

```json
{
  "username": "johndoe",
  "first_name": "John",
  "last_name": "Doe",
  "email": "john@example.com",
  "password": "password123",
  "role": "user"
}
```

- **Response:**

```json
{
  "token": "jwt_token_here",
  "refresh_token": "refresh_token_here",
  "user": {
    "id": "user_id",
    "username": "johndoe",
    "email": "john@example.com",
    "role": "user"
  },
  "message": "User created successfully"
}
```

#### User Login

- **POST** `/api/v1/auth/login`
- **Body:**

```json
{
  "email": "john@example.com",
  "password": "password123"
}
```

- **Response:**

```json
{
  "token": "jwt_token_here",
  "refresh_token": "refresh_token_here",
  "user": {
    "id": "user_id",
    "username": "johndoe",
    "email": "john@example.com",
    "role": "user"
  },
  "message": "Login successful"
}
```

#### User Logout

- **POST** `/api/v1/auth/logout`
- **Headers:** `Authorization: Bearer <token>`
- **Response:**

```json
{
  "message": "Logout successful"
}
```

### User Management Endpoints

#### Get User Profile

- **GET** `/api/v1/profile`
- **Headers:** `Authorization: Bearer <token>`
- **Response:**

```json
{
  "message": "Profile retrieved successfully",
  "data": {
    "id": "user_id",
    "username": "johndoe",
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "role": "user",
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

#### Get All Users (Admin Only)

- **GET** `/api/v1/users`
- **Headers:** `Authorization: Bearer <admin_token>`
- **Response:**

```json
{
  "message": "Users retrieved successfully",
  "data": [
    {
      "id": "user_id",
      "username": "johndoe",
      "email": "john@example.com",
      "role": "user"
    }
  ]
}
```

#### Get User by ID

- **GET** `/api/v1/users/{id}`
- **Headers:** `Authorization: Bearer <token>`
- **Response:**

```json
{
  "message": "User retrieved successfully",
  "data": {
    "id": "user_id",
    "username": "johndoe",
    "email": "john@example.com",
    "role": "user"
  }
}
```

#### Update User

- **PUT** `/api/v1/users/{id}`
- **Headers:** `Authorization: Bearer <token>`
- **Body:**

```json
{
  "username": "newusername",
  "first_name": "Updated",
  "last_name": "Name",
  "email": "newemail@example.com"
}
```

- **Response:**

```json
{
  "message": "User updated successfully"
}
```

#### Delete User (Admin Only)

- **DELETE** `/api/v1/users/{id}`
- **Headers:** `Authorization: Bearer <admin_token>`
- **Response:**

```json
{
  "message": "User deleted successfully"
}
```

#### Health Check

- **GET** `/api/v1/health`
- **Response:**

```json
{
  "status": "healthy",
  "message": "API is running"
}
```

## Authentication

The API uses JWT (JSON Web Tokens) for authentication. After successful login/signup, you'll receive a token that must be included in the `Authorization` header for protected routes:

```
Authorization: Bearer <your_jwt_token>
```

## Roles

- **user**: Regular user with access to their own profile and user operations
- **admin**: Administrative user with access to all user management operations

## Error Responses

All errors follow this format:

```json
{
  "error": "Error Type",
  "message": "Detailed error message"
}
```

Common HTTP status codes:

- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `500` - Internal Server Error

## Environment Variables

| Variable     | Description               | Default                     |
| ------------ | ------------------------- | --------------------------- |
| `MONGO_URI`  | MongoDB connection string | `mongodb://localhost:27017` |
| `JWT_SECRET` | Secret key for JWT tokens | `your-secret-key`           |
| `PORT`       | Server port               | `8080`                      |

## Testing the API

You can test the API using tools like:

- **Postman**
- **curl**
- **HTTPie**
- **Insomnia**

### Example curl commands:

```bash
# Health check
curl http://localhost:8080/api/v1/health

# Signup
curl -X POST http://localhost:8080/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "first_name": "Test",
    "last_name": "User",
    "email": "test@example.com",
    "password": "password123",
    "role": "user"
  }'

# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'

# Get profile (replace TOKEN with actual token)
curl -X GET http://localhost:8080/api/v1/profile \
  -H "Authorization: Bearer TOKEN"
```

## Project Structure

```
24mongoapi/
├── controllers/          # HTTP request handlers
│   └── controller.go
├── db/                   # Database configuration and connection
│   └── database.go
├── middleware/           # HTTP middleware (auth, CORS, etc.)
│   └── middleware.go
├── models/              # Data models and structures
│   └── model.go
├── routes/              # API route definitions
│   └── routes.go
├── .env.example         # Environment variables example
├── go.mod              # Go module dependencies
├── go.sum              # Go module checksums
├── main.go             # Application entry point
└── README.md           # This file
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.
