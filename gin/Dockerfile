# Use the official Go image as the base image
FROM golang:1.21-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Use a minimal alpine image for the final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create a non-root user
RUN addgroup -g 1001 -S golang && \
    adduser -S golang -u 1001 -G golang

WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/main .

# Change ownership of the binary
RUN chown golang:golang main

# Switch to non-root user
USER golang

# Expose port 8080
EXPOSE 8080

# Set default environment variables
ENV PORT=8080
ENV DB_HOST=postgres
ENV DB_PORT=5432
ENV DB_USER=postgres
ENV DB_PASSWORD=password
ENV DB_NAME=ginapi
ENV DB_SSLMODE=disable

# Command to run the application
CMD ["./main"]
