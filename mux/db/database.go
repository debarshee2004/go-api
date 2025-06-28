package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var connectionString string = os.Getenv("MONGO_URI")

const databaseName string = "mongodb"
const userCollectionName string = "users"

var UserCollection *mongo.Collection
var Client *mongo.Client

func init() {
	// Set default connection string if not provided
	if connectionString == "" {
		connectionString = "mongodb://localhost:27017"
		log.Println("Warning: MONGO_URI not set, using default: mongodb://localhost:27017")
	}

	// client options
	clientOption := options.Client().ApplyURI(connectionString)
	clientOption.SetMaxPoolSize(10)
	clientOption.SetMinPoolSize(2)
	clientOption.SetMaxConnIdleTime(30 * time.Second)

	// connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOption)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	// Test the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}

	fmt.Println("Connected to MongoDB successfully!")

	// Set global client
	Client = client

	// collection instance
	UserCollection = client.Database(databaseName).Collection(userCollectionName)
	if UserCollection == nil {
		log.Fatalf("Failed to get collection: %s", userCollectionName)
	}

	fmt.Printf("Collection instance %s is ready to use.\n", userCollectionName)
}

// GetUserCollection returns the user collection
func GetUserCollection() *mongo.Collection {
	return UserCollection
}

// GetClient returns the MongoDB client
func GetClient() *mongo.Client {
	return Client
}

// Disconnect closes the MongoDB connection
func Disconnect() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return Client.Disconnect(ctx)
}
