package main

import (
	"fmt"
	"log"

	"github.com/ChiefGupta/go-fiber-postgres/initializers"
	"github.com/ChiefGupta/go-fiber-postgres/models"
)

func init() {
	config, err := initializers.LoadConfig(".")
	if err != nil {
		log.Fatal("Could not load environment variables", err.Error())
	}

	initializers.ConnectDB(&config)
}

func main() {
	initializers.DB.AutoMigrate(&models.User{})
	fmt.Println("Migration complete")
}
