package main

import (
	"log"

	"github.com/ChiefGupta/go-fiber-postgres/initializers"
	"github.com/ChiefGupta/go-fiber-postgres/router"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

func init() {
	config, err := initializers.LoadConfig(".")
	if err != nil {
		log.Fatal("Could not load env variables", err.Error())
	}

	initializers.ConnectDB(&config)
}

func main() {
	config, err := initializers.LoadConfig(".")
	if err != nil {
		log.Fatal("Could not load env variables", err)
	}

	app := fiber.New()

	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000",
		AllowHeaders:     "Origin, Content-Type, Accept",
		AllowMethods:     "GET, POST, PATCH, DELETE",
		AllowCredentials: true,
	}))

	router.Routes(app)

	log.Fatal(app.Listen(":" + config.ServerPort))
}
