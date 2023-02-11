package router

import (
	"github.com/gofiber/fiber/v2"
)

func Routes(app *fiber.App) {
	app.Route("/users", func(router fiber.Router) {

	})

	app.Route("/users/:userId", func(router fiber.Router) {

	})
}
