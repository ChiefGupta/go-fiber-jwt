package router

import (
	"github.com/ChiefGupta/go-fiber-postgres/controllers"
	"github.com/gofiber/fiber/v2"
)

func Routes(app *fiber.App) {
	app.Route("/users", func(router fiber.Router) {
		router.Post("", controllers.CreateUserHandler)
		router.Get("", controllers.FindUsers)
	})

	app.Route("/users/:userId", func(router fiber.Router) {
		router.Get("", controllers.FindUserById)
		router.Delete("", controllers.DeleteUser)
		router.Patch("", controllers.UpdateUser)
	})
}
