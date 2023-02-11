package router

import (
	"fmt"

	"github.com/ChiefGupta/go-fiber-jwt/controllers"
	"github.com/ChiefGupta/go-fiber-jwt/middleware"
	"github.com/gofiber/fiber/v2"
)

func Routes(app *fiber.App) {
	app.Route("/auth", func(router fiber.Router) {
		router.Post("/register", controllers.SignUpUser)
		router.Post("/login", controllers.SignInUser)
		router.Get("/logout", middleware.DeserializeUser, controllers.LogoutUser)
	})

	app.Route("/users", func(router fiber.Router) {
		router.Get("/me", middleware.DeserializeUser, controllers.GetMe)
	})

	app.All("*", func(c *fiber.Ctx) error {
		path := c.Path()
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status":  "fail",
			"message": fmt.Sprintf("Path: %v does not exists on this server", path),
		})
	})
}
