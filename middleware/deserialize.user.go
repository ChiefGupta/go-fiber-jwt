package middleware

import (
	"strings"

	"github.com/ChiefGupta/go-fiber-jwt/initializers"
	"github.com/ChiefGupta/go-fiber-jwt/models"
	"github.com/ChiefGupta/go-fiber-jwt/utils"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func DeserializeUser(c *fiber.Ctx) error {
	var access_token string
	authorization := c.Get("Authorization")

	if strings.HasPrefix(authorization, "Bearer ") {
		access_token = strings.TrimPrefix(authorization, "Bearer ")
	} else if c.Cookies("access_token") != "" {
		access_token = c.Cookies("access_token")
	}

	if access_token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "fail",
			"message": "You are not logged in",
		})
	}

	config, _ := initializers.LoadConfig(".")

	tokenClaims, err := utils.ValidateToken(access_token, config.AccessTokenPublicKey)
	if err != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"status":  "fail",
			"message": err.Error(),
		})
	}

	var user models.User
	err = initializers.DB.First(&user, "id = ?", tokenClaims.UserID).Error

	if err == gorm.ErrRecordNotFound {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"status":  "fail",
			"message": "the user belonging to this token no logger exists",
		})
	}

	c.Locals("user", models.FilterUserRecord(&user))
	c.Locals("access_token_uuid", tokenClaims.UserID)

	return c.Next()
}
