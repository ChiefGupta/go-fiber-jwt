package controllers

import (
	"strings"
	"time"

	"github.com/ChiefGupta/go-fiber-postgres/initializers"
	"github.com/ChiefGupta/go-fiber-postgres/models"
	"github.com/gofiber/fiber/v2"
)

func CreateUserHandler(c *fiber.Ctx) error {
	var payload *models.CreateUserSchema

	if err := c.BodyParser(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "fail",
			"message": err.Error(),
		})
	}

	errors := models.ValidateStruct(payload)
	if errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errors)
	}

	now := time.Now()
	newUser := models.User{
		Username:  payload.Username,
		Email:     payload.Email,
		Password:  payload.Password,
		CreatedAt: now,
		UpdatedAt: now,
	}

	result := initializers.DB.Create(&newUser)

	if result.Error != nil && strings.Contains(result.Error.Error(), "duplicate key value violates unique") {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"status":  "fail",
			"message": "Email or Username already exists, please use another",
		})
	} else if result.Error != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"status":  "error",
			"message": result.Error.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status": "success",
		"data":   fiber.Map{"user": newUser},
	})
}

func FindUsers(c *fiber.Ctx) error {
	var users []models.User

	result := initializers.DB.Find(&users)
	if result.Error != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"status":  "error",
			"message": result.Error,
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"results": len(users),
		"users":   users,
	})
}

func FindUserById(c *fiber.Ctx) error {
	userId := c.Params("userId")

	var user models.User

	result := initializers.DB.First(&user, "email= ?", userId)
	if result.Error != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"status":  "error",
			"message": result.Error.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": "success",
		"data":   fiber.Map{"user": user},
	})
}

func UpdateUser(c *fiber.Ctx) error {
	userId := c.Params("userId")

	var payload *models.UpdateUserSchema

	if err := c.BodyParser(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "fail",
			"message": err.Error(),
		})
	}

	var user models.User

	result := initializers.DB.First(&user, "email= ?", userId)
	if result.Error != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"status":  "error",
			"message": result.Error.Error(),
		})
	}

	updates := make(map[string]interface{})

	if payload.Username != "" {
		updates["username"] = payload.Username
	}

	if payload.Email != "" {
		updates["email"] = payload.Email
	}

	if payload.Password != "" {
		updates["password"] = payload.Password
	}

	updates["updated_at"] = time.Now()

	initializers.DB.Model(&user).Updates(updates)

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"status": "success",
		"data":   fiber.Map{"user": user},
	})
}

func DeleteUser(c *fiber.Ctx) error {
	userId := c.Params("userId")

	var user models.User

	result := initializers.DB.First(&user, "email= ?", userId)
	if result.Error != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"status":  "error",
			"message": result.Error.Error(),
		})
	} else {
		initializers.DB.Delete(&user, "email= ?", userId)
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"status":  "success",
			"message": "User deleted successfully",
		})
	}
}
