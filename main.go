package main

import (
	"encoding/base64"
	"log"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

type User struct {
	ID       string `json:"user_id" validate:"required,min=6,max=20,alphanum"`
	Password string `json:"password" validate:"required,min=8,max=20,alphanum,excludesall=' \t\n'"`
}

var users = make(map[string]*User)

// POST /signup
func createUserHandler(c *fiber.Ctx) error {
	user := new(User)
	if err := c.BodyParser(user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Account creation failed",
			"cause":   "required user_id and password",
		})
	}

	validate := validator.New()
	if err := validate.Struct(user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Validation error",
			"cause":   err.Error(),
		})
	}
	if _, ok := users[user.ID]; ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Account creation failed",
			"cause":   "already same user_id is used",
		})
	}
	// users = append(users, user)
	users[user.ID] = user

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Account successfully created",
		"user": fiber.Map{
			"user_id":  user.ID,
			"nickname": user.ID,
		},
	})
}

// GET /users/{user_id}
func getUsersHandler(c *fiber.Ctx) error {
	// Check if the user exists
	if _, ok := users[c.Params("user_id")]; !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"message": "No User found",
		})
	}

	// Check the Authorization header for the base64 encoded username and password
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Authentication Failed",
		})
	}
	authHeaderParts := strings.SplitN(authHeader, " ", 2)
	if len(authHeaderParts) != 2 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Authentication Failed",
		})
	}
	decodedHeaderParts, err := base64.StdEncoding.DecodeString(authHeaderParts[1])
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Authentication Failed",
		})
	}
	actualInfo := strings.Split(string(decodedHeaderParts), ":")
	if len(actualInfo) != 2 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Authentication Failed",
		})
	}
	userId := actualInfo[0]
	password := actualInfo[1]

	if userId != c.Params("user_id") {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Authentication Failed",
		})
	}

	// If the user was found
	if password != users[userId].Password {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Authentication Failed",
		})
	}

	user := users[userId]
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "User details by user_id",
		"user": fiber.Map{
			"user_id":  user.ID,
			"nickname": user.ID,
			"comment":  "",
		},
	})
}

func deleteUserHandler(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Authentication Failed",
		})
	}
	authHeaderParts := strings.SplitN(authHeader, " ", 2)
	if len(authHeaderParts) != 2 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Authentication Failed",
		})
	}
	decodedHeaderParts, err := base64.StdEncoding.DecodeString(authHeaderParts[1])
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Authentication Failed",
		})
	}
	actualInfo := strings.Split(string(decodedHeaderParts), ":")
	if len(actualInfo) != 2 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Authentication Failed",
		})
	}
	userId := actualInfo[0]
	password := actualInfo[1]

	// Check if the user exists
	if _, ok := users[userId]; !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"message": "No User found",
		})
	} else {
		// If the user was found
		if password != users[userId].Password {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Authentication Failed",
			})
		}
	}
	// Delete the user
	delete(users, userId)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Account and user successfully removed",
	})
}

func main() {
	app := fiber.New()

	app.Post("/signup", createUserHandler)
	app.Get("/users/:user_id", getUsersHandler)
	app.Post("/close", deleteUserHandler)
	log.Fatal(app.Listen("0.0.0.0:50000"))
}
