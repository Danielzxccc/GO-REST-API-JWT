package main

import (
	"go-jwt/controllers"
	"go-jwt/initializers"
	"go-jwt/middleware"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVaribles()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()
	// testing
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	// auth routes
	r.GET("/users", middleware.RequireAuth, controllers.GetUsers)
	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.Login)
	r.DELETE("/logout", controllers.Logout)

	r.Run()
}
