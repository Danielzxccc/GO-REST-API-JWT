package main

import (
	"go-jwt/controllers"
	"go-jwt/initializers"
	"go-jwt/middleware"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVaribles()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()
	r.Use(cors.Default())
	// testing
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	// auth routes

	v1 := r.Group("/v1", middleware.RequireAuth)
	{
		v1.GET("/users", controllers.GetUsers)
		v1.GET("/users/:id", controllers.FindUser)
	}

	// r.GET("/users", middleware.RequireAuth, controllers.GetUsers)
	r.GET("/users/:id", controllers.FindUser)
	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.Login)
	r.DELETE("/logout", controllers.Logout)

	r.Run()
}
