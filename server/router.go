package server

import (
	"io"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

type File struct {
	Name    string
	Size    int64
	ModTime string
}

type User struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func NewRouter(apiToken string) *gin.Engine {
	// Disable Console Color, you don't need console color when writing the logs to file.
	gin.DisableConsoleColor()

	// Logging to a file.
	f, _ := os.Create("gin.log")
	gin.DefaultWriter = io.MultiWriter(f)

	router := gin.Default()

	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	router.GET("/", func(c *gin.Context) {
		yaraJson := User{Name: "test", Email: "testagain"}
		c.JSON(http.StatusOK, yaraJson)
	})

	router.MaxMultipartMemory = 8 << 20 // 8 MiB
	router.POST("/upload", func(c *gin.Context) {
		// Multipart form
		form, _ := c.MultipartForm()
		files := form.File["file[]"]

		for _, file := range files {
			if err := c.SaveUploadedFile(file, "/srv/yara-storm/storage"+file.Filename); err != nil {
				println(err)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"message": "Unable to save the file",
				})
				return
			}
		}
		c.HTML(http.StatusOK, "upload.tmpl", gin.H{})
	})

	return router
}
