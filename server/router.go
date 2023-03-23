package server

import (
	"io"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/xFaraday/yara-storm/yaraLib"
)

type File struct {
	Name    string
	Size    int64
	ModTime string
}

type Rules struct {
	Name   string `json:"name"`
	Number int    `json:"number"`
}

type RuleSet struct {
	Rules []Rules `json:"rules"`
}

func GetYaraRulesLoaded() RuleSet {
	rules := yaraLib.GetRulesNames()

	ruleset := RuleSet{}
	for i, rule := range rules {
		ruleset.Rules = append(ruleset.Rules, Rules{Name: rule, Number: i})
		println(rule)
	}
	for _, rule := range ruleset.Rules {
		println(rule.Name)
	}
	return ruleset
}

func NewRouter() *gin.Engine {
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
		ruleset := GetYaraRulesLoaded()
		c.JSON(http.StatusOK, ruleset)
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
