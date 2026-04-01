package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	trappsec "github.com/trappsec-dev/trappsec/packages/go/gin"
)

type registerPayload struct {
	Email string `json:"email" form:"email"`
}

func main() {
	otelEnabled := flag.Bool("otel", false, "Enable OpenTelemetry integration")
	webhookURL := flag.String("webhook", "", "Enable webhook integration")
	flag.Parse()

	r := gin.New()
	r.Use(gin.Recovery())
	app := trappsec.InstallSentry(r, "GoGinApp", "Development")
	app.SetDefaultUnauthenticated(401, gin.H{"error": "authentication required"}, "application/json")

	app.IdentifyUser(func(req any) *trappsec.AuthContext {
		c, ok := req.(*gin.Context)
		if !ok {
			return nil
		}
		uid := c.GetHeader("x-user-id")
		if uid == "" {
			return nil
		}
		role := c.GetHeader("x-user-role")
		if role == "" {
			role = "user"
		}
		return &trappsec.AuthContext{User: uid, Role: role}
	})

	app.OverrideSourceIP(func(req any) string {
		if c, ok := req.(*gin.Context); ok {
			if ip := c.GetHeader("x-real-ip"); ip != "" {
				return ip
			}
			return c.ClientIP()
		}
		return "0.0.0.0"
	})

	app.POST("/auth/register", func(c *gin.Context) {
		var payload registerPayload
		_ = c.ShouldBind(&payload)
		c.JSON(http.StatusOK, gin.H{"status": "registered", "email": payload.Email})
	})

	app.GET("/api/v2/profile", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"name": c.GetHeader("x-user-id"), "is_admin": false})
	})

	app.POST("/api/v2/profile", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"name": c.GetHeader("x-user-id"), "status": "updated"})
	})

	app.GET("/api/v2/orders", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"orders": []gin.H{
			{"id": "ord-123", "item": "Laptop", "amount": 1200},
			{"id": "ord-124", "item": "Mouse", "amount": 45},
		}})
	})

	app.GET("/api/v2/orders/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "item": "Laptop", "amount": 1200, "status": "shipped"})
	})

	app.GET("/api/v2/echo/query", func(c *gin.Context) {
		result := map[string]string{}
		for k, v := range c.Request.URL.Query() {
			if len(v) > 0 {
				result[k] = v[0]
			}
		}
		c.JSON(http.StatusOK, result)
	})

	app.POST("/api/v2/echo/body", func(c *gin.Context) {
		var body map[string]any
		if err := c.ShouldBindJSON(&body); err != nil || body == nil {
			c.JSON(http.StatusOK, gin.H{})
			return
		}
		c.JSON(http.StatusOK, body)
	})

	app.POST("/api/v2/echo/form", func(c *gin.Context) {
		result := map[string]string{}
		if err := c.Request.ParseForm(); err == nil {
			for k, v := range c.Request.PostForm {
				if len(v) > 0 {
					result[k] = v[0]
				}
			}
		}
		c.JSON(http.StatusOK, result)
	})

	app.POST("/api/v2/echo/multipart", func(c *gin.Context) {
		result := map[string]string{}
		if err := c.Request.ParseMultipartForm(32 << 20); err == nil {
			if c.Request.MultipartForm != nil {
				for k, v := range c.Request.MultipartForm.Value {
					if len(v) > 0 {
						result[k] = v[0]
					}
				}
			}
		}
		c.JSON(http.StatusOK, result)
	})

	frontendDir := filepath.Join("..", "lure-frontend")
	app.GET("/", func(c *gin.Context) {
		c.File(filepath.Join(frontendDir, "index.html"))
	})
	app.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		if len(path) > 0 && path[0] == '/' {
			path = path[1:]
		}
		target := filepath.Join(frontendDir, filepath.Clean(path))
		if _, err := os.Stat(target); err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.File(target)
	})

	app.Trap("/deployment/config").Methods("GET").Intent("Reconnaissance").Respond(trappsec.ResponseConfig{
		Status: 200,
		Body:   gin.H{"region": "us-east-1", "deployment_type": "production"},
	})

	app.Trap("/deployment/metrics").Methods("GET").Intent("Reconnaissance").Respond(trappsec.ResponseConfig{
		Status: 200,
		Body: func(_ any) any {
			return gin.H{
				"cpu":    fmt.Sprintf("%d%%", rand.Intn(91)+5),
				"memory": fmt.Sprintf("%d%%", rand.Intn(71)+20),
			}
		},
	})

	app.Template("fake_deprecated_api_response", 410, gin.H{"error": "Gone", "message": "API v1 has been deprecated"}, "application/json")
	app.Trap("/api/v1/orders").Methods("GET", "POST").Intent("Legacy API Probing").Respond(trappsec.ResponseConfig{Template: "fake_deprecated_api_response"})
	app.Trap("/api/v1/profile").Methods("GET", "POST").Intent("Legacy API Probing").Respond(trappsec.ResponseConfig{Template: "fake_deprecated_api_response"})

	app.Watch("/auth/register").Body("role", "user", "Privilege Escalation (role)").Body("credits", 0, "Credit Manipulation")
	app.Watch("/api/v2/profile").Body("is_admin", trappsec.NoDefault, "Privilege Escalation")
	app.Watch("/api/v2/orders/:id").Query("discount_code", "NONE", "Coupon Tampering")
	app.Watch("/api/v2/echo/query").Query("honey_q", trappsec.NoDefault, "Query Field Test").Query("role_q", "user", "Query Default Test")
	app.Watch("/api/v2/echo/body").Body("honey_b", trappsec.NoDefault, "Body Field Test").Body("role_b", "user", "Body Default Test")
	app.Watch("/api/v2/echo/form").Body("honey_f", trappsec.NoDefault, "Form Field Test")
	app.Watch("/api/v2/echo/multipart").Body("honey_m", trappsec.NoDefault, "Multipart Field Test")

	if *otelEnabled {
		app.AddOTEL()
	}
	if *webhookURL != "" {
		app.AddWebhook(*webhookURL, nil)
	}

	log.Println("Starting server on http://127.0.0.1:8000")
	if err := app.Run("127.0.0.1:8000"); err != nil {
		log.Fatal(err)
	}
}
