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
	ts := trappsec.NewSentry(r, "GoGinApp", "Development")
	ts.SetDefaultUnauthenticated(401, gin.H{"error": "authentication required"}, "application/json")

	ts.IdentifyUser(func(req any) *trappsec.AuthContext {
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

	ts.OverrideSourceIP(func(req any) string {
		if c, ok := req.(*gin.Context); ok {
			if ip := c.GetHeader("x-real-ip"); ip != "" {
				return ip
			}
			return c.ClientIP()
		}
		return "0.0.0.0"
	})

	r.POST("/auth/register", func(c *gin.Context) {
		var payload registerPayload
		_ = c.ShouldBind(&payload)
		c.JSON(http.StatusOK, gin.H{"status": "registered", "email": payload.Email})
	})

	r.GET("/api/v2/profile", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"name": c.GetHeader("x-user-id"), "is_admin": false})
	})

	r.POST("/api/v2/profile", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"name": c.GetHeader("x-user-id"), "status": "updated"})
	})

	r.GET("/api/v2/orders", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"orders": []gin.H{
			{"id": "ord-123", "item": "Laptop", "amount": 1200},
			{"id": "ord-124", "item": "Mouse", "amount": 45},
		}})
	})

	frontendDir := filepath.Join("..", "lure-frontend")
	r.GET("/", func(c *gin.Context) {
		c.File(filepath.Join(frontendDir, "index.html"))
	})
	r.NoRoute(func(c *gin.Context) {
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

	ts.Trap("/deployment/config").Methods("GET").Intent("Reconnaissance").Respond(trappsec.ResponseConfig{
		Status: 200,
		Body:   gin.H{"region": "us-east-1", "deployment_type": "production"},
	})

	ts.Trap("/deployment/metrics").Methods("GET").Intent("Reconnaissance").Respond(trappsec.ResponseConfig{
		Status: 200,
		Body: func(_ any) any {
			return gin.H{
				"cpu":    fmt.Sprintf("%d%%", rand.Intn(91)+5),
				"memory": fmt.Sprintf("%d%%", rand.Intn(71)+20),
			}
		},
	})

	ts.Template("fake_deprecated_api_response", 410, gin.H{"error": "Gone", "message": "API v1 has been deprecated"}, "application/json")
	ts.Trap("/api/v1/orders").Methods("GET", "POST").Intent("Legacy API Probing").Respond(trappsec.ResponseConfig{Template: "fake_deprecated_api_response"})
	ts.Trap("/api/v1/profile").Methods("GET", "POST").Intent("Legacy API Probing").Respond(trappsec.ResponseConfig{Template: "fake_deprecated_api_response"})

	ts.Watch("/auth/register").Body("role", "user", "Privilege Escalation (role)").Body("credits", 0, "Credit Manipulation")
	ts.Watch("/api/v2/profile").Body("is_admin", trappsec.NoDefault, "Privilege Escalation")

	if *otelEnabled {
		ts.AddOTEL()
	}
	if *webhookURL != "" {
		ts.AddWebhook(*webhookURL, nil)
	}

	log.Println("Starting server on http://127.0.0.1:8000")
	if err := r.Run("127.0.0.1:8000"); err != nil {
		log.Fatal(err)
	}
}
