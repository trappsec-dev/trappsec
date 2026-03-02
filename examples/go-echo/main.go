package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/labstack/echo/v4"
	trappsec "github.com/trappsec-dev/trappsec/packages/go"
)

type registerPayload struct {
	Email string `json:"email" form:"email"`
}

func main() {
	otelEnabled := flag.Bool("otel", false, "Enable OpenTelemetry integration")
	webhookURL := flag.String("webhook", "", "Enable webhook integration")
	port := flag.String("port", "8000", "HTTP listen port")
	flag.Parse()

	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		_ = c.String(http.StatusInternalServerError, err.Error())
	}

	ts := trappsec.NewSentry(e, "GoEchoApp", "Development")
	ts.SetDefaultUnauthenticated(401, map[string]any{"error": "authentication required"}, "application/json")

	ts.IdentifyUser(func(req any) *trappsec.AuthContext {
		c, ok := req.(echo.Context)
		if !ok {
			return nil
		}
		uid := c.Request().Header.Get("x-user-id")
		if uid == "" {
			return nil
		}
		role := c.Request().Header.Get("x-user-role")
		if role == "" {
			role = "user"
		}
		return &trappsec.AuthContext{User: uid, Role: role}
	})

	ts.OverrideSourceIP(func(req any) string {
		c, ok := req.(echo.Context)
		if !ok {
			return "0.0.0.0"
		}
		if ip := c.Request().Header.Get("x-real-ip"); ip != "" {
			return ip
		}
		return c.RealIP()
	})

	e.POST("/auth/register", func(c echo.Context) error {
		payload := new(registerPayload)
		_ = c.Bind(payload)
		return c.JSON(http.StatusOK, map[string]any{"status": "registered", "email": payload.Email})
	})

	e.GET("/api/v2/profile", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{"name": c.Request().Header.Get("x-user-id"), "is_admin": false})
	})

	e.POST("/api/v2/profile", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{"name": c.Request().Header.Get("x-user-id"), "status": "updated"})
	})

	e.GET("/api/v2/orders", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{
			"orders": []map[string]any{
				{"id": "ord-123", "item": "Laptop", "amount": 1200},
				{"id": "ord-124", "item": "Mouse", "amount": 45},
			},
		})
	})

	frontendDir := filepath.Join("..", "lure-frontend")
	e.GET("/", func(c echo.Context) error {
		return c.File(filepath.Join(frontendDir, "index.html"))
	})
	e.GET("/*", func(c echo.Context) error {
		path := c.Param("*")
		fullPath := "/" + path
		if strings.HasPrefix(fullPath, "/api/") || strings.HasPrefix(fullPath, "/auth/") || strings.HasPrefix(fullPath, "/deployment/") {
			return c.NoContent(http.StatusNotFound)
		}

		target := filepath.Join(frontendDir, filepath.Clean(path))
		if _, err := os.Stat(target); err != nil {
			return c.NoContent(http.StatusNotFound)
		}
		return c.File(target)
	})

	ts.Trap("/deployment/config").Methods("GET").Intent("Reconnaissance").Respond(trappsec.ResponseConfig{
		Status: 200,
		Body:   map[string]any{"region": "us-east-1", "deployment_type": "production"},
	})

	ts.Trap("/deployment/metrics").Methods("GET").Intent("Reconnaissance").Respond(trappsec.ResponseConfig{
		Status: 200,
		Body: func(_ any) any {
			return map[string]any{
				"cpu":    fmt.Sprintf("%d%%", rand.Intn(91)+5),
				"memory": fmt.Sprintf("%d%%", rand.Intn(71)+20),
			}
		},
	})

	ts.Template("fake_deprecated_api_response", 410, map[string]any{
		"error": "Gone", "message": "API v1 has been deprecated",
	}, "application/json")

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

	addr := "127.0.0.1:" + *port
	log.Printf("Starting server on http://%s", addr)
	if err := e.Start(addr); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
