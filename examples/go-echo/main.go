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
	trappsec "github.com/trappsec-dev/trappsec/packages/go/echo"
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

	app := trappsec.InstallSentry(e, "GoEchoApp", "Development")
	app.SetDefaultUnauthenticated(401, map[string]any{"error": "authentication required"}, "application/json")

	app.IdentifyUser(func(req any) *trappsec.AuthContext {
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

	app.OverrideSourceIP(func(req any) string {
		c, ok := req.(echo.Context)
		if !ok {
			return "0.0.0.0"
		}
		if ip := c.Request().Header.Get("x-real-ip"); ip != "" {
			return ip
		}
		return c.RealIP()
	})

	app.POST("/auth/register", func(c echo.Context) error {
		payload := new(registerPayload)
		_ = c.Bind(payload)
		return c.JSON(http.StatusOK, map[string]any{"status": "registered", "email": payload.Email})
	})

	app.GET("/api/v2/profile", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{"name": c.Request().Header.Get("x-user-id"), "is_admin": false})
	})

	app.POST("/api/v2/profile", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{"name": c.Request().Header.Get("x-user-id"), "status": "updated"})
	})

	app.GET("/api/v2/orders", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{
			"orders": []map[string]any{
				{"id": "ord-123", "item": "Laptop", "amount": 1200},
				{"id": "ord-124", "item": "Mouse", "amount": 45},
			},
		})
	})

	app.GET("/api/v2/orders/:id", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{
			"id":     c.Param("id"),
			"item":   "Laptop",
			"amount": 1200,
			"status": "shipped",
		})
	})

	app.GET("/api/v2/echo/query", func(c echo.Context) error {
		result := map[string]string{}
		for k, v := range c.QueryParams() {
			if len(v) > 0 {
				result[k] = v[0]
			}
		}
		return c.JSON(http.StatusOK, result)
	})

	app.POST("/api/v2/echo/body", func(c echo.Context) error {
		var body map[string]any
		if err := c.Bind(&body); err != nil || body == nil {
			return c.JSON(http.StatusOK, map[string]any{})
		}
		return c.JSON(http.StatusOK, body)
	})

	app.POST("/api/v2/echo/form", func(c echo.Context) error {
		result := map[string]string{}
		if err := c.Request().ParseForm(); err == nil {
			for k, v := range c.Request().PostForm {
				if len(v) > 0 {
					result[k] = v[0]
				}
			}
		}
		return c.JSON(http.StatusOK, result)
	})

	app.POST("/api/v2/echo/multipart", func(c echo.Context) error {
		result := map[string]string{}
		if err := c.Request().ParseMultipartForm(32 << 20); err == nil {
			if c.Request().MultipartForm != nil {
				for k, v := range c.Request().MultipartForm.Value {
					if len(v) > 0 {
						result[k] = v[0]
					}
				}
			}
		}
		return c.JSON(http.StatusOK, result)
	})

	frontendDir := filepath.Join("..", "lure-frontend")
	app.GET("/", func(c echo.Context) error {
		return c.File(filepath.Join(frontendDir, "index.html"))
	})
	app.GET("/*", func(c echo.Context) error {
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

	app.Trap("/deployment/config").Methods("GET").Intent("Reconnaissance").Respond(trappsec.ResponseConfig{
		Status: 200,
		Body:   map[string]any{"region": "us-east-1", "deployment_type": "production"},
	})

	app.Trap("/deployment/metrics").Methods("GET").Intent("Reconnaissance").Respond(trappsec.ResponseConfig{
		Status: 200,
		Body: func(_ any) any {
			return map[string]any{
				"cpu":    fmt.Sprintf("%d%%", rand.Intn(91)+5),
				"memory": fmt.Sprintf("%d%%", rand.Intn(71)+20),
			}
		},
	})

	app.Template("fake_deprecated_api_response", 410, map[string]any{
		"error": "Gone", "message": "API v1 has been deprecated",
	}, "application/json")

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

	addr := "127.0.0.1:" + *port
	log.Printf("Starting server on http://%s", addr)
	if err := app.Start(addr); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
