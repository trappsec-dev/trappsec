package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	echootel "github.com/labstack/echo-otel/v5"
	"github.com/labstack/echo/v5"
	trappsec "github.com/trappsec-dev/trappsec/packages/go/echo"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type registerPayload struct {
	Email string `json:"email" form:"email"`
}

func main() {
	otelEnabled := flag.Bool("otel", false, "Enable OpenTelemetry integration")
	webhookURL := flag.String("webhook", "", "Enable webhook integration")
	port := flag.String("port", listenPort(), "HTTP listen port")
	flag.Parse()

	e := echo.New()
	// Use the socket address for c.RealIP(); echo's default trusts X-Forwarded-For.
	// Behind a proxy you control, use echo.ExtractIPFromXFFHeader(echo.TrustIPRange(...)).
	e.IPExtractor = echo.ExtractIPDirect()
	e.HTTPErrorHandler = func(c *echo.Context, err error) {
		_ = c.String(http.StatusInternalServerError, err.Error())
	}

	app := trappsec.InstallSentry(e, "GoEchoApp", "Development")
	app.DefaultUnauthenticatedResponse(trappsec.ResponseConfig{Status: 401, Body: map[string]any{"error": "authentication required"}})

	if *otelEnabled {
		setupOpenTelemetry()
		app.Use(echootel.NewMiddleware("GoEchoApp"))
		app.AddOTEL()
	}

	app.IdentifyUser(func(req any) *trappsec.AuthContext {
		c, ok := req.(*echo.Context)
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
		c, ok := req.(*echo.Context)
		if !ok {
			return "0.0.0.0"
		}
		if ip := c.Request().Header.Get("x-real-ip"); ip != "" {
			return ip
		}
		return c.RealIP()
	})

	app.POST("/auth/register", func(c *echo.Context) error {
		payload := new(registerPayload)
		_ = c.Bind(payload)
		return c.JSON(http.StatusOK, map[string]any{"status": "registered", "email": payload.Email})
	})

	app.GET("/api/v2/profile", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{"name": c.Request().Header.Get("x-user-id"), "is_admin": false})
	})

	app.POST("/api/v2/profile", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{"name": c.Request().Header.Get("x-user-id"), "status": "updated"})
	})

	app.GET("/api/v2/orders", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{
			"orders": []map[string]any{
				{"id": "ord-123", "item": "Laptop", "amount": 1200},
				{"id": "ord-124", "item": "Mouse", "amount": 45},
			},
		})
	})

	app.GET("/api/v2/orders/:id", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{
			"id":     c.Param("id"),
			"item":   "Laptop",
			"amount": 1200,
			"status": "shipped",
		})
	})

	app.GET("/api/v2/echo/query", func(c *echo.Context) error {
		result := map[string]string{}
		for k, v := range c.QueryParams() {
			if len(v) > 0 {
				result[k] = v[0]
			}
		}
		return c.JSON(http.StatusOK, result)
	})

	app.POST("/api/v2/echo/body", func(c *echo.Context) error {
		var body map[string]any
		if err := c.Bind(&body); err != nil || body == nil {
			return c.JSON(http.StatusOK, map[string]any{})
		}
		return c.JSON(http.StatusOK, body)
	})

	app.POST("/api/v2/echo/form", func(c *echo.Context) error {
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

	app.POST("/api/v2/echo/multipart", func(c *echo.Context) error {
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

	frontend := os.DirFS(filepath.Join("..", "lure-frontend"))
	app.GET("/", func(c *echo.Context) error {
		serveFrontend(c.Response(), c.Request(), frontend, "/")
		return nil
	})
	app.GET("/*", func(c *echo.Context) error {
		fullPath := "/" + c.Param("*")
		if strings.HasPrefix(fullPath, "/api/") || strings.HasPrefix(fullPath, "/auth/") || strings.HasPrefix(fullPath, "/deployment/") {
			return c.NoContent(http.StatusNotFound)
		}
		serveFrontend(c.Response(), c.Request(), frontend, fullPath)
		return nil
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

	app.Watch("/auth/register").Body("role", trappsec.Default("user"), trappsec.Intent("Privilege Escalation (role)")).Body("credits", trappsec.Default(0), trappsec.Intent("Credit Manipulation"))
	app.Watch("/api/v2/profile").Body("is_admin", trappsec.Intent("Privilege Escalation"))
	app.Watch("/api/v2/orders/:id").Query("discount_code", trappsec.Default("NONE"), trappsec.Intent("Coupon Tampering"))
	app.Watch("/api/v2/echo/query").Query("honey_q", trappsec.Intent("Query Field Test")).Query("role_q", trappsec.Default("user"), trappsec.Intent("Query Default Test"))
	app.Watch("/api/v2/echo/body").Body("honey_b", trappsec.Intent("Body Field Test")).Body("role_b", trappsec.Default("user"), trappsec.Intent("Body Default Test"))
	app.Watch("/api/v2/echo/form").Body("honey_f", trappsec.Intent("Form Field Test"))
	app.Watch("/api/v2/echo/multipart").Body("honey_m", trappsec.Intent("Multipart Field Test"))

	if *webhookURL != "" {
		alertsOnly := false
		app.AddWebhook(*webhookURL, &trappsec.WebhookOptions{Secret: os.Getenv("TRAPPSEC_WEBHOOK_SECRET"), AlertsOnly: &alertsOnly})
	}
	if u := os.Getenv("TRAPPSEC_ALERTS_WEBHOOK"); u != "" { // second receiver with the default AlertsOnly
		app.AddWebhook(u, &trappsec.WebhookOptions{Secret: os.Getenv("TRAPPSEC_WEBHOOK_SECRET")})
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	addr := "127.0.0.1:" + *port
	log.Printf("Starting server on http://%s", addr)
	sc := echo.StartConfig{Address: addr, HideBanner: true}
	if err := sc.Start(ctx, app); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	flush(app)
}

func setupOpenTelemetry() {
	exporter, err := stdouttrace.New()
	if err != nil {
		log.Fatalf("failed to initialize OTEL stdout exporter: %v", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
}

// listenPort is $PORT, or 8000.
func listenPort() string {
	if p := os.Getenv("PORT"); p != "" {
		return p
	}
	return "8000"
}

// flush flushes queued trappsec deliveries (webhook, Slack) after the server
// stops, so events still in flight are not lost.
func flush(app *trappsec.App) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = app.Close(ctx)
}

// serveFrontend serves the lure frontend file named by urlPath, or answers
// 404. os.DirFS refuses names that leave the directory ("..", absolute
// paths), so a crafted path cannot read files elsewhere on the machine.
func serveFrontend(w http.ResponseWriter, r *http.Request, frontend fs.FS, urlPath string) {
	name := strings.TrimPrefix(path.Clean("/"+urlPath), "/")
	if name == "" {
		name = "index.html"
	}
	if st, err := fs.Stat(frontend, name); err != nil || st.IsDir() {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	http.ServeFileFS(w, r, frontend, name)
}
