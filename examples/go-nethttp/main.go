package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	trappsec "github.com/trappsec-dev/trappsec/packages/go/nethttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func main() {
	otelFlag := flag.Bool("otel", false, "Enable OpenTelemetry integration")
	webhook := flag.String("webhook", "", "Enable webhook integration")
	flag.Parse()

	mux := http.NewServeMux()
	app := trappsec.InstallSentry(mux, "GoNetHTTPApp", "Development")

	if *otelFlag {
		setupOpenTelemetry()
		app.AddOTEL()
	}

	register := func(pattern string, handler http.HandlerFunc) {
		if *otelFlag {
			app.Handle(pattern, otelhttp.NewHandler(http.HandlerFunc(handler), pattern))
			return
		}
		app.HandleFunc(pattern, handler)
	}

	register("POST /auth/register", func(w http.ResponseWriter, r *http.Request) {

		email := ""
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "application/json") {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				if v, ok := body["email"].(string); ok {
					email = v
				}
			}
		} else {
			_ = r.ParseForm()
			email = r.FormValue("email")
		}

		writeJSON(w, http.StatusOK, map[string]any{"status": "registered", "email": email})
	})

	register("GET /api/v2/profile", func(w http.ResponseWriter, r *http.Request) {
		name := r.Header.Get("x-user-id")
		writeJSON(w, http.StatusOK, map[string]any{"name": name, "is_admin": false})
	})

	register("POST /api/v2/profile", func(w http.ResponseWriter, r *http.Request) {
		name := r.Header.Get("x-user-id")
		writeJSON(w, http.StatusOK, map[string]any{"name": name, "status": "updated"})
	})

	register("GET /api/v2/orders", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"orders": []map[string]any{
			{"id": "ord-123", "item": "Laptop", "amount": 1200},
			{"id": "ord-124", "item": "Mouse", "amount": 45},
		}})
	})

	register("GET /api/v2/orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "item": "Laptop", "amount": 1200, "status": "shipped"})
	})

	register("GET /api/v2/echo/query", func(w http.ResponseWriter, r *http.Request) {
		result := map[string]string{}
		for k, v := range r.URL.Query() {
			if len(v) > 0 {
				result[k] = v[0]
			}
		}
		writeJSON(w, http.StatusOK, result)
	})

	register("POST /api/v2/echo/body", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body == nil {
			writeJSON(w, http.StatusOK, map[string]any{})
			return
		}
		writeJSON(w, http.StatusOK, body)
	})

	register("POST /api/v2/echo/form", func(w http.ResponseWriter, r *http.Request) {
		result := map[string]string{}
		if err := r.ParseForm(); err == nil {
			for k, v := range r.PostForm {
				if len(v) > 0 {
					result[k] = v[0]
				}
			}
		}
		writeJSON(w, http.StatusOK, result)
	})

	register("POST /api/v2/echo/multipart", func(w http.ResponseWriter, r *http.Request) {
		result := map[string]string{}
		if err := r.ParseMultipartForm(32 << 20); err == nil {
			if r.MultipartForm != nil {
				for k, v := range r.MultipartForm.Value {
					if len(v) > 0 {
						result[k] = v[0]
					}
				}
			}
		}
		writeJSON(w, http.StatusOK, result)
	})

	frontendDir := filepath.Join("..", "lure-frontend")
	register("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/auth/") || strings.HasPrefix(r.URL.Path, "/deployment/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		cleanPath := filepath.Clean(strings.TrimPrefix(path, "/"))
		target := filepath.Join(frontendDir, cleanPath)
		f, err := os.Open(target)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		defer f.Close()
		if strings.HasSuffix(target, ".html") {
			w.Header().Set("Content-Type", "text/html")
		} else if strings.HasSuffix(target, ".css") {
			w.Header().Set("Content-Type", "text/css")
		} else if strings.HasSuffix(target, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		}
		_, _ = io.Copy(w, f)
	})

	app.DefaultUnauthenticatedResponse(trappsec.ResponseConfig{Status: 401, Body: map[string]any{"error": "authentication required"}})

	app.IdentifyUser(func(req any) *trappsec.AuthContext {
		r, ok := req.(*http.Request)
		if !ok || r == nil {
			return nil
		}
		uid := r.Header.Get("x-user-id")
		if uid == "" {
			return nil
		}
		role := r.Header.Get("x-user-role")
		if role == "" {
			role = "user"
		}
		return &trappsec.AuthContext{User: uid, Role: role}
	})

	app.OverrideSourceIP(func(req any) string {
		r, ok := req.(*http.Request)
		if !ok || r == nil {
			return "0.0.0.0"
		}
		ip := r.Header.Get("x-real-ip")
		if ip != "" {
			return ip
		}
		// RemoteAddr is "host:port"; record the host only.
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			return host
		}
		return r.RemoteAddr
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
	app.Watch("/api/v2/orders/{id}").Query("discount_code", trappsec.Default("NONE"), trappsec.Intent("Coupon Tampering"))
	app.Watch("/api/v2/echo/query").Query("honey_q", trappsec.Intent("Query Field Test")).Query("role_q", trappsec.Default("user"), trappsec.Intent("Query Default Test"))
	app.Watch("/api/v2/echo/body").Body("honey_b", trappsec.Intent("Body Field Test")).Body("role_b", trappsec.Default("user"), trappsec.Intent("Body Default Test"))
	app.Watch("/api/v2/echo/form").Body("honey_f", trappsec.Intent("Form Field Test"))
	app.Watch("/api/v2/echo/multipart").Body("honey_m", trappsec.Intent("Multipart Field Test"))

	if *webhook != "" {
		alertsOnly := false
		app.AddWebhook(*webhook, &trappsec.WebhookOptions{Secret: os.Getenv("TRAPPSEC_WEBHOOK_SECRET"), AlertsOnly: &alertsOnly})
	}
	if u := os.Getenv("TRAPPSEC_ALERTS_WEBHOOK"); u != "" { // second receiver with the default AlertsOnly
		app.AddWebhook(u, &trappsec.WebhookOptions{Secret: os.Getenv("TRAPPSEC_WEBHOOK_SECRET")})
	}

	flushOnShutdown(app)
	addr := "127.0.0.1:" + listenPort()
	log.Printf("Starting server on http://%s", addr)
	if err := app.ListenAndServe(addr); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
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

// flushOnShutdown flushes queued trappsec deliveries (webhook, Slack) when the
// process is asked to stop, so events still in flight are not lost.
func flushOnShutdown(app *trappsec.App) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = app.Close(ctx)
		os.Exit(0)
	}()
}
