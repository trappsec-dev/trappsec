package trappsec

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type EventHandler interface {
	Emit(event TriggerContext) error
}

type LogHandler struct {
	logger *log.Logger
}

func (h *LogHandler) Emit(event TriggerContext) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	h.logger.Println(string(data))
	return nil
}

type WebhookOptions struct {
	Secret            string
	Headers           map[string]string
	HeartbeatInterval int
	Template          func(TriggerContext) any
	Service           string
	Environment       string
}

type WebhookHandler struct {
	url         string
	secret      string
	headers     map[string]string
	template    func(TriggerContext) any
	service     string
	environment string
	client      *http.Client
}

func NewWebhookHandler(url string, opts *WebhookOptions) (*WebhookHandler, error) {
	if url == "" {
		return nil, fmt.Errorf("webhook url is required")
	}
	if opts == nil {
		opts = &WebhookOptions{}
	}

	h := &WebhookHandler{
		url:         url,
		secret:      opts.Secret,
		headers:     map[string]string{"Content-Type": "application/json"},
		template:    opts.Template,
		service:     opts.Service,
		environment: opts.Environment,
		client:      &http.Client{Timeout: 5 * time.Second},
	}
	for k, v := range opts.Headers {
		h.headers[k] = v
	}

	if opts.HeartbeatInterval > 0 {
		go h.heartbeatLoop(opts.HeartbeatInterval)
	}

	return h, nil
}

func (h *WebhookHandler) Emit(event TriggerContext) error {
	payload := any(event)
	if h.template != nil {
		payload = h.template(event)
	}
	return h.send(payload)
}

func (h *WebhookHandler) heartbeatLoop(interval int) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		_ = h.send(map[string]any{
			"timestamp":   float64(time.Now().UnixNano()) / 1e9,
			"event":       "trappsec.heartbeat",
			"service":     h.service,
			"environment": h.environment,
		})
	}
}

func (h *WebhookHandler) send(payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, h.url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	if h.secret != "" {
		mac := hmac.New(sha256.New, []byte(h.secret))
		mac.Write(data)
		req.Header.Set("x-trappsec-signature", hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

type OTELHandler struct{}

func (h *OTELHandler) Emit(_ TriggerContext) error {
	// OTEL enrichment in Go requires request context propagation through trigger events.
	// This placeholder keeps API compatibility; integration can pass context-aware events in a follow-up.
	return nil
}
