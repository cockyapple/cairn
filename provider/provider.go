// Package provider adapts four kinds of model endpoint to one call. It holds no
// policy: the gatekeeper and the review council decide what a model may do,
// this package only moves text. Adapters are tested against local fakes; none
// of them has been run against a live service by the test suite.
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxResponse = 4 << 20
	maxErrBody  = 200
	// DefaultMaxTokens is used when a Request leaves MaxTokens at zero.
	DefaultMaxTokens = 1024
	ollamaNumCtx     = 16384
)

// Request is one single-turn completion.
type Request struct {
	System    string
	User      string
	MaxTokens int
}

// Provider returns the model's text for a request.
type Provider interface {
	Name() string
	Complete(ctx context.Context, r Request) (string, error)
}

// Config describes one endpoint. APIKey is sent only over https, or to a
// loopback address.
type Config struct {
	BaseURL string
	Model   string
	APIKey  string
	Client  *http.Client
}

var (
	ErrInsecureURL = errors.New("provider: refusing to send a credential over plain http to a non-loopback host")
	ErrEmpty       = errors.New("provider: the model returned no text")
)

type base struct {
	name string
	cfg  Config
	url  string
}

func newBase(name string, cfg Config, path string) (*base, error) {
	if cfg.Model == "" {
		return nil, fmt.Errorf("provider %s: model is required", name)
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("provider %s: bad base url", name)
	}
	if u.Scheme == "http" && cfg.APIKey != "" && !loopback(u.Hostname()) {
		return nil, ErrInsecureURL
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 120 * time.Second}
	}
	return &base{name: name, cfg: cfg, url: strings.TrimRight(cfg.BaseURL, "/") + path}, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (b *base) Name() string { return b.name + ":" + b.cfg.Model }

func maxTokens(r Request) int {
	if r.MaxTokens > 0 {
		return r.MaxTokens
	}
	return DefaultMaxTokens
}

// post sends body as JSON and decodes the reply into out. The credential header
// is set by the caller through hdr.
func (b *base) post(ctx context.Context, hdr map[string]string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := b.cfg.Client.Do(req)
	if err != nil {
		return fmt.Errorf("provider %s: request failed: %w", b.name, redactURL(err))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("provider %s: reading reply: %w", b.name, err)
	}
	if len(data) > maxResponse {
		return fmt.Errorf("provider %s: reply larger than %d bytes", b.name, maxResponse)
	}
	if resp.StatusCode/100 != 2 {
		msg := string(data)
		if len(msg) > maxErrBody {
			msg = msg[:maxErrBody]
		}
		return fmt.Errorf("provider %s: http %d: %s", b.name, resp.StatusCode, msg)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("provider %s: reply is not the expected json: %w", b.name, err)
	}
	return nil
}

// redactURL drops the URL from a transport error, which could carry a key
// placed in a query string by a caller.
func redactURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func nonEmpty(s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "", ErrEmpty
	}
	return s, nil
}

// ---- OpenAI-compatible (chat completions) ----

type openAI struct{ *base }

// NewOpenAI talks to any server that implements POST {base}/chat/completions.
func NewOpenAI(cfg Config) (Provider, error) {
	b, err := newBase("openai", cfg, "/chat/completions")
	if err != nil {
		return nil, err
	}
	return &openAI{b}, nil
}

func (p *openAI) Complete(ctx context.Context, r Request) (string, error) {
	msgs := []map[string]string{}
	if r.System != "" {
		msgs = append(msgs, map[string]string{"role": "system", "content": r.System})
	}
	msgs = append(msgs, map[string]string{"role": "user", "content": r.User})
	body := map[string]any{"model": p.cfg.Model, "messages": msgs, "max_completion_tokens": maxTokens(r)}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	hdr := map[string]string{}
	if p.cfg.APIKey != "" {
		hdr["Authorization"] = "Bearer " + p.cfg.APIKey
	}
	if err := p.post(ctx, hdr, body, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", ErrEmpty
	}
	return nonEmpty(out.Choices[0].Message.Content)
}

// ---- Anthropic ----

type anthropic struct{ *base }

// NewAnthropic talks to POST {base}/v1/messages.
func NewAnthropic(cfg Config) (Provider, error) {
	b, err := newBase("anthropic", cfg, "/v1/messages")
	if err != nil {
		return nil, err
	}
	return &anthropic{b}, nil
}

func (p *anthropic) Complete(ctx context.Context, r Request) (string, error) {
	body := map[string]any{
		"model":      p.cfg.Model,
		"max_tokens": maxTokens(r),
		"messages":   []map[string]string{{"role": "user", "content": r.User}},
	}
	if r.System != "" {
		body["system"] = r.System
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	hdr := map[string]string{"anthropic-version": "2023-06-01", "x-api-key": p.cfg.APIKey}
	if err := p.post(ctx, hdr, body, &out); err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, c := range out.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}
	return nonEmpty(sb.String())
}

// ---- Google (Gemini generateContent) ----

type google struct{ *base }

// NewGoogle talks to POST {base}/v1beta/models/{model}:generateContent.
func NewGoogle(cfg Config) (Provider, error) {
	b, err := newBase("google", cfg, "/v1beta/models/"+url.PathEscape(cfg.Model)+":generateContent")
	if err != nil {
		return nil, err
	}
	return &google{b}, nil
}

func (p *google) Complete(ctx context.Context, r Request) (string, error) {
	body := map[string]any{
		"contents":         []map[string]any{{"role": "user", "parts": []map[string]string{{"text": r.User}}}},
		"generationConfig": map[string]any{"maxOutputTokens": maxTokens(r)},
	}
	if r.System != "" {
		body["systemInstruction"] = map[string]any{"parts": []map[string]string{{"text": r.System}}}
	}
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text    string `json:"text"`
					Thought bool   `json:"thought"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := p.post(ctx, map[string]string{"x-goog-api-key": p.cfg.APIKey}, body, &out); err != nil {
		return "", err
	}
	if len(out.Candidates) == 0 {
		return "", ErrEmpty
	}
	var sb strings.Builder
	for _, part := range out.Candidates[0].Content.Parts {
		if !part.Thought {
			sb.WriteString(part.Text)
		}
	}
	return nonEmpty(sb.String())
}

// ---- Ollama ----

type ollama struct{ *base }

// NewOllama talks to POST {base}/api/chat. num_ctx is always set: Ollama's
// silent default truncates long prompts.
func NewOllama(cfg Config) (Provider, error) {
	b, err := newBase("ollama", cfg, "/api/chat")
	if err != nil {
		return nil, err
	}
	return &ollama{b}, nil
}

func (p *ollama) Complete(ctx context.Context, r Request) (string, error) {
	msgs := []map[string]string{}
	if r.System != "" {
		msgs = append(msgs, map[string]string{"role": "system", "content": r.System})
	}
	msgs = append(msgs, map[string]string{"role": "user", "content": r.User})
	body := map[string]any{
		"model": p.cfg.Model, "messages": msgs, "stream": false,
		"options": map[string]any{"num_ctx": ollamaNumCtx, "num_predict": maxTokens(r)},
	}
	var out struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	hdr := map[string]string{}
	if p.cfg.APIKey != "" {
		hdr["Authorization"] = "Bearer " + p.cfg.APIKey
	}
	if err := p.post(ctx, hdr, body, &out); err != nil {
		return "", err
	}
	return nonEmpty(out.Message.Content)
}
