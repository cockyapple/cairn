package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serve(t *testing.T, reply string, check func(*http.Request, map[string]any)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if check != nil {
			check(r, m)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply))
	}))
}

func TestOpenAI(t *testing.T) {
	s := serve(t, `{"choices":[{"message":{"content":"hello"}}]}`, func(r *http.Request, m map[string]any) {
		if r.URL.Path != "/chat/completions" || r.Header.Get("Authorization") != "Bearer k1" {
			t.Errorf("bad request %s %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		if m["model"] != "m" || len(m["messages"].([]any)) != 2 {
			t.Errorf("bad body %v", m)
		}
	})
	defer s.Close()
	p, err := NewOpenAI(Config{BaseURL: s.URL, Model: "m", APIKey: "k1"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Complete(context.Background(), Request{System: "s", User: "u"})
	if err != nil || got != "hello" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestAnthropic(t *testing.T) {
	s := serve(t, `{"content":[{"type":"thinking","text":"x"},{"type":"text","text":"a"},{"type":"text","text":"b"}]}`, func(r *http.Request, m map[string]any) {
		if r.URL.Path != "/v1/messages" || r.Header.Get("x-api-key") != "k2" || r.Header.Get("anthropic-version") == "" {
			t.Errorf("bad request")
		}
		if _, has := m["temperature"]; has {
			t.Errorf("temperature must be omitted")
		}
		if m["system"] != "sys" {
			t.Errorf("system missing")
		}
	})
	defer s.Close()
	p, _ := NewAnthropic(Config{BaseURL: s.URL, Model: "m", APIKey: "k2"})
	got, err := p.Complete(context.Background(), Request{System: "sys", User: "u"})
	if err != nil || got != "ab" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestGoogleSkipsThoughts(t *testing.T) {
	s := serve(t, `{"candidates":[{"content":{"parts":[{"text":"hidden","thought":true},{"text":"visible"}]}}]}`, func(r *http.Request, m map[string]any) {
		if r.URL.Path != "/v1beta/models/gemini-x:generateContent" || r.Header.Get("x-goog-api-key") != "k3" {
			t.Errorf("bad request %s", r.URL.Path)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("the key must not travel in the query string")
		}
	})
	defer s.Close()
	p, _ := NewGoogle(Config{BaseURL: s.URL, Model: "gemini-x", APIKey: "k3"})
	got, err := p.Complete(context.Background(), Request{User: "u"})
	if err != nil || got != "visible" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestOllamaSetsNumCtx(t *testing.T) {
	s := serve(t, `{"message":{"content":"ok"}}`, func(r *http.Request, m map[string]any) {
		o := m["options"].(map[string]any)
		if o["num_ctx"].(float64) < 8192 || m["stream"] != false {
			t.Errorf("num_ctx/stream not set: %v", m)
		}
	})
	defer s.Close()
	p, _ := NewOllama(Config{BaseURL: s.URL, Model: "llama"})
	if got, err := p.Complete(context.Background(), Request{User: "u"}); err != nil || got != "ok" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestFailures(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, strings.Repeat("x", 1000), 500)
	}))
	defer bad.Close()
	p, _ := NewOpenAI(Config{BaseURL: bad.URL, Model: "m", APIKey: "SECRET-KEY"})
	_, err := p.Complete(context.Background(), Request{User: "u"})
	if err == nil || len(err.Error()) > 400 || strings.Contains(err.Error(), "SECRET-KEY") {
		t.Fatalf("error should be short and key-free: %v", err)
	}

	empty := serve(t, `{"choices":[]}`, nil)
	defer empty.Close()
	p, _ = NewOpenAI(Config{BaseURL: empty.URL, Model: "m"})
	if _, err := p.Complete(context.Background(), Request{User: "u"}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("want ErrEmpty, got %v", err)
	}

	junk := serve(t, `not json`, nil)
	defer junk.Close()
	p, _ = NewAnthropic(Config{BaseURL: junk.URL, Model: "m"})
	if _, err := p.Complete(context.Background(), Request{User: "u"}); err == nil {
		t.Fatal("non-json reply must fail")
	}
}

func TestRefusesCredentialOverPlainHTTP(t *testing.T) {
	if _, err := NewOpenAI(Config{BaseURL: "http://models.example.com", Model: "m", APIKey: "k"}); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("want ErrInsecureURL, got %v", err)
	}
	if _, err := NewOpenAI(Config{BaseURL: "http://models.example.com", Model: "m"}); err != nil {
		t.Fatalf("keyless http is the caller's choice: %v", err)
	}
	if _, err := NewOllama(Config{BaseURL: "http://localhost:11434", Model: "m", APIKey: "k"}); err != nil {
		t.Fatalf("loopback is allowed: %v", err)
	}
	if _, err := NewOpenAI(Config{BaseURL: "ftp://x", Model: "m"}); err == nil {
		t.Fatal("bad scheme must fail")
	}
	if _, err := NewOpenAI(Config{BaseURL: "https://x"}); err == nil {
		t.Fatal("missing model must fail")
	}
}

func TestContextCancel(t *testing.T) {
	s := serve(t, `{}`, nil)
	defer s.Close()
	p, _ := NewOllama(Config{BaseURL: s.URL, Model: "m"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Complete(ctx, Request{User: "u"}); err == nil {
		t.Fatal("cancelled context must fail")
	}
}
