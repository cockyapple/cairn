package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestDefaultClientDoesNotFollowARedirectWithTheKey(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "" || r.Header.Get("x-goog-api-key") != "" || r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer other.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/x", http.StatusTemporaryRedirect)
	}))
	defer first.Close()
	for name, mk := range map[string]func(Config) (Provider, error){
		"openai":    func(c Config) (Provider, error) { return NewOpenAI(c) },
		"anthropic": func(c Config) (Provider, error) { return NewAnthropic(c) },
		"google":    func(c Config) (Provider, error) { return NewGoogle(c) },
	} {
		p, err := mk(Config{BaseURL: first.URL, Model: "m", APIKey: "secret"})
		if err != nil {
			t.Fatal(name, err)
		}
		if _, err := p.Complete(context.Background(), Request{System: "s", User: "u"}); err == nil {
			t.Errorf("%s: a redirect was treated as an answer", name)
		}
	}
	if leaked.Load() {
		t.Fatal("the API key reached the redirect target")
	}
}
