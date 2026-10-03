package gatekeeper_test

import (
	"context"
	"strings"
	"testing"

	"github.com/cockyapple/cairn/gatekeeper"
)

func TestHandlerCannotRewriteWhatTheLogCommitsTo(t *testing.T) {
	e, g := setup(t)
	g.Handle("refund", func(_ context.Context, args []byte) ([]byte, error) {
		copy(args, "XXXXXXXXXX")
		return []byte("done"), nil
	})
	if _, err := g.Do(context.Background(), "actor", "refund", []byte("order 4471")); err != nil {
		t.Fatalf("a handler that scribbles on its input broke the completion: %v", err)
	}
	st := e.replays(t)
	if len(st.OpenIntents) != 0 || st.Completed != 1 {
		t.Fatalf("open=%d completed=%d", len(st.OpenIntents), st.Completed)
	}
}

func TestOneKeyIsOneAgent(t *testing.T) {
	e, g := setup(t)
	err := g.AddAgent(&gatekeeper.Agent{Name: "twin", Key: e.actor, Allow: []string{"refund"}})
	if err == nil || !strings.Contains(err.Error(), "one key must mean one agent") {
		t.Fatalf("a second agent on the same key must be refused: %v", err)
	}
}

func TestFullMailboxIsALoggedRefusal(t *testing.T) {
	e, g := setup(t)
	if err := g.DeclareMessage(&gatekeeper.MessageType{
		Name: "order", From: []string{"reader"}, To: []string{"actor"},
		Validate: gatekeeper.Strict(gatekeeper.Field{Name: "order", Pattern: `[0-9]{1,8}`}),
	}); err != nil {
		t.Fatal(err)
	}
	gatekeeper.FillMailbox(g, "actor", gatekeeper.MaxMailbox)
	err := g.Send(context.Background(), "reader", "actor", "order", []byte(`{"order":"1"}`))
	if gatekeeper.ErrCode(err) != gatekeeper.CodeMailboxFull {
		t.Fatalf("want mailbox_full as a refusal, got %v", err)
	}
	if got := e.lastResult(t); !strings.HasPrefix(got, "refused\nmailbox_full\n") {
		t.Fatalf("the log should record a refusal, not a generic error: %q", got)
	}
}

func TestHandlerRefusalIsRecordedAsARefusal(t *testing.T) {
	e, g := setup(t)
	g.Handle("refund", func(context.Context, []byte) ([]byte, error) {
		return nil, &gatekeeper.Refusal{Code: "custom_code", Detail: "no"}
	})
	_, err := g.Do(context.Background(), "actor", "refund", []byte("x"))
	if gatekeeper.ErrCode(err) != "custom_code" {
		t.Fatalf("%v", err)
	}
	if got := e.lastResult(t); got != "refused\ncustom_code\nno" {
		t.Fatalf("%q", got)
	}
}
