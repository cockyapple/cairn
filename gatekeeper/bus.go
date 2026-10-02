package gatekeeper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
)

const maxMailbox = 1024

// MessageType declares one kind of message agents may exchange: who may send
// it, who may receive it, and what its body must look like. Anything not
// declared cannot be sent.
type MessageType struct {
	Name     string
	From, To []string // agent names
	Validate func(body []byte) error
}

type Message struct {
	Type string
	From string
	Body []byte
}

func (g *Gatekeeper) DeclareMessage(t *MessageType) error {
	if t.Name == "" || t.Validate == nil {
		return errors.New("gatekeeper: a message type needs a name and a validator")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.types[t.Name] = t
	return nil
}

// Send delivers a typed message from one agent to another. The body is checked
// before delivery, the exchange is logged as the sender's action
// "bus.send:<type>", and a message that fails any check is refused and never
// reaches the mailbox.
func (g *Gatekeeper) Send(ctx context.Context, from, to, typ string, body []byte) error {
	a, err := g.agent(from)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := g.admit(a); err != nil {
		return err
	}
	action := "bus.send:" + typ
	args := append([]byte(to+"\n"), body...)
	if len(args) > a.MaxArgs {
		return g.refuse(a, action, nil, &Refusal{CodeArgsTooLarge, "message exceeds the sender's size limit"})
	}
	g.mu.Lock()
	t := g.types[typ]
	_, toKnown := g.agents[to]
	g.mu.Unlock()
	switch {
	case t == nil:
		return g.refuse(a, action, args, &Refusal{CodeUnknownMessage, "no such message type is declared"})
	case !a.allowed[action] || !slices.Contains(t.From, from) || !slices.Contains(t.To, to) || !toKnown:
		return g.refuse(a, action, args, &Refusal{CodeRouteDenied, "this sender may not send this type to this recipient"})
	}
	if err := t.Validate(body); err != nil {
		return g.refuse(a, action, args, &Refusal{CodeMessageInvalid, err.Error()})
	}
	deliver := func(ctx context.Context, _ []byte) ([]byte, error) {
		g.mu.Lock()
		defer g.mu.Unlock()
		if len(g.boxes[to]) >= maxMailbox {
			return nil, errors.New(CodeMailboxFull)
		}
		g.boxes[to] = append(g.boxes[to], Message{Type: typ, From: from, Body: slices.Clone(body)})
		return nil, nil
	}
	_, err = g.do(ctx, a, action, args, deliver)
	return err
}

// Receive returns and clears an agent's mailbox.
func (g *Gatekeeper) Receive(agent string) []Message {
	g.mu.Lock()
	defer g.mu.Unlock()
	m := g.boxes[agent]
	delete(g.boxes, agent)
	return m
}

// Field constrains one string field of a message body.
type Field struct {
	Name    string
	Enum    []string // when set, the value must be one of these
	Pattern string   // when set, the value must match this whole-string pattern
	MaxLen  int      // zero means 256
}

// Strict builds a validator for a flat JSON object whose every field is a
// string: all declared fields present, no others, each within its constraints.
// It narrows what one agent can hand to another; it does not make the content
// true. A compromised sender can still send a well-formed message that lies.
func Strict(fields ...Field) func([]byte) error {
	res := make([]*regexp.Regexp, len(fields))
	for i, f := range fields {
		if f.Pattern != "" {
			res[i] = regexp.MustCompile(`\A(?:` + f.Pattern + `)\z`)
		}
	}
	return func(body []byte) error {
		m, err := flatObject(body)
		if err != nil {
			return err
		}
		if len(m) != len(fields) {
			return errors.New("body has missing or unexpected fields")
		}
		for i, f := range fields {
			raw, ok := m[f.Name]
			if !ok {
				return fmt.Errorf("field %q is missing", f.Name)
			}
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf("field %q is not a string", f.Name)
			}
			limit := f.MaxLen
			if limit == 0 {
				limit = 256
			}
			switch {
			case len(s) > limit:
				return fmt.Errorf("field %q is too long", f.Name)
			case f.Enum != nil && !slices.Contains(f.Enum, s):
				return fmt.Errorf("field %q is not an allowed value", f.Name)
			case res[i] != nil && !res[i].MatchString(s):
				return fmt.Errorf("field %q does not match its pattern", f.Name)
			}
		}
		return nil
	}
}

// flatObject reads one JSON object, refusing duplicate keys and trailing data:
// two parsers could otherwise disagree about which duplicate wins.
func flatObject(body []byte) (map[string]json.RawMessage, error) {
	bad := errors.New("body is not a single json object without duplicate keys")
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, bad
	}
	m := map[string]json.RawMessage{}
	for dec.More() {
		k, err := dec.Token()
		ks, ok := k.(string)
		if err != nil || !ok {
			return nil, bad
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, bad
		}
		if _, dup := m[ks]; dup {
			return nil, bad
		}
		m[ks] = v
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, bad
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, bad
	}
	return m, nil
}
