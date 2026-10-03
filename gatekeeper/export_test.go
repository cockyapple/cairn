package gatekeeper

// FillMailbox puts n placeholder messages in an agent's mailbox.
func FillMailbox(g *Gatekeeper, agent string, n int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := 0; i < n; i++ {
		g.boxes[agent] = append(g.boxes[agent], Message{Type: "filler"})
	}
}

// MaxMailbox reports the mailbox cap.
const MaxMailbox = maxMailbox
