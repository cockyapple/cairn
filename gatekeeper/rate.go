package gatekeeper

import (
	"fmt"
	"time"
)

const (
	CodeRateLimited   = "rate_limited"
	DefaultRateWindow = time.Minute
)

// admit applies the agent's request budget. Every request counts, whether or
// not policy would have allowed it. Once the budget for a window is spent, the
// first refusal in that window is logged like any other; later ones are counted
// and the count is logged as one more refusal when the next window opens, so a
// compromised agent cannot use refusals to flood the log. A counted-only
// refusal never ran anything, but it has no entry of its own; if the agent goes
// quiet before a new window opens, the count is not written. The caller holds
// a.mu.
func (g *Gatekeeper) admit(a *Agent) error {
	if a.RateLimit <= 0 {
		return nil
	}
	now := g.now()
	if now.Sub(a.winStart) >= a.window() || now.Before(a.winStart) {
		if a.unlogged > 0 {
			detail := fmt.Sprintf("%d further requests in the previous window were refused without individual entries", a.unlogged)
			if err, written := g.refuseRecorded(a, []byte(fmt.Sprintf("suppressed=%d", a.unlogged)), &Refusal{CodeRateLimited, detail}); !written {
				return err
			}
		}
		a.winStart, a.winCount, a.unlogged, a.limitLogged = now, 0, 0, false
	}
	if a.winCount < a.RateLimit {
		a.winCount++
		return nil
	}
	r := &Refusal{CodeRateLimited, fmt.Sprintf("the agent's budget of %d requests per %s is spent", a.RateLimit, a.window())}
	if a.limitLogged {
		a.unlogged++
		return r
	}
	err, written := g.refuseRecorded(a, nil, r)
	a.limitLogged = written
	return err
}

// refuseRecorded logs a rate_limited refusal and reports whether its intent
// reached the log. An intent whose completion the log then refused still counts:
// the completion is queued and flush writes it before the agent's next action,
// so trying again would put a second intent on the log.
func (g *Gatekeeper) refuseRecorded(a *Agent, args []byte, r *Refusal) (err error, written bool) {
	hadPending := a.pending != nil
	err = g.refuse(a, "rate_limited", args, r)
	return err, ErrCode(err) != "" || (!hadPending && a.pending != nil)
}

func (a *Agent) window() time.Duration {
	if a.RateWindow > 0 {
		return a.RateWindow
	}
	return DefaultRateWindow
}

func (g *Gatekeeper) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}
