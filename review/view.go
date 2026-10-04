package review

import (
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/cockyapple/cairn/eval"
	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
)

// Render writes a single static HTML page of the log's proposals: what each
// changes, the eval deltas, who voted how, and what the rules say about it.
// The log is verified first; if it does not verify, the page says so and shows
// nothing else. Every value from the log is untrusted text and is escaped by
// html/template; the page carries no script and a CSP that forbids it.
// sc is optional; when given it is verified against the log.
func Render(w io.Writer, entries []ledger.Entry, blobs governance.Blobs, opt governance.Options, sc *ledger.SignedCheckpoint) error {
	pg := page{Entries: len(entries)}
	st, err := governance.Replay(entries, blobs, opt)
	if err != nil {
		pg.Failure = fmt.Sprintf("%s: %v", governance.ErrCode(err), err)
		return pageTmpl.Execute(w, pg)
	}
	pg.Verified = true
	pg.Frozen = st.Frozen
	pg.Epoch = st.Trust().Epoch
	pg.OpenIntents = len(st.OpenIntents)
	switch {
	case sc == nil:
		pg.Checkpoint = "none supplied: the page shows what the log says, not that anyone signed it"
	default:
		trust, ok := st.TrustForSize(sc.Size)
		if !ok {
			pg.Checkpoint = "does not match this log"
		} else if err := ledger.VerifyLog(entries[:min(int(sc.Size), len(entries))], sc, &trust); err != nil {
			pg.Checkpoint = "failed: " + ledger.ErrCode(err)
		} else {
			pg.Checkpoint = fmt.Sprintf("valid for the first %d entries (quorum and witnesses met)", sc.Size)
			pg.CheckpointOK = true
		}
	}
	for i := len(st.Proposals) - 1; i >= 0; i-- {
		pg.Proposals = append(pg.Proposals, card(st, blobs, st.Proposals[i]))
	}
	return pageTmpl.Execute(w, pg)
}

type page struct {
	Entries      int
	Verified     bool
	Failure      string
	Frozen       bool
	Epoch        uint64
	OpenIntents  int
	Checkpoint   string
	CheckpointOK bool
	Proposals    []cardData
}

type voteRow struct {
	Key, Role, Verdict, Class, Comment string
}

type evalRow struct {
	Name                       string
	Baseline, Candidate, Delta string
	Class                      string
}

type diffRow struct{ Mark, Class, Text string }

type cardData struct {
	Hash, Target, Tier, Status, Class, Proposer, Time string
	Need                                              string
	Delay                                             string
	Effective                                         string
	Rationale                                         string
	Votes                                             []voteRow
	HasEval                                           bool
	EvalSuite, EvalMeans                              string
	Eval                                              []evalRow
	DiffNote                                          string
	Diff                                              []diffRow
	Problem                                           string
	Truncated                                         string
}

func short(b []byte) string { return hex.EncodeToString(b[:6]) }

func bp(n int) string { return fmt.Sprintf("%d.%02d", n/100, abs(n%100)) }

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func ts(t uint64) string {
	return time.Unix(int64(t), 0).UTC().Format("2006-01-02 15:04:05") + " UTC (as claimed by the entry)"
}

func dur(sec uint64) string {
	if sec == 0 {
		return "none"
	}
	if sec%86400 == 0 {
		return fmt.Sprintf("%d days", sec/86400)
	}
	return fmt.Sprintf("%d hours", sec/3600)
}

func card(st *governance.State, blobs governance.Blobs, p governance.ProposalInfo) cardData {
	total, sec := governance.Required(p.Proposal.Tier)
	c := cardData{
		Hash: hex.EncodeToString(p.Hash[:]), Target: p.Proposal.Target,
		Tier: fmt.Sprintf("T%d", p.Proposal.Tier), Status: string(p.Status), Class: string(p.Status),
		Proposer: short(p.Author[:]), Time: ts(p.Time),
		Need:  fmt.Sprintf("%d approvals, %d from a security reviewer", total, sec),
		Delay: dur(governance.MinDelay(p.Proposal.Tier)),
	}
	if p.Status == governance.StatusActivated {
		c.Effective = ts(p.EffectiveAfter)
	}
	for _, v := range p.Votes {
		r := voteRow{Key: short(v.Author[:]), Role: roleName(v.Role)}
		switch v.Verdict {
		case ledger.VerdictApprove:
			r.Verdict, r.Class = "approve", "ok"
		case ledger.VerdictReject:
			r.Verdict, r.Class = "reject", "bad"
		default:
			r.Verdict, r.Class = "escalate", "bad"
		}
		if b, ok := blobs.Get(v.CommentHash); ok && ledger.BlobHash(b) == v.CommentHash {
			r.Comment = clip(string(b), 600)
		} else {
			r.Comment = "(comment not available)"
		}
		c.Votes = append(c.Votes, r)
	}
	m, err := Gather(st, blobs, p.Hash)
	if err != nil {
		c.Problem = "cannot show this proposal: " + err.Error()
		return c
	}
	c.Rationale = clip(string(m.Rationale), 4000)
	if m.Eval != nil {
		c.HasEval = true
		c.EvalSuite = m.Eval.Suite
		s := m.Eval.Summary()
		c.EvalMeans = fmt.Sprintf("mean %s -> %s (%s), %d of %d cases regressed", bp(s.BaselineMean), bp(s.CandidateMean), signed(s.Delta), len(s.Regressions), len(m.Eval.Cases))
		for _, cs := range m.Eval.Cases {
			c.Eval = append(c.Eval, evalRowOf(cs))
		}
		if m.EvalProblem != "" {
			c.Problem = "Do not trust the eval table: " + m.EvalProblem + "."
		}
	}
	if m.HasPrevious {
		c.DiffNote = "Change against the artifact in force before this proposal:"
	} else {
		c.DiffNote = "No earlier artifact for this target; the full proposed content:"
	}
	const maxRows = 2000
	d, err := Diff(m.Previous, m.Artifact)
	lines := len(d)
	if err != nil {
		c.DiffNote = "Too large to diff against the earlier version, so no changes are marked. The full proposed content follows:"
		lines = lineCount(m.Artifact)
		d = d[:0]
		for _, ln := range firstLines(m.Artifact, maxRows+1) {
			d = append(d, DiffLine{Op: Same, Text: ln})
		}
	}
	for i, l := range d {
		if i == maxRows {
			c.Diff = append(c.Diff, diffRow{"", "same", fmt.Sprintf("... %d more lines not shown", lines-maxRows)})
			c.Truncated = fmt.Sprintf("This view is incomplete: %d lines are not shown. Do not approve what you have not read; use the bundle for the rest.", lines-maxRows)
			break
		}
		row := diffRow{Mark: " ", Class: "same", Text: l.Text}
		switch l.Op {
		case Add:
			row.Mark, row.Class = "+", "add"
		case Del:
			row.Mark, row.Class = "-", "del"
		}
		c.Diff = append(c.Diff, row)
	}
	return c
}

func evalRowOf(cs eval.CaseScore) evalRow {
	d := cs.Candidate - cs.Baseline
	r := evalRow{Name: cs.Name, Baseline: bp(cs.Baseline), Candidate: bp(cs.Candidate), Delta: signed(d)}
	switch {
	case d < 0:
		r.Class = "bad"
	case d > 0:
		r.Class = "ok"
	}
	return r
}

func signed(n int) string {
	if n < 0 {
		return "-" + bp(-n)
	}
	return "+" + bp(n)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + " ..."
}

func roleName(r ledger.Role) string {
	switch r {
	case ledger.RoleReviewer:
		return "reviewer"
	case ledger.RoleSecurityReviewer:
		return "security reviewer"
	case ledger.RoleValidator:
		return "validator"
	case ledger.RoleWitness:
		return "witness"
	case ledger.RoleProposer:
		return "proposer"
	case ledger.RoleAgent:
		return "agent"
	}
	return "unknown"
}

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cairn review</title>
<style>
:root{--bg:#f5f6f4;--fg:#1c2220;--mut:#5a6561;--line:#d5dad7;--card:#fff;--ok:#1d6b4b;--okbg:#e2f2ea;--bad:#a02c2c;--badbg:#f8e3e3;--warn:#8a5a00;--warnbg:#f8eed6;--addbg:#e4f3e8;--delbg:#f9e4e4}
@media (prefers-color-scheme:dark){:root{--bg:#141817;--fg:#e6ebe8;--mut:#98a5a0;--line:#2c3532;--card:#1b211f;--ok:#6fd0a2;--okbg:#17342a;--bad:#f09090;--badbg:#3a1d1d;--warn:#e6bf6a;--warnbg:#38301a;--addbg:#16301f;--delbg:#3a1f1f}}
*{box-sizing:border-box}
body{margin:0;padding:1.5rem 1rem 4rem;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:60rem;margin:0 auto;display:flex;flex-direction:column;gap:1.25rem}
h1{font-size:1.4rem;margin:0}h2{font-size:1.05rem;margin:0}h3{font-size:.8rem;margin:1rem 0 .4rem;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
.mono,code,pre,td.k{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.bar{display:flex;flex-wrap:wrap;gap:.5rem 1.5rem;color:var(--mut);font-size:.9rem}
.pill{display:inline-block;padding:.05rem .55rem;border-radius:99px;font-size:.78rem;font-weight:600}
.open,.warn{background:var(--warnbg);color:var(--warn)}.activated,.ok{background:var(--okbg);color:var(--ok)}.rejected,.bad{background:var(--badbg);color:var(--bad)}.void{background:var(--line);color:var(--mut)}
.notice{border:1px solid var(--line);border-left-width:4px;padding:.7rem 1rem;background:var(--card)}
.notice.fail{border-left-color:var(--bad)}.notice.good{border-left-color:var(--ok)}
article{background:var(--card);border:1px solid var(--line);padding:1rem 1.1rem}
article header{display:flex;flex-wrap:wrap;gap:.4rem .8rem;align-items:baseline}
.sub{color:var(--mut);font-size:.85rem;overflow-wrap:anywhere}
table{border-collapse:collapse;width:100%;font-size:.88rem}th,td{text-align:left;padding:.25rem .6rem .25rem 0;vertical-align:top;border-bottom:1px solid var(--line)}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.tw{overflow-x:auto}
pre.diff{margin:0;font-size:.82rem;line-height:1.45;overflow-x:auto;border:1px solid var(--line)}
pre.diff span{display:block;padding:0 .6rem;white-space:pre-wrap;overflow-wrap:anywhere}
span.add{background:var(--addbg)}span.del{background:var(--delbg)}
p.rat{white-space:pre-wrap;margin:.2rem 0}
</style></head><body><main>
<h1>Cairn review</h1>
{{if .Verified}}
<div class="notice good"><strong>The log verifies.</strong> {{.Entries}} entries: the hash chain, every signature and every governance rule replayed from the start.</div>
<div class="bar"><span>Trust epoch {{.Epoch}}</span><span>{{if .Frozen}}<span class="pill bad">activations frozen</span>{{else}}not frozen{{end}}</span><span>{{.OpenIntents}} agent actions started but not finished</span></div>
<div class="notice {{if .CheckpointOK}}good{{end}}">Checkpoint: {{.Checkpoint}}</div>
{{range .Proposals}}
<article>
<header><h2>{{.Target}}</h2><span class="pill {{.Class}}">{{.Status}}</span><span class="pill void">{{.Tier}}</span></header>
<div class="sub mono">proposal {{.Hash}}</div>
<div class="sub">proposed by key {{.Proposer}} at {{.Time}}</div>
<div class="sub">needs {{.Need}}; delay before it takes effect: {{.Delay}}{{if .Effective}}; effective after {{.Effective}}{{end}}</div>
{{if .Problem}}<div class="notice fail" style="margin-top:.7rem">{{.Problem}}</div>{{end}}
{{if .Truncated}}<div class="notice fail" style="margin-top:.7rem">{{.Truncated}}</div>{{end}}
<h3>Rationale</h3><p class="rat">{{.Rationale}}</p>
<h3>Votes</h3>
{{if .Votes}}<div class="tw"><table><tr><th>Key</th><th>Role</th><th>Verdict</th><th>Comment</th></tr>
{{range .Votes}}<tr><td class="k">{{.Key}}</td><td>{{.Role}}</td><td><span class="pill {{.Class}}">{{.Verdict}}</span></td><td style="white-space:pre-wrap;overflow-wrap:anywhere">{{.Comment}}</td></tr>{{end}}</table></div>{{else}}<p class="sub">No votes yet.</p>{{end}}
{{if .HasEval}}<h3>Eval: {{.EvalSuite}}</h3><p class="sub">Scores are out of 100.00. {{.EvalMeans}}. The log records which result reviewers saw; it does not prove the eval was run honestly.</p>
<div class="tw"><table><tr><th>Case</th><th class="n">Before</th><th class="n">After</th><th class="n">Change</th></tr>
{{range .Eval}}<tr><td>{{.Name}}</td><td class="n">{{.Baseline}}</td><td class="n">{{.Candidate}}</td><td class="n"><span class="pill {{.Class}}">{{.Delta}}</span></td></tr>{{end}}</table></div>{{else}}<h3>Eval</h3><p class="sub">No eval result attached.</p>{{end}}
<h3>Change</h3><p class="sub">{{.DiffNote}}</p>
{{if .Diff}}<pre class="diff">{{range .Diff}}<span class="{{.Class}}">{{.Mark}} {{.Text}}</span>{{end}}</pre>{{end}}
</article>
{{else}}<p class="sub">The log holds no proposals.</p>{{end}}
{{else}}
<div class="notice fail"><strong>This log does not verify.</strong> {{.Failure}}<br>Nothing from it is shown, because none of it can be trusted.</div>
{{end}}
</main></body></html>
`))
