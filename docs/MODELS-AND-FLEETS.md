# Any model, many agents

> **Status: design.** This document describes the intended design. What is built today is
> listed in the README status table; most of what follows (capability grants, delegation,
> fleet budgets, model scoring, the injection benchmark) is not implemented.

Two requirements: Cairn must work with **any LLM, cloud or local**, and must run
**many agents at once** without giving up protection. Both follow from one rule
that is already in the constitution: the model is an untrusted component.

## 1. Any LLM, cloud or local

Because no guarantee depends on the model behaving well, no guarantee depends on
which model it is. Swapping models changes quality and cost, not the security
boundary.

### Provider adapter

A model is reached only through an adapter with a deliberately tiny contract:

    complete(request) -> response

- `request`: a list of typed messages (system, task, data, tool_results), a tool
  schema list, and limits (max tokens, timeout).
- `response`: text and/or structured tool-call proposals, plus usage counts.
- The adapter holds **no credentials the model can see**. API keys live in the
  gatekeeper process, never in model context.
- The adapter cannot execute tools. It returns proposals; the gatekeeper decides.

Planned adapters: OpenAI-compatible HTTP (covers OpenAI, Azure, vLLM, LM Studio,
llama.cpp server, LiteLLM, many others), Anthropic, Google, and Ollama. A local
model on a GPU and a hosted frontier model look identical to the rest of Cairn.
Tool-call proposals from models without native tool calling are parsed from
constrained output (JSON schema), and anything that fails validation is dropped.

### Model identity is on the ledger

- The model in use (provider, model id, version or digest, quantization for local
  weights) is part of the agent's configuration. **Changing it is a T2 proposal**
  and is reviewed, delayed and logged like any other change.
- Each ACTION entry's args or result blob records the model id that produced it,
  so an audit can tell which model did what.

### Model trust classes

Models differ in how easily they are fooled. Small local models are often weaker
against injection. Cairn does not guess; it measures.

- Every (model, configuration) pair is scored on the injection corpus and the
  benign-utility suite (INJECTION-DEFENSE.md, "What we measure").
- A grant can state a **minimum eval score** for the model allowed to use it. A
  model with no score on record gets the minimum grant: read-only, no egress, no
  spend.
- So a cheap local model can triage and summarise freely, while anything that
  moves value demands a model that passed the gate, *plus* the gatekeeper and a
  human approval. Local-only operation is fully supported; it just earns
  authority through measurement like everything else.

### Privacy

A grant can require `local_only`: the gatekeeper then refuses to route that
agent's content to any cloud adapter. A sanitiser step (like citadel-crew's) can
be required before any cloud call.

## 2. Many agents at once, still protected

### One agent, one identity

Every agent instance has its own Ed25519 key, its own role (`agent`), its own
capability grant, its own budget, its own ACTION chain (`prev_action_hash`), and
its own sandbox. Compromising one agent yields that agent's grant and nothing
else.

### Isolation

- Process or container per agent, no shared filesystem by default, no ambient
  credentials, default-deny egress per agent.
- No shared mutable memory. Anything one agent wants another to see goes through
  the **message bus**.

### Message bus

Agents talk only through typed records the gatekeeper validates and logs, never
free text spliced into another agent's prompt. A message carries: sender key,
recipient, a schema id, a schema-validated body, and a hash. Free-form text
fields are bounded and delivered to the recipient as **data**, not instruction
(constitution I8). This closes the "one agent poisons the next" path.

### Delegation only ever narrows

An agent may create a sub-agent or hand off a task only by issuing a delegation
that is a **strict subset** of its own grant (tools, hosts, budget, time). It can
never grant more than it has (constitution I11). The delegation is an ACTION on
the ledger, so the full tree of who spawned whom is auditable.

### Fleet-level limits

Per-agent caps are not enough when many agents can each stay under their own cap.

- **Fleet budget**: a global ceiling on spend, calls and egress across all agents,
  enforced by the gatekeeper.
- **Concurrency cap**: a maximum number of live agents, and a maximum spawn rate.
- **Fleet anomaly rules**: correlated behaviour across agents (many agents hitting
  a new host, a burst of denied attempts, the same canary seen twice) raises a
  FREEZE for the whole fleet, not just one agent.
- **Kill switch**: any security reviewer can freeze activations; the gatekeeper
  can additionally suspend an agent instantly (it revokes the grant, it does not
  need a vote to get safer, per I4).

### Ordering and concurrency

Agents append ACTIONs concurrently; the sequencer (Stage A) or BFT (Stage B)
gives them one total order. Each agent's own chain lets an auditor replay that
agent in isolation. Write contention is handled by batching into the log, not by
locking agents against each other.

### The lethal-trifecta rule at fleet scale

The split from INJECTION-DEFENSE.md applies across agents: readers (untrusted
input, no tools), actors (tools, no untrusted raw text), and the gatekeeper
between them. A fleet is many readers and actors wired through the bus, never
one agent holding private data, untrusted input and an exit.

## 3. What is new in the plan

| Phase | Addition |
|-------|----------|
| 0 | This design, invariants I11 and I12, ADRs 10 and 11 (done) |
| 1 | Formats: capability grant and delegation, with the replay enforcing I11 at delegation time and each action against its grant (built, SPEC 10.3.2 and 10.3.3); model-identity record and agent-suspend (not started) |
| 2 | Gatekeeper with provider adapters (OpenAI-compatible, Anthropic, Google, Ollama), per-agent sandbox, message bus |
| 3 | Fleet budgets, concurrency and spawn limits, fleet anomaly freeze |
| 5 | Per-model injection scoring, model trust classes, multi-agent adversarial tests (agent-to-agent injection, collusion, budget splitting) |

## 4. Honest limits

- Model scores are snapshots; models and attacks change. Scores expire and are
  re-run on every model or prompt change.
- A fleet of individually harmless agents can still cause harm together (budget
  splitting, coordinated low-and-slow abuse). Fleet limits and fleet anomaly rules
  reduce this; they do not eliminate it.
- Local models give privacy and zero egress, not safety. Their authority is earned
  the same way as any other model's.
