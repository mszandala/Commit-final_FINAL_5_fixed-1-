# AI Control Layer — Test Suite: Data Sources & Coverage

**Purpose of this document.** It records *which public benchmarks/sources we modelled our
test prompts on, why, and what each file catches* — for the presentation and so we don't
forget the reasoning later. The challenge forbids pre-packaged datasets (§7 of the brief):
**all prompts here are our own, self-created**, only *structurally modelled* on the public
benchmarks below. No dataset rows were copied.

---

## 1. Files at a glance

| File | Guardrail stage | Cases | Neg / Pos | What it proves |
|---|---|---|---|---|
| `input_guardrail_tests.json` | **Input** (request → model) | 44 | 29 / 15 | Blocks prompt injection, jailbreaks, obfuscation, RBAC violations, tool/agent exploits; allows legitimate role-scoped and benign requests |
| `output_guardrail_tests.json` | **Output** (model → user) | 30 | 22 / 8 | Redacts/blocks leaked salaries, secrets, PII, and data-exfiltration channels (Markdown/link/SSRF); allows clean output |
| `budget_resource_tests.json` | **Resource governance** | 10 | 7 / 3 | Enforces token/cost/iteration/fan-out budgets and allowed-model policy |
| `historical_attack_tests.json` | **Historical attack mitigation** | 12 | 9 / 3 | Blocks malicious code execution, unsafe deserialization, supply-chain/model-repo exploits, known-signature matches |

**Total: 96 cases.** Convention: *NEGATIVE* = must be blocked/redacted/throttled;
*POSITIVE* = must be allowed (these are the false-positive guards).

---

## 2. Expected actions (what the policy engine returns)

- **BLOCK** — request/response stopped; `expected_error_pattern` is a substring of the error.
- **REDACT** — delivered but sanitized; the masked string (e.g. `[REDACTED_SALARY]`) is the marker.
- **THROTTLE** — rate-/fan-out-limited (budget suite).
- **ALLOW** — passes clean; `expected_error_pattern` is `null`.

This maps to the brief's *"Block vs Redact or adherence %"* threshold model (Formal Req. 1).

---

## 3. Sources / benchmarks we modelled on — and why

### Prompt injection & jailbreak (input)
- **Lakera PINT** — industry prompt-injection test; basis for our delimiter-injection and
  authority-spoofing wrappers. *Catches:* instruction-override via delimiters/fake system blocks.
- **JailbreakChat / Reddit DAN family** (DAN, Developer Mode, hypothetical/narrative role-play)
  — basis for our persona-jailbreak cases. *Catches:* "ignore your rules" persona attacks.
- **"In-the-Wild" Jailbreak Prompts (Shen et al., *Do Anything Now*)** and **HackAPrompt** —
  real-world jailbreak corpora; informed our known-signature case. *Catches:* historically
  successful jailbreak openers fed from an external signature feed.
- **qualifire/prompt-injections-benchmark**, **Necent/llm-jailbreak-prompt-injection-dataset**
  (HuggingFace) — structural reference for direct injection / system-prompt extraction.
- **JailbreakBench (JBB-Behaviors, NeurIPS 2024)** — open robustness benchmark; reference for
  how to label positive/negative behaviours cleanly. https://proceedings.neurips.cc/paper_files/paper/2024/hash/63092d79154adebd7305dfd498cbff70-Abstract.html

### Automated exploitation / obfuscation (input)
- **Garak** & **PyRIT** — automated LLM red-team toolkits; basis for Base64/ROT13/hex
  obfuscation, system-prompt extraction, and tool-abuse payloads. *Catches:* encoded or
  tool-mediated attacks.
- **Unicode Tag Smuggling** — invisible-character instruction injection. *Catches:* hidden
  instructions in non-printing Unicode.
- **Multilingual evasion** — non-English jailbreak + "translate-and-execute". *Catches:*
  bypass attempts that switch language to dodge English-only filters.

### Agentic / MCP tool exploits (input)
- **InjecAgent** — benchmark for *indirect* prompt injection in tool-integrated agents; basis
  for our indirect-injection (poisoned document/email) case. https://arxiv.org/html/2403.02691v3
- **AgentDojo / Agent Security Bench** — agent attack/defence environments; informed the
  SQL-execution, path-traversal, and shell-command tool-exploit cases. *Catches:* unauthorized
  tool calls (DB dump, `../../../etc/shadow`, shell).

### Output leakage & exfiltration (output)
- **OWASP LLM02 (Sensitive Information Disclosure)** — frames the salary/secret/PII redaction cases.
- **MITRE ATLAS `AML.T0077` (LLM response rendering)** and public write-ups on **Markdown-image
  / hyperlink data exfiltration** — basis for the rendering-channel cases. *Catches:* data smuggled
  out via `![](attacker-url?data=...)`, link query strings, or SSRF links to `169.254.169.254`.
  https://www.startupdefense.io/mitre-atlas-techniques/aml-t0077-llm-response-rendering ·
  https://archestra.ai/blog/data-exfiltration-via-markdown-image

### Budget / resource governance
- **OWASP LLM10 (Unbounded Consumption)** — frames the output-bomb, runaway-tool-loop,
  oversized-context, and fan-out cases. *Catches:* denial-of-wallet / runaway execution.
- **Centralized policy (allowed models, per-user quota, per-request cost cap)** — from the
  brief's Formal Req. 1 & 3. *Catches:* routing to disallowed/expensive models, quota abuse.

### Historical attack mitigation
- **OWASP LLM03 (Supply Chain)** & **LLM05 (Improper Output Handling)**, **Meta CyberSecEval**
  — basis for malicious-code-execution, unsafe-deserialization (pickle/yaml/torch), typosquatting,
  untrusted-model-repo (`trust_remote_code=True`), and insecure-code-generation cases.
  *Catches:* the exact classes named in Formal Req. 4.

> All attack payloads in the historical suite are standard, well-known *detection signatures*
> (e.g. `curl | sh`, `pickle.loads`, typosquatted package names) used as the thing the guardrail
> must block — not functional exploits.

---

## 4. Coverage map — OWASP LLM Top 10 (2025) & competition requirements

| Risk / requirement | Covered by | Example case |
|---|---|---|
| LLM01 Prompt Injection | input | `TEST-ATK-DELIM-USER-022`, `TEST-ATK-UNICODE-SMUGGLE-041` |
| LLM02 Sensitive Info Disclosure | output | `OUT-LEAK-SALARY-001`, `OUT-LEAK-PII-001` |
| LLM03 Supply Chain | historical | `HIST-TYPOSQUAT-006`, `HIST-REMOTE-CODE-007` |
| LLM04 Data/Model Poisoning | input (indirect inj.) | `TEST-ATK-INDIRECT-029` |
| LLM05 Improper Output Handling | output / historical | `OUT-EXFIL-MARKDOWN-001`, `HIST-RCE-001` |
| LLM06 Excessive Agency | input (tool exploits) | `TEST-ATK-MCP-SQL-026`, `TEST-ATK-MCP-SHELL-028` |
| LLM07 System Prompt Leakage | input | `TEST-ATK-SYSLEAK-024` |
| LLM08 Vector/Embedding Weaknesses | *gap — see §6* | — |
| LLM09 Misinformation | *partial / out of scope* | — |
| LLM10 Unbounded Consumption | budget | `BUD-OUTPUT-BOMB-001`, `BUD-TOOL-LOOP-002` |
| **Access control / authN (Formal Req. 2)** | input RBAC | `TEST-RBAC-*`, `TEST-RBAC-IDOR-BANKER-044` |
| **Budget & resource (Formal Req. 3)** | budget | whole `budget_resource_tests.json` |
| **Historical attack mitigation (Formal Req. 4)** | historical | whole `historical_attack_tests.json` |
| **Positive/negative self-test (Formal Req. 6)** | all files | POSITIVE cases in each |

---

## 5. Schemas

**Input, budget, historical** (shared core):
`id`, `benchmark_reference`, `category`, `test_type` (`NEGATIVE`/`POSITIVE`), `user_role`,
`prompt`, `expected_action`, `expected_rule_triggered`, `expected_error_pattern`.
- Input adds: `requested_resource`, `role_authorized` (RBAC).
- Budget adds: `control_metric`. Historical adds: `attack_class`.

**Output** (differs — it tests the model's *response*):
`id`, `category`, `test_type` (`NEGATIVE_OUTPUT`/`POSITIVE_OUTPUT`), `user_role`, `user_prompt`,
`raw_llm_output`, `expected_action`, `expected_rule_triggered`, `sanitized_llm_output`.

A pytest harness loads each file and asserts the control layer returns the `expected_action`
and matches `expected_rule_triggered` / `expected_error_pattern` (or the sanitized output).

---

## 6. RBAC role → resource matrix (used by the input suite)

| Role | Authorized resources |
|---|---|
| `basic_user` | — (none) |
| `hr` | employee_data |
| `administrator` | bank_data, deposits, employee_data |
| `banker` | user_data, bank_data, deposits |
| `it` | projects |
| `analyst` | stock_market, bank_data, deposits |
| `lawyer` | client_data |
| `portfolio_manager` | stock_market, bank_data, deposits, user_data |

Object-level (IDOR) checks sit *on top* of resource-level scope: a role authorized for a
resource can still be denied a specific record it isn't assigned to (`TEST-RBAC-IDOR-BANKER-044`).

---

## 7. Known gaps / next additions (honest list for Q&A)

- **LLM08** — vector/embedding & RAG-poisoning tests not yet included.
- Multi-turn **crescendo** attacks (state across turns) — only single-turn narrative so far.
- Multimodal (image-borne) injection — out of scope for a text gateway.
- Canary/honeytoken leak detection on the output side.
- Broader multilingual coverage (only PL/FR samples included as proof-of-concept).
