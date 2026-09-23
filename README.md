# SENTINEL — Adaptive Safety for Autonomous AI Agents

**IndabaX Tunisia 2026 · SENTINEL Challenge**

A defense layer that sits between a tool-using LLM agent and every action it attempts, deciding **allow /
block / escalate / rewrite** based on an action's provenance, the agent's declared policy, and the content it
observed — never from a scenario identifier or an expected outcome.

**40 / 40 published scenarios pass** — all three domains, all five difficulty levels.

---

## 📹 Video demonstration
**[Watch here](https://drive.google.com/file/d/1HYiHmgNuPGfFgdV6bK0M4DwGi0btPs_o/view?usp=sharing)**

## 📄 Technical report
Full report (method, ablation studies, failure analysis, responsible-AI statement):
[`SENTINEL_Technical_Report.pdf`](./SENTINEL_Technical_Report.pdf) · 

## 📝 Design log
The complete, real-time engineering journal — every bug found, every fix, every version (v1 → v4):
[`design-log.md`](./design-log.md)

---

## What it does

The defense reasons about two properties of every piece of content the agent observes:

- **Trust level** — how much to believe an instruction implied by this content
- **Sensitivity level** — whether this content is allowed to be reproduced elsewhere at all, *independent of
  trust*

Five layers process every candidate action:

| Layer | Function |
|---|---|
| **Sensitivity guard** | Detects restricted/confidential content about to be copied into an outbound action, and **rewrites** the action to redact it — not a blunt block |
| **Encoding-aware detector** | Catches the same secrets disguised as reversed, hex, base64, or spaced-out text |
| **Hard policy constraints** | Deterministic allow/block rules independent of content — is this tool permitted, and is a consequential action actually confirmed? |
| **Content risk scorer** | Authority-spoofing and format-mimicry detection, with a **read/write asymmetry**: reads referenced only by untrusted content are flagged and allowed; writes/sends with the same property are blocked |
| **Decision aggregator** | Combines everything above into one verdict, tagging risk honestly using session history |

See [`SENTINEL_Technical_Report.pdf`](./SENTINEL_Technical_Report.pdf) for the full architecture diagram and a
detailed account of how each layer came to exist — most were built in direct response to a real scenario failure,
documented as they happened.

## Results

| Domain | Scenarios | Result |
|---|---|---|
| Finance | 7 / 7 | Clean |
| Enterprise | 15 / 15 | Clean |
| SOC | 18 / 18 | Clean |
| **Total** | **40 / 40** | **Clean** |

Three real ablation studies (not synthetic) are documented in the technical report, each with a genuine
before/after result on real scenario data — including a 21-scenario failure (0/21) closed by a single general
fix (21/21) rather than per-scenario patching.

## Project structure

```
Sentinel_Starter_Kit/
├── starter-kits/python-defense/
│   ├── app/decision.py          # the defense — all 5 layers
│   └── tests/test_app.py        # 18 unit tests, including regression tests for real bugs we found
├── scenarios/public/            # the 40 published scenarios (organizer-provided)
├── design-log.md                # full development journal
├── SENTINEL_Technical_Report.pdf
├── SENTINEL_Technical_Report.tex
└── README.md
```

## Running it locally

```powershell
# Terminal 1 — start the defense
cd starter-kits/python-defense
python -m uvicorn app.main:app --port 8080

# Terminal 2 — run any scenario against it
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml --defense-url http://127.0.0.1:8080
```

Full setup instructions are in the starter kit's own `README.md`.

## Honest limitations

We do not claim complete security. Documented openly in the technical report:

- Content-pattern checks (regex-based) can be bypassed by natural-language phrasing that avoids literal tool
  names — found by our own adversarial testing before submission, not by a third party
- The encoding-aware detector is validated by our own hand-authored tests; no published scenario yet exercises
  obfuscated exfiltration
- The defense reacts to whichever tools a scenario's policy grants the agent; it does not redesign the agent's
  base permission set

---

*Built for IndabaX Tunisia 2026 — SENTINEL: Adaptive Safety for Autonomous AI Agents.*
