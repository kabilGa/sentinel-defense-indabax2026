"""SENTINEL defense — Step 1.

Layers, matching our architecture diagram:
  1. provenance resolver   -> resolve_trust()
  2. hard policy constraints -> check_hard_policy()
  3. content risk scorer (minimal v1: authority-spoof + format-mimicry regex checks)
                            -> check_content_risk()
  4. decision aggregator   -> decide() combines the above into one verdict

Known gaps (tracked in docs/design-log.md, to become v2/v3):
  - No exfiltration/encoded-secret screening on 'respond' content yet.
  - No learned/LLM-supervisor risk scoring yet — pure rules for now.
  - Session-level taint (history_digest.least_trusted_seen) is read but not
    yet used to tighten thresholds across steps (planned adaptive-attack work).
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from collections import Counter

from app.models import CandidateAction, DefenseDecision, DefenseRequest

UNTRUSTED = {"untrusted_internal", "untrusted_external", "adversary_controlled"}

# --- content risk scorer (v1: cheap regex signals, no ML/LLM yet) ----------

AUTHORITY_SPOOF_PATTERNS = [
    r"\bsystem\s*[:#]",
    r"\[?\s*admin(istrator)?\s*(override)?\s*\]?\s*:",
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"new\s+instructions?\s+from\s+(the\s+)?(admin|system|officer|manager)",
    r"you\s+are\s+now\s+authorized",
]

FORMAT_MIMICRY_PATTERNS = [
    r"\bthought\s*:",
    r"\baction\s*:",
    r"\bobservation\s*:",
]


def _matches_any(patterns: list[str], text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


# --- provenance resolver -----------------------------------------------------

def resolve_trust(request: DefenseRequest) -> dict[str, str]:
    """Map provenance id -> trust level. Memory inherits trust: a memory_write's own
    provenance record already carries whatever trust level it was created with, so
    reading it here (rather than treating memory as automatically trusted) is what
    makes memory-poisoning fail — we never re-derive trust from 'it's in memory now'."""
    return {record.id: record.provenance.trust_level for record in request.provenance}


def untrusted_conversation_texts(request: DefenseRequest, trust: dict[str, str]) -> list[str]:
    return [
        item.content
        for item in request.conversation
        if any(trust.get(pid) in UNTRUSTED for pid in item.provenance_ids)
    ]


def trusted_texts(request: DefenseRequest, trust: dict[str, str]) -> list[str]:
    """The user's own goal plus any conversation item sourced from a trusted
    provenance. Used to tell 'this value is a legitimate shared fact' apart from
    'this value only exists because the attacker put it there' (see design-log
    Entry 4 — the poisoned-invoice over-blocking failure)."""
    texts = [request.user_goal]
    texts += [
        item.content
        for item in request.conversation
        if not item.provenance_ids or any(trust.get(pid) not in UNTRUSTED for pid in item.provenance_ids)
    ]
    return texts


# --- hard policy constraints --------------------------------------------------

def action_digest(action: CandidateAction) -> str:
    """Same digest the evaluator uses for confirmations."""

    def canonical(value: object) -> object:
        if isinstance(value, str):
            return " ".join(value.split())
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return value

    payload: dict[str, object] = {
        "type": action.type,
        "tool": action.tool,
        "arguments": {k: canonical(v) for k, v in sorted(action.arguments.items())},
        "content": action.content if action.type != "tool_call" else None,
    }
    if action.confirmation_for is not None:
        payload["confirmation_for"] = action_digest(action.confirmation_for)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]


STATUS_CONSEQUENTIAL = {"ticket_update": {"closed", "resolved"}, "incident_update": {"closed"}}


def check_hard_policy(request: DefenseRequest, action: CandidateAction) -> DefenseDecision | None:
    """Deterministic, non-negotiable rules. Returns a Decision to short-circuit, or
    None to let the content risk scorer have a look."""
    if action.tool is not None and action.tool not in request.policy_context.get("allowed_tools", []):
        return DefenseDecision(
            decision="block", risk_score=0.9, confidence=0.85, reason_codes=["TOOL_NOT_REQUIRED_FOR_GOAL"]
        )

    # A tool can be consequential two ways: it's always sensitive (explicit list), or
    # THIS call's arguments make it sensitive (e.g. incident_update is fine normally,
    # but closing an incident via status='closed' is consequential). Missing this
    # second check was a real regression we shipped in v1 -- see design-log Entry 5:
    # it let a hostile log line close an incident with zero human confirmation.
    status = action.arguments.get("status")
    consequential = action.tool in request.policy_context.get("consequential_tools", []) or (
        isinstance(status, str) and status in STATUS_CONSEQUENTIAL.get(action.tool, set())
    )
    if consequential:
        confirmed = action_digest(action) in request.history_digest.confirmations_granted
        if not confirmed:
            return DefenseDecision(
                decision="escalate", risk_score=0.6, confidence=0.7, reason_codes=["MISSING_CONFIRMATION"]
            )
    return None


# --- content risk scorer (v1) -------------------------------------------------

READ_LIKE_SUFFIXES = ("_read", "_search", "_lookup", "_correlate")


def is_read_like(tool: str) -> bool:
    """Reads only bring content INTO context; they don't send/execute/confirm
    anything. The real damage in these attacks always happens at a send/execute
    step, not a read step (see design-log Entry 12 -- enterprise_memory_poison's
    DOC-3104 was a genuinely needed document, only ever mentioned via poisoned
    memory by coincidence, not a fake one). So an untrusted-exclusive reference
    is treated as a flag, not an automatic block, for reads -- writes/sends stay
    strictly gated."""
    return tool.endswith(READ_LIKE_SUFFIXES)


def check_content_risk(request: DefenseRequest, action: CandidateAction) -> DefenseDecision | None:
    trust = resolve_trust(request)
    untrusted_texts = untrusted_conversation_texts(request, trust)

    for text in untrusted_texts:
        if _matches_any(AUTHORITY_SPOOF_PATTERNS, text):
            return DefenseDecision(
                decision="block",
                risk_score=0.95,
                confidence=0.75,
                reason_codes=["AUTHORITY_SPOOF_IN_CONTENT"],
                explanation="Untrusted content claims elevated authority it does not have.",
            )
        if _matches_any(FORMAT_MIMICRY_PATTERNS, text):
            return DefenseDecision(
                decision="escalate",
                risk_score=0.7,
                confidence=0.6,
                reason_codes=["FORMAT_MIMICRY_SUSPECTED"],
                explanation="Untrusted content mimics agent-internal reasoning syntax.",
            )

    # Original v0 signal, refined: does untrusted content directly reference this
    # exact tool + an argument value that is EXCLUSIVE to untrusted content (not
    # also present in something trusted)? Values shared with trusted content are
    # legitimate facts (e.g. an invoice number both parties already know), not
    # injected instructions -- see design-log Entry 4.
    if action.tool is not None:
        trusted_blob = " ".join(t.lower() for t in trusted_texts(request, trust))
        values = [str(v).lower() for v in action.arguments.values() if v is not None and len(str(v)) >= 4]
        for text in untrusted_texts:
            lowered = text.lower()
            if action.tool not in lowered:
                continue
            exclusive_matches = [v for v in values if v in lowered and v not in trusted_blob]
            if exclusive_matches:
                if is_read_like(action.tool):
                    return DefenseDecision(
                        decision="allow",
                        risk_score=0.5,
                        confidence=0.55,
                        reason_codes=["UNTRUSTED_REFERENCED_READ"],
                        explanation="Only referenced via untrusted content, but reading carries low harm on "
                        "its own; any send/execute that follows stays strictly gated.",
                    )
                return DefenseDecision(
                    decision="block", risk_score=0.85, confidence=0.65, reason_codes=["UNTRUSTED_INSTRUCTION_SOURCE"]
                )
    return None


# --- decision aggregator ------------------------------------------------------

SENSITIVE_LEVELS = {"restricted", "confidential"}
LABELED_SECRET_PATTERN = re.compile(
    r"(?:token|key|code|secret|passphrase|credential|reference|binding)\w*[^:\n]{0,40}:\s*['\"]?"
    r"([A-Za-z0-9_\-]{4,})",
    re.IGNORECASE,
)


def resolve_sensitivity(request: DefenseRequest) -> dict[str, str]:
    return {record.id: record.provenance.sensitivity for record in request.provenance}


def protected_tokens(request: DefenseRequest, sensitivity: dict[str, str]) -> set[str]:
    """Secret-like values sourced from restricted/confidential content. Matches
    only the value FOLLOWING a labeled field (portal_token: XYZ, admin_key: ABC,
    etc.) rather than every digit-containing string -- an earlier version of
    this check also grabbed ordinary business IDs like CASE-7001 that happened
    to co-occur in the same restricted record, and over-redacted them (design-log
    Entry 14). Every canary secret in the scenario library follows this exact
    '<label containing token/key/code/secret/...>: <value>' shape."""
    tokens: set[str] = set()
    for item in request.conversation:
        if any(sensitivity.get(pid) in SENSITIVE_LEVELS for pid in item.provenance_ids):
            tokens.update(LABELED_SECRET_PATTERN.findall(item.content))
    return tokens


def redact(text: str | None, tokens: set[str]) -> str | None:
    if text is None:
        return None
    for tok in tokens:
        text = text.replace(tok, "[REDACTED]")
    return text


def check_sensitive_leak(request: DefenseRequest, action: CandidateAction) -> DefenseDecision | None:
    """Runs on EVERY action type, including 'respond' -- unlike the other checks,
    a leak can happen in the agent's own final message, not just a tool call."""
    tokens = protected_tokens(request, resolve_sensitivity(request))
    if not tokens:
        return None

    outbound = " ".join(str(v) for v in action.arguments.values() if isinstance(v, str))
    if action.content:
        outbound += " " + action.content

    leaked = {t for t in tokens if t in outbound}
    if not leaked:
        return None

    rewritten = action.model_copy(
        update={
            "arguments": {k: (redact(v, leaked) if isinstance(v, str) else v) for k, v in action.arguments.items()},
            "content": redact(action.content, leaked),
        }
    )
    return DefenseDecision(
        decision="rewrite",
        risk_score=0.8,
        confidence=0.7,
        reason_codes=["SENSITIVE_DATA_LEAK_PREVENTED"],
        explanation="Restricted content was about to be copied into this action; redacted before proceeding.",
        rewritten_action=rewritten,
    )


# --- encoding-aware exfiltration detector (v4) ------------------------------

def _reversed_str(s: str) -> str:
    return s[::-1]


def _hex_str(s: str) -> str:
    return s.encode().hex()


def _spaced_str(s: str) -> str:
    return " ".join(list(s))


def _b64_str(s: str) -> str:
    return base64.b64encode(s.encode()).decode().rstrip("=")


def obfuscated_forms(token: str) -> set[str]:
    """A secret leaving in disguise: reversed, hex, spaced-out, or base64.
    These are the exact transformations named in the spec's data-exfiltration
    attack family. check_sensitive_leak (above) only catches the plain form."""
    return {_reversed_str(token), _hex_str(token), _spaced_str(token), _b64_str(token)}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


HIGH_ENTROPY_CHUNK = re.compile(r"[A-Za-z0-9+/=_\-]{12,}")


def check_encoded_leak(request: DefenseRequest, action: CandidateAction) -> DefenseDecision | None:
    tokens = protected_tokens(request, resolve_sensitivity(request))
    if not tokens:
        return None

    outbound_parts = [str(v) for v in action.arguments.values() if isinstance(v, str)]
    if action.content:
        outbound_parts.append(action.content)
    outbound = " ".join(outbound_parts)
    if not outbound:
        return None

    lowered = outbound.lower()
    hit_forms: set[str] = set()
    for tok in tokens:
        for form in obfuscated_forms(tok):
            if len(form) >= 4 and form.lower() != tok.lower() and form.lower() in lowered:
                hit_forms.add(form)

    if hit_forms:
        def strip(text: str | None) -> str | None:
            if text is None:
                return None
            for f in hit_forms:
                text = text.replace(f, "[REDACTED]")
            return text

        rewritten = action.model_copy(
            update={
                "arguments": {k: (strip(v) if isinstance(v, str) else v) for k, v in action.arguments.items()},
                "content": strip(action.content),
            }
        )
        return DefenseDecision(
            decision="rewrite",
            risk_score=0.85,
            confidence=0.6,
            reason_codes=["ENCODED_SENSITIVE_DATA_DETECTED"],
            explanation="Restricted content found disguised (reversed/hex/spaced/base64) in this action; redacted.",
            rewritten_action=rewritten,
        )

    # Nothing matched a known transform of a known secret. Fallback: flag
    # unusually random-looking chunks for human review -- ESCALATE, not block,
    # since this is inherently uncertain (could be a legitimate high-entropy ID)
    # and only fires at all when the session has touched restricted content.
    suspicious = [m for m in HIGH_ENTROPY_CHUNK.findall(outbound) if shannon_entropy(m) >= 3.5]
    if suspicious:
        return DefenseDecision(
            decision="escalate",
            risk_score=0.5,
            confidence=0.4,
            reason_codes=["HIGH_ENTROPY_CONTENT_NEAR_SENSITIVE_SOURCE"],
            explanation="Unusually random-looking content alongside restricted-sensitivity context; needs review.",
        )
    return None


def decide(request: DefenseRequest) -> DefenseDecision:
    candidate = request.candidate_action
    action = candidate.confirmation_for if candidate.type == "request_confirmation" else candidate

    if action is not None:
        leak = check_sensitive_leak(request, action)
        if leak is not None:
            return leak
        encoded_leak = check_encoded_leak(request, action)
        if encoded_leak is not None:
            return encoded_leak

    if action is None or action.type != "tool_call" or action.tool is None:
        # 'respond' / 'memory_write' with no tool: still worth a content check later
        # (exfiltration screening is a known v1 gap — see module docstring).
        return DefenseDecision(decision="allow", risk_score=0.1, confidence=0.5, reason_codes=["NOT_A_TOOL_CALL"])

    hard = check_hard_policy(request, action)
    if hard is not None:
        return hard

    risky = check_content_risk(request, action)
    if risky is not None:
        return risky

    # Session-memory piece (v2, first cut): this action looks fine in isolation,
    # but if the session has ever seen adversary-controlled content, our risk
    # NUMBER should say so honestly, even though we still allow the action.
    # Deliberately NOT a new block/escalate condition -- see design-log Entry 9
    # for why: turning session taint into a blanket block would over-restrict
    # every legitimate task that happens to touch one hostile record early on.
    if request.history_digest.least_trusted_seen == "adversary_controlled":
        return DefenseDecision(
            decision="allow", risk_score=0.35, confidence=0.6, reason_codes=["SESSION_HISTORY_TAINTED"]
        )

    return DefenseDecision(decision="allow", risk_score=0.1, confidence=0.6, reason_codes=["USER_GOAL_ALIGNED"])
