"""
OutboundGuard.recover() — rewrite-to-send, not refuse-to-send.

The regression these lock down is real and dated. On 2026-07-12 a group agent answered five
questions with "I drafted a reply to that, but it would have exposed private details from Sai's
setup, so I'm not sending it." Every one of those five was blocked on a single finding —
"Absolute local filesystem path". A path is trivially rewritable. The agent apologised instead of
answering, five times, for a problem it could have simply fixed.

Two library bugs made that inevitable, and both are pinned here:

  1. `_regex_redact()` never touched `_COMPILED_INTERNAL` — the 0.95-scored patterns (paths,
     codenames, scaffolding) that are the ONLY reason `check()` ever returns BLOCKED. So the
     redactor that was meant to rescue a blocked message could not remove the thing that blocked
     it, and handed back text that failed re-screening.
  2. `check()` short-circuits at risk >= 0.9 BEFORE the LLM slow path, and `sanitize()` returned
     "[BLOCKED]" for a blocked result without calling the LLM either. The LLM rewriter was
     therefore unreachable for exactly the findings that needed it — dead code by construction.
"""
import pytest

from jataayu.guards.outbound import OutboundGuard, PrivacyConfig


# The five real declines, verbatim from jataayu_quarantine.jsonl. Not illustrative — the actual
# drafts that were thrown away.
REAL_DECLINES = [
    "Done. Started a clean new project: `/home/user/projects/project_agent_guardrail_drift` "
    "-- scaffolding is in place.",
    "The local repo is already set up correctly here: "
    "`/home/user/projects/project_webpage/repos/saikrishnarallabandi.github.io`",
]

GROUP = "whatsapp-group"


class StubLLM:
    """Stands in for the LLM backend. Records calls; returns whatever it was primed with."""

    def __init__(self, reply=None, fail=False):
        self.reply = reply
        self.fail = fail
        self.calls = []

    def call(self, system_prompt, user_message, max_tokens=1024):
        self.calls.append((system_prompt, user_message))
        if self.fail:
            raise RuntimeError("backend down")
        return self.reply


def guard(llm=None, use_llm=False, names=None):
    g = OutboundGuard(PrivacyConfig(
        protected_names=names or [],
        use_llm=use_llm,
    ))
    if llm is not None:
        g.llm = llm
    return g


# ---------------------------------------------------------------------------
# The deterministic floor — no LLM at all
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("draft", REAL_DECLINES)
def test_real_declines_now_send_without_any_llm(draft):
    """Each of these was a canned apology in production. Every one must now be delivered."""
    r = guard(use_llm=False).recover(draft, surface=GROUP)

    assert r.action == "send", f"still refusing to send: {r.reason}"
    assert r.text, "sent an empty message"
    assert "/home2/" not in r.text and "/home/" not in r.text, "path survived the rewrite"
    assert "I'm not sending it" not in r.text, "still apologising instead of answering"


def test_path_collapses_to_bare_filename_not_a_redaction_marker():
    """A path is redacted to its filename so the sentence still MEANS something.

    "[REDACTED]" would technically be safe and would also destroy the answer.
    """
    r = guard(use_llm=False).recover(
        "The outbound guard lives in /home/user/projects/jataayu/jataayu/guards/outbound.py "
        "and the scoring is in docs/design/scoring.md",
        surface=GROUP,
    )
    assert r.action == "send"
    assert "outbound.py" in r.text
    assert "scoring.md" in r.text
    assert "/home2/" not in r.text
    assert "docs/design" not in r.text


def test_clean_message_is_untouched():
    text = "Yeah, the guard re-screens every rewrite before it goes out."
    r = guard(use_llm=False).recover(text, surface=GROUP)

    assert r.action == "send"
    assert r.changed is False
    assert r.text == text
    assert r.stages == []


def test_internal_codename_is_neutralised():
    r = guard(use_llm=False).recover("The Cassandra numbers look strong.", surface=GROUP)
    assert r.action == "send"
    assert "Cassandra" not in r.text


def test_mixed_pii_and_path_is_still_sendable():
    """Findings from several classes at once — the common case, and the one that used to decline.

    Raised in review on PR #17. It caught a hole of exactly the shape this file exists to close:
    _regex_redact() only stripped PII patterns scoring >= 0.75, but an email and a phone number
    score UNDER that. So they were DETECTED (raising risk out of CLEAN, blocking the send) and then
    survived the redaction meant to rescue it — re-screening failed and the message was withheld.

    Nothing that can stop a message may be beyond the reach of the thing that repairs it.
    """
    r = guard(use_llm=False, names=["Veda"]).recover(
        "Ping sai@example.com or +1 555 123 4567 — the scoring lives in docs/design/scoring.md "
        "and Veda has the notes.",
        surface=GROUP,
    )

    assert r.action == "send", f"multi-class findings must still be sendable: {r.reason}"
    assert "sai@example.com" not in r.text
    assert "555 123 4567" not in r.text
    assert "Veda" not in r.text
    assert "docs/design" not in r.text
    assert "scoring.md" in r.text, "the answer must survive the redaction"


# ---------------------------------------------------------------------------
# The credential floor — the one thing that is never rephrased
# ---------------------------------------------------------------------------

def test_credential_is_withheld_and_never_shown_to_the_llm():
    """A leaked path is embarrassing and reversible. A leaked key is neither.

    We would rather withhold the message than hand a live secret to a model and hope.
    """
    llm = StubLLM(reply="totally harmless now, promise")
    g = guard(llm=llm, use_llm=True)

    r = g.recover(
        "use sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM to auth",
        surface=GROUP,
    )

    assert r.action == "withhold"
    assert r.withheld_category == "credential"
    assert r.text == ""
    assert llm.calls == [], "the credential must never be sent to the LLM"


def test_rewrite_that_reintroduces_a_credential_is_withheld():
    """The rewrite is not trusted either — it is re-screened, and a rogue one is caught."""
    llm = StubLLM(reply="here, use sk-ant-api03-QQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ00001111")
    g = guard(llm=llm, use_llm=True)

    r = g.recover("scaffolding is in /home/user/projects/foo", surface=GROUP)

    assert r.action == "withhold"
    assert r.withheld_category == "credential"


# ---------------------------------------------------------------------------
# The LLM path — the primary route
# ---------------------------------------------------------------------------

def test_llm_rewrite_is_used_and_re_screened():
    llm = StubLLM(reply="Done. Started a clean new project: project_agent_guardrail_drift.")
    g = guard(llm=llm, use_llm=True)

    r = g.recover(REAL_DECLINES[0], surface=GROUP)

    assert r.action == "send"
    assert r.llm_used is True
    assert r.stages == ["llm-rephrase"]
    assert r.text == "Done. Started a clean new project: project_agent_guardrail_drift."
    assert len(llm.calls) == 1


def test_llm_rewrite_preserves_the_answer_a_protected_name_would_have_destroyed():
    """Deterministic redaction gives "[REDACTED] has a recital" — safe, and useless.

    This is what the LLM is FOR: "A family member has a recital" answers the question.
    """
    llm = StubLLM(reply="A family member has a recital on Thursday so I'll be offline.")
    g = guard(llm=llm, use_llm=True, names=["Veda"])

    r = g.recover("Veda has a recital on Thursday so I'll be offline.", surface=GROUP)

    assert r.action == "send"
    assert "Veda" not in r.text
    assert "recital" in r.text, "the LLM must keep the answer, not just delete the name"


def test_llm_that_still_leaks_falls_back_to_deterministic_redaction():
    """The LLM is a network call to a model that can be wrong. The floor catches it."""
    llm = StubLLM(reply="Sure! It's at /home/user/projects/still_leaking/x.py")
    g = guard(llm=llm, use_llm=True)

    r = g.recover(REAL_DECLINES[0], surface=GROUP)

    assert r.action == "send", "a bad rewrite must not become a refusal"
    assert "/home2/" not in r.text
    assert "redact" in r.stages


def test_llm_down_falls_back_to_deterministic_redaction():
    """A guard that only works when the model cooperates is not a guard."""
    g = guard(llm=StubLLM(fail=True), use_llm=True)

    r = g.recover(REAL_DECLINES[0], surface=GROUP)

    assert r.action == "send"
    assert "/home2/" not in r.text
    assert r.stages == ["llm-unavailable", "redact"]
    assert r.llm_used is False


def test_llm_refusal_is_treated_as_no_answer_not_as_the_message():
    """The rewriter is told never to refuse. If it refuses anyway, we do not SEND the refusal."""
    g = guard(llm=StubLLM(reply="BLOCKED"), use_llm=True)

    r = g.recover(REAL_DECLINES[0], surface=GROUP)

    assert r.action == "send"
    assert "BLOCKED" not in r.text
    assert "/home2/" not in r.text


def test_residue_is_fed_back_on_retry():
    """Round 2 must be told what actually survived round 1, or it just makes the same mistake."""

    class TwoTries(StubLLM):
        def call(self, system_prompt, user_message, max_tokens=1024):
            self.calls.append((system_prompt, user_message))
            if len(self.calls) == 1:
                return "Nearly: /home/user/projects/foo is done"  # still leaking
            return "Nearly: foo is done"  # clean

    llm = TwoTries()
    g = guard(llm=llm, use_llm=True)

    r = g.recover(REAL_DECLINES[0], surface=GROUP, max_attempts=2)

    assert r.action == "send"
    assert r.text == "Nearly: foo is done"
    assert r.stages == ["llm-rephrase", "llm-rephrase"]
    assert "Absolute local filesystem path" in llm.calls[1][1], \
        "the second attempt must be told what survived the first"


# ---------------------------------------------------------------------------
# sanitize() — the old surface, now routed through recover()
# ---------------------------------------------------------------------------

def test_sanitize_rescues_a_blocked_message_instead_of_returning_BLOCKED():
    """Before: a 0.95 path finding meant sanitize() returned "[BLOCKED …]" and the caller had
    nothing to send. It now returns the salvaged text."""
    out = guard(use_llm=False).sanitize(REAL_DECLINES[0], surface=GROUP)

    assert not out.startswith("[BLOCKED")
    assert "/home2/" not in out
    assert "project_agent_guardrail_drift" in out


def test_sanitize_still_blocks_a_credential():
    out = guard(use_llm=False).sanitize(
        "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM", surface=GROUP
    )
    assert out.startswith("[BLOCKED")
