"""
Jataayu Effect Boundary — authorize at the action, not the text
===============================================================
Pattern/classifier guards (jataayu's inbound engine, Prompt-Guard, etc.) defend *the attack
string*. The literature is unanimous that this is the weakest tier against adaptive attackers: a
trivial transform defeats string detection ~100% of the time. The durable defenses
(CaMeL — arXiv 2503.18813; FIDES — 2505.23643; arXiv:2606.09549) move the security boundary
off the text and onto the **action**: an attacker who wins the text battle still must not be able
to COMMIT an unauthorized high-effect action.

This module implements that boundary deterministically (no LLM in the decision path):

  1. Provenance-typed values. Data read by the agent is wrapped with a provenance label
     (TRUSTED / UNTRUSTED). Provenance flows into the actions those values drive.

  2. PREVIEW -> COMMIT. `preview()` produces a canonical, normalized description of the exact
     request plus a deterministic policy decision (ALLOW / DENY / NEEDS_APPROVAL) based on
     (effect severity x worst inbound provenance x the agent's capability policy). A `commit_token`
     is issued only on ALLOW, bound to the canonical request. `commit()` runs the executor only if
     the token validates against the action actually being executed — so mutating the action after
     authorization (a classic injection trick) yields a hash mismatch and is rejected.

  3. Read-boundary confinement. `confine_read()` replaces a raw sensitive read with an opaque
     handle + a bounded summary. The agent/LLM context only ever holds the handle, so an injected
     "exfiltrate the secret" instruction has nothing but a handle to send; only the trusted
     executor can dereference it at commit time.

It composes with `jataayu.config.policy.AgentPolicy` (capability allow/forbid lists) but works
standalone with safe defaults.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Optional

from jataayu.core.taint import (
    _SHELL_SINK_TOOLS, _FILE_WRITE_TOOLS, _NETWORK_TOOLS, _SECRET_TOOLS,
)


class Provenance(Enum):
    """Where a value came from, for authorization purposes."""
    TRUSTED = "trusted"      # first-party: the operator, system config, signed sources
    UNTRUSTED = "untrusted"  # anything attacker-influenceable: web, issues, tool returns, memory

    def worst(self, other: "Provenance") -> "Provenance":
        return Provenance.UNTRUSTED if Provenance.UNTRUSTED in (self, other) else Provenance.TRUSTED


class EffectClass(Enum):
    """The kind of effect an action has, ordered by severity."""
    NONE = "none"
    READ = "read"
    MEMORY_WRITE = "memory_write"
    FILE_WRITE = "file_write"
    NETWORK = "network"
    SECRET_READ = "secret_read"
    SHELL = "shell"
    CODE_EVAL = "code_eval"
    # A tool name that matches NO known effect family. Treated as high-harm under untrusted
    # provenance (fail-closed), because we cannot vouch that an unrecognized action is safe.
    UNKNOWN = "unknown"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]

    @property
    def capability(self) -> Optional[str]:
        """The capability tag (matching AgentPolicy) this effect requires, if any."""
        return _EFFECT_CAPABILITY.get(self)


_SEVERITY = {
    EffectClass.NONE: 0,
    EffectClass.READ: 1,
    EffectClass.MEMORY_WRITE: 2,
    EffectClass.FILE_WRITE: 3,
    EffectClass.NETWORK: 4,
    EffectClass.SECRET_READ: 4,
    EffectClass.SHELL: 5,
    EffectClass.CODE_EVAL: 5,
    EffectClass.UNKNOWN: 4,
}

_EFFECT_CAPABILITY = {
    EffectClass.READ: "fs_read",
    EffectClass.MEMORY_WRITE: "memory_write",
    EffectClass.FILE_WRITE: "fs_write",
    EffectClass.NETWORK: "network_write",
    EffectClass.SECRET_READ: "reads_secrets",
    EffectClass.SHELL: "exec",
    EffectClass.CODE_EVAL: "exec",
    # Keep UNKNOWN under capability isolation in allowlist mode.
    EffectClass.UNKNOWN: "unknown_effect",
}

# Effects for which untrusted-derived input is categorically denied (no preview->commit at all):
# committing them under attacker influence is the kill-chain endpoint.
_CRITICAL_EFFECTS = frozenset({EffectClass.SHELL, EffectClass.CODE_EVAL, EffectClass.SECRET_READ})
# Effects for which untrusted-derived input requires human approval rather than an outright deny.
# UNKNOWN is here so an unrecognized tool driven by untrusted input is held for approval, not
# silently allowed (the fail-closed posture; see EffectBoundary(fail_closed_unknown=...)).
_APPROVAL_EFFECTS = frozenset({
    EffectClass.NETWORK, EffectClass.FILE_WRITE, EffectClass.MEMORY_WRITE, EffectClass.UNKNOWN,
})

_CODE_EVAL_TOOLS = frozenset({"eval", "exec", "python_eval", "js_eval", "run_code", "code_interpreter"})
_MEMORY_WRITE_TOOLS = frozenset({"memory_write", "save_memory", "remember", "store_memory", "kv_set"})

# ---------------------------------------------------------------------------
# Token-level effect signals.
#
# Exact whole-string matching against the sets above is not enough: real MCP tools are almost
# always namespaced (`shell.exec`, `os.system`) or snake_case (`run_shell_command`), and any name
# that missed the exact sets previously fell through to READ -> ALLOW — so `rm -rf` from untrusted
# input was authorized under a name like `shell.exec`. We therefore also match on the *components*
# of the tool name (split on `.`/`_`/`-`/`/`/space and camelCase).
#
# SHELL and CODE_EVAL are security-equivalent here (both severity-5, both capability "exec", both
# in _CRITICAL_EFFECTS), so the shell-vs-codeeval label is best-effort; what matters is that either
# is recognized as a critical exec effect rather than a read.
_SHELL_TOKENS = frozenset({
    "bash", "shell", "sh", "zsh", "ksh", "csh", "fish", "cmd", "powershell", "pwsh",
    "terminal", "subprocess", "popen",
})
# Shell-ish tokens that are too common to match anywhere in a name (e.g. "get_system_status"),
# so they only count when they are the trailing verb (`os.system`, `process.spawn`).
_SHELL_VERB_TOKENS = frozenset({"system", "spawn"})
_CODE_TOKENS = frozenset({
    "python", "python3", "py", "javascript", "js", "node", "nodejs", "ruby", "perl", "php",
    "lua", "code", "interpreter", "compile",
    # RCE-capable deserialization sinks: loading untrusted pickle/dill/marshal is arbitrary code
    # execution regardless of arguments. (Unsafe `yaml.load` is handled separately in classify()
    # so that the safe `yaml.safe_load` is not swept in.)
    "pickle", "unpickle", "cpickle", "dill", "marshal",
})

# Secret-read detection.
#
# `_name_tokens` splits `api_key`->["api","key"] and camelCase `apiKey`->["api","key"], so the
# signal must live in the *individual* tokens. But a bare generic noun (`key`/`keys`/`rsa`/`cert`)
# is too common to match alone — `press_key`, `list_keys`, `get_public_key` are not secret reads —
# and matching it bare BOTH over-blocks those benign names AND (via exact-token, not stem, matching)
# still misses plurals like `list_api_keys`. So a credential read fires on either:
#   (a) a STRONG standalone token — unambiguous on its own; or
#   (b) a QUALIFIER token combined with a GENERIC secret noun (handles api_key, access_token,
#       private_key, list_api_keys, id_rsa, ... and their plurals/casing).
# Bare generic nouns without a qualifier do NOT fire (undoes the round-2 over-block).
_SECRET_STRONG = frozenset({
    "secret", "secrets", "credential", "credentials", "keychain", "vault",
    "passwd", "password", "apikey", "apitoken", "privatekey",
    "pkcs12", "keystore", "pem",
    # Canonical agent secret-store files — a FINITE, known list. `.env` is deliberately excluded
    # (handled by the env-var branch below); `dotenv` is the single-token spelling of the file.
    # Novel/arbitrary secret filenames are out of scope here — that is the Phase-2 argument/
    # path-aware classification job, not name-token matching.
    "netrc", "dotenv", "pgpass", "htpasswd", "kubeconfig",
})
# Secret-store names that `_name_tokens` splits across components (so no single token can carry the
# signal). Each frozenset is an all-must-be-present token combo.
_SECRET_STORE_COMBOS = (
    frozenset({"kube", "config"}),        # read_kube_config
    frozenset({"service", "account"}),    # get_service_account, gcp_service_account_key
    frozenset({"token", "file"}),         # read_token_file
)
_SECRET_QUALIFIERS = frozenset({
    "api", "access", "private", "ssh", "oauth", "bearer", "signing", "secret", "id",
})
_SECRET_NOUNS = frozenset({
    "key", "keys", "token", "tokens", "cert", "certs", "certificate", "certificates",
    "rsa", "keypair",
})
_SECRET_ENV_TOKENS = frozenset({"env", "environ", "environment"})
# Read-ish verbs that mark a secret read but are not in the general _READ_VERBS fallback set
# (a dump/exfil of the environment is still a read of it).
_SECRET_EXTRA_READ_VERBS = frozenset({"dump", "fetch", "retrieve", "reveal"})

_MEMORY_TOKENS = frozenset({"memory", "memories"})
_MEMORY_WRITE_VERBS = frozenset({"write", "save", "store", "set", "remember", "persist", "put"})

_FILE_WRITE_STRONG = frozenset({
    "write", "overwrite", "append", "truncate", "unlink", "mkdir", "rmdir", "chmod", "chown",
})
_FILE_MUTATE_VERBS = frozenset({
    "create", "delete", "remove", "edit", "save", "modify", "update", "rename", "move", "replace",
})
_FILE_NOUNS = frozenset({
    "file", "files", "dir", "dirs", "directory", "directories", "path", "folder",
    "document", "doc", "docs",
})

_NETWORK_STRONG = frozenset({
    "fetch", "curl", "wget", "http", "https", "url", "webhook", "download", "upload",
    "browse", "browser", "request",
})
_NETWORK_VERBS = frozenset({
    "send", "post", "publish", "transfer", "reserve", "book", "invite", "share",
    "email", "sms", "notify", "dispatch",
})

# Verbs that mark a genuine READ (so the name is *recognized* and stays ALLOW even under untrusted
# input), distinguishing benign reads from a truly-unknown tool that must fail closed.
_READ_VERBS = frozenset({
    "read", "get", "list", "search", "view", "show", "cat", "open", "load", "find", "query",
    "describe", "stat", "head", "tail", "grep", "ls", "dir", "lookup", "count", "info", "status",
    "summary", "preview", "inspect", "recall",
})


def _name_tokens(name: str) -> list[str]:
    """Split a tool name into lowercase components on separators and camelCase boundaries."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    return [tok for tok in re.split(r"[^a-zA-Z0-9]+", spaced.lower()) if tok]


class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


class CommitRejected(Exception):
    """Raised when commit() is called on an action that was not authorized by its preview."""


@dataclass
class Value:
    """A piece of data flowing into an action, tagged with its provenance."""
    data: Any
    provenance: Provenance = Provenance.UNTRUSTED
    source: str = "unknown"


@dataclass
class OpaqueHandle:
    """A reference to confined sensitive content. The raw value never enters agent context."""
    handle_id: str
    summary: str
    source: str

    def __str__(self) -> str:
        return f"<jataayu:handle:{self.handle_id} {self.summary}>"


@dataclass
class PreviewResult:
    tool_name: str
    params: dict
    effect_class: EffectClass
    provenance: Provenance
    decision: Decision
    reason: str
    canonical: str
    commit_token: Optional[str] = None
    violations: list[str] = field(default_factory=list)

    @property
    def approved(self) -> bool:
        return self.decision is Decision.ALLOW

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "effect_class": self.effect_class.value,
            "provenance": self.provenance.value,
            "decision": self.decision.value,
            "reason": self.reason,
            "violations": self.violations,
            "commit_token": self.commit_token,
        }


def _canonical(tool_name: str, params: dict) -> str:
    """Deterministic, normalized serialization of an action for binding the commit token."""
    return json.dumps({"tool": tool_name.strip().lower(), "params": params},
                      sort_keys=True, separators=(",", ":"), default=str)


class EffectBoundary:
    """
    Deterministic action-level authorization with PREVIEW -> COMMIT and read confinement.

    Example::

        boundary = EffectBoundary(policy=agent_policy)

        # Untrusted content extracted from a web page wants to run a shell command:
        pv = boundary.preview("bash", {"command": cmd},
                              values=[Value(cmd, Provenance.UNTRUSTED, source="web-page")])
        if pv.approved:
            boundary.commit(pv, {"command": cmd}, lambda: run(cmd))
        else:
            log(pv.reason)   # DENY — untrusted data may not reach a shell, regardless of text
    """

    def __init__(self, policy=None, *, default_untrusted: bool = True,
                 fail_closed_unknown: bool = True):
        self.policy = policy
        self.default_untrusted = default_untrusted
        # When True (default), an unrecognized tool name driven by untrusted input is held for
        # human approval rather than allowed. Set False for a permissive posture on unknowns.
        self.fail_closed_unknown = fail_closed_unknown
        self._vault: dict[str, str] = {}
        self._counter = 0

    # -- effect classification -------------------------------------------------
    def classify(self, tool_name: str) -> EffectClass:
        t = tool_name.strip().lower()
        # 1. Exact whole-string match against the curated sink sets (most specific).
        if t in _CODE_EVAL_TOOLS:
            return EffectClass.CODE_EVAL
        if t in _SHELL_SINK_TOOLS:
            return EffectClass.SHELL
        if t in _SECRET_TOOLS:
            return EffectClass.SECRET_READ
        if t in _MEMORY_WRITE_TOOLS:
            return EffectClass.MEMORY_WRITE
        if t in _FILE_WRITE_TOOLS:
            return EffectClass.FILE_WRITE
        if t in _NETWORK_TOOLS:
            return EffectClass.NETWORK

        # 2. Token-level match for namespaced / snake_case / camelCase names that missed the
        #    exact sets. Ordered most-dangerous-first so a critical sink always wins over the
        #    benign READ fallback (e.g. `get_shell` -> SHELL, not READ).
        toks = _name_tokens(tool_name)
        if not toks:
            return EffectClass.UNKNOWN
        tset = set(toks)
        verb = toks[-1]

        # Exec effects (shell / code-eval) — severity-5, capability "exec".
        shell_strong = bool(tset & _SHELL_TOKENS) or verb in _SHELL_VERB_TOKENS
        code_strong = bool(tset & _CODE_TOKENS)
        exec_verb = verb in {"exec", "eval"} or bool(tset & {"exec", "eval"})
        # Unsafe YAML load (`yaml.load` / `yaml_load` / `load_yaml`) is an RCE deserialization sink,
        # but the safe `yaml.safe_load` must NOT trip — so match yaml+load only when not "safe".
        yaml_unsafe = ("yaml" in tset) and bool(tset & {"load", "loads"}) and ("safe" not in tset)
        if shell_strong or code_strong or exec_verb or yaml_unsafe:
            if shell_strong:
                return EffectClass.SHELL
            # Code namespace (python.exec), a bare exec/eval verb, or unsafe deserialization.
            return EffectClass.CODE_EVAL

        # Secret reads: a strong standalone token, a known secret-store token combo, a qualifier +
        # a generic secret noun, or any read of the environment. Checked before the READ-verb
        # fallback so `get_api_key` / `cat_env` are SECRET_READ, not READ. The env branch uses the
        # SAME full read-verb set as the fallback so every env read denies consistently.
        if (
            (tset & _SECRET_STRONG)
            or any(combo <= tset for combo in _SECRET_STORE_COMBOS)
            or ((tset & _SECRET_QUALIFIERS) and (tset & _SECRET_NOUNS))
            or ((tset & _SECRET_ENV_TOKENS)
                and bool(tset & (_READ_VERBS | _SECRET_EXTRA_READ_VERBS)))
        ):
            return EffectClass.SECRET_READ

        # Memory writes (checked before file writes: "write_memory" is a memory write).
        if (tset & _MEMORY_TOKENS) and (tset & _MEMORY_WRITE_VERBS):
            return EffectClass.MEMORY_WRITE

        # File writes.
        if (tset & _FILE_WRITE_STRONG) or ((tset & _FILE_MUTATE_VERBS) and (tset & _FILE_NOUNS)):
            return EffectClass.FILE_WRITE

        # Network / external-effect actions.
        if (tset & _NETWORK_STRONG) or (tset & _NETWORK_VERBS):
            return EffectClass.NETWORK

        # 3. Recognized read verb -> genuine READ (stays ALLOW even under untrusted input).
        #
        # Known residual gap (deliberately not reclassified here): names whose harm lives in the
        # *arguments*, not the name — `sql.query` (a SELECT read vs a DROP), `dns_lookup` (a read
        # vs an exfil channel), `load_and_run` — classify READ. Promoting them by name alone would
        # over-block the common benign read; discriminating them needs argument inspection, which
        # is out of scope for name-based classification. Likewise a plain `read_certificate` stays
        # READ (a public cert is not secret); the private-key/cert BUNDLE forms `pkcs12`/`keystore`
        # are strong secret tokens and deny. The fail-closed UNKNOWN default already covers any
        # name that carries no read verb at all.
        if tset & _READ_VERBS:
            return EffectClass.READ

        # 4. Nothing matched -> unknown; the decision layer fails closed on untrusted input.
        return EffectClass.UNKNOWN

    # -- the policy decision (deterministic, no LLM) ---------------------------
    def _decide(self, effect: EffectClass, provenance: Provenance) -> tuple[Decision, str, list[str]]:
        violations: list[str] = []

        # 1. Capability isolation from the agent policy always wins.
        cap = effect.capability
        if cap and self.policy is not None and not self.policy.is_capability_allowed(cap):
            violations.append(cap)
            return Decision.DENY, f"capability '{cap}' is forbidden for this agent", violations

        # 2. Untrusted-derived input into a consequential effect.
        if provenance is Provenance.UNTRUSTED:
            if effect in _CRITICAL_EFFECTS:
                return (Decision.DENY,
                        f"untrusted-derived input may not reach a {effect.value} effect", violations)
            if effect is EffectClass.UNKNOWN:
                if self.fail_closed_unknown:
                    return (Decision.NEEDS_APPROVAL,
                            "unrecognized tool with untrusted-derived input requires human "
                            "approval (fail-closed on unknown effect)", violations)
                # Permissive posture: fall through to ALLOW.
            elif effect in _APPROVAL_EFFECTS:
                return (Decision.NEEDS_APPROVAL,
                        f"untrusted-derived {effect.value} effect requires human approval", violations)

        # 3. Trusted input, or low-severity effect.
        return Decision.ALLOW, f"{provenance.value} input into {effect.value} effect", violations

    # -- preview / commit ------------------------------------------------------
    def preview(self, tool_name: str, params: dict,
                values: Iterable[Value] = ()) -> PreviewResult:
        effect = self.classify(tool_name)
        provs = [v.provenance for v in values]
        if provs:
            provenance = provs[0]
            for p in provs[1:]:
                provenance = provenance.worst(p)
        else:
            provenance = Provenance.UNTRUSTED if self.default_untrusted else Provenance.TRUSTED

        decision, reason, violations = self._decide(effect, provenance)
        canonical = _canonical(tool_name, params)
        token = None
        if decision is Decision.ALLOW:
            token = hashlib.sha256(canonical.encode()).hexdigest()

        return PreviewResult(
            tool_name=tool_name, params=params, effect_class=effect, provenance=provenance,
            decision=decision, reason=reason, canonical=canonical,
            commit_token=token, violations=violations,
        )

    def commit(self, preview: PreviewResult, params: dict, executor: Callable[[], Any]) -> Any:
        """
        Execute `executor` iff `preview` authorized exactly this action.

        Rejects when: the preview was not ALLOW, no token was issued, or the action's canonical
        form changed since preview (an attacker mutating the call after authorization).
        """
        if preview.decision is not Decision.ALLOW or not preview.commit_token:
            raise CommitRejected(f"not authorized: {preview.decision.value} — {preview.reason}")
        expected = hashlib.sha256(_canonical(preview.tool_name, params).encode()).hexdigest()
        if expected != preview.commit_token:
            raise CommitRejected("action was mutated after authorization (commit token mismatch)")
        return executor()

    # -- read-boundary confinement ---------------------------------------------
    def confine_read(self, content: str, source: str, *, summary: Optional[str] = None) -> OpaqueHandle:
        """Store sensitive content out of agent context, returning an opaque handle + summary."""
        self._counter += 1
        digest = hashlib.sha256(f"{self._counter}:{content}".encode()).hexdigest()[:12]
        if summary is None:
            summary = f"{len(content)} chars from {source}"
        self._vault[digest] = content
        return OpaqueHandle(handle_id=digest, summary=summary, source=source)

    def dereference(self, handle: OpaqueHandle) -> Optional[str]:
        """Resolve a handle back to raw content — for the trusted executor at commit time only."""
        return self._vault.get(handle.handle_id)
