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
}

_EFFECT_CAPABILITY = {
    EffectClass.READ: "fs_read",
    EffectClass.MEMORY_WRITE: "memory_write",
    EffectClass.FILE_WRITE: "fs_write",
    EffectClass.NETWORK: "network_write",
    EffectClass.SECRET_READ: "reads_secrets",
    EffectClass.SHELL: "exec",
    EffectClass.CODE_EVAL: "exec",
}

# Effects for which untrusted-derived input is categorically denied (no preview->commit at all):
# committing them under attacker influence is the kill-chain endpoint.
_CRITICAL_EFFECTS = frozenset({EffectClass.SHELL, EffectClass.CODE_EVAL, EffectClass.SECRET_READ})
# Effects for which untrusted-derived input requires human approval rather than an outright deny.
_APPROVAL_EFFECTS = frozenset({
    EffectClass.NETWORK, EffectClass.FILE_WRITE, EffectClass.MEMORY_WRITE,
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
# Tokens are NOT all equal, and matching on mere set membership is wrong in both directions: it
# lets one benign token mask a dangerous name and one dangerous-looking noun escalate a benign one.
# A tool name is verb + object (`read_file`, `run_shell_command`) or namespace + verb
# (`shell.exec`, `os.system`), so the EFFECT is carried by the verb and the object only qualifies
# it. We therefore match effect verbs at a *verb position* (see `_verb_tokens`) and treat the
# object tokens below as qualifiers. That is what separates `run_shell_command` (exec) from
# `list_shell_history` (a read that merely mentions a shell).
#
# SHELL and CODE_EVAL are security-equivalent here (both severity-5, both capability "exec", both
# in _CRITICAL_EFFECTS), so the shell-vs-codeeval label is best-effort; what matters is that either
# is recognized as a critical exec effect rather than a read.
_SHELL_TOKENS = frozenset({
    "bash", "shell", "sh", "zsh", "ksh", "csh", "fish", "cmd", "powershell", "pwsh",
    "terminal", "subprocess", "popen",
})
_INTERPRETER_TOKENS = frozenset({
    "python", "python3", "py", "javascript", "js", "node", "nodejs", "ruby", "perl", "php",
    "lua", "code", "interpreter",
})
# RCE-capable deserialization sinks: loading untrusted pickle/dill/marshal is arbitrary code
# execution regardless of arguments, and these tokens are never a benign noun in a tool name, so
# unlike the interpreter tokens they fire wherever they appear. (Unsafe `yaml.load` is handled
# separately in classify() so that the safe `yaml.safe_load` is not swept in.)
_RCE_TOKENS = frozenset({"pickle", "unpickle", "cpickle", "dill", "marshal"})

# Exec verbs, by how much they mean on their own.
#   STRONG   — unambiguous in any verb position: `shell.exec`, `eval_python`, `read_file_and_exec`.
#   TRAILING — too common leading (`system_info`, `spawn_worker`) so only as the trailing verb:
#              `os.system`, `process.spawn`.
#   WEAK     — generic action verbs that mean "execute" only when the object is a shell or an
#              interpreter (`run_shell_command`, `code.run`); `run_query` / `execute_search`
#              are ordinary reads.
_EXEC_VERBS_STRONG = frozenset({"exec", "eval", "popen"})
_EXEC_VERBS_TRAILING = frozenset({"system", "spawn"})
_EXEC_VERBS_WEAK = frozenset({"run", "execute", "launch", "invoke", "start", "compile"})

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

# Verbs that mark a genuine READ.
_READ_VERBS = frozenset({
    "read", "get", "list", "search", "view", "show", "cat", "open", "load", "find", "query",
    "describe", "stat", "head", "tail", "grep", "ls", "dir", "lookup", "count", "info", "status",
    "summary", "preview", "inspect", "recall",
})


def _name_tokens(name: str) -> list[str]:
    """Split a tool name into lowercase components on separators and camelCase boundaries."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    return [tok for tok in re.split(r"[^a-zA-Z0-9]+", spaced.lower()) if tok]


def _verb_tokens(name: str) -> tuple[set[str], Optional[str], set[str]]:
    """
    (verb positions, trailing token, head-verb positions) for a tool name.

    A dotted prefix is a namespace, so the verb lives in the final dotted segment; within that
    segment it sits either leading (`read_file`, `run_shell_command`) or trailing (`shell_exec`,
    `os.system`). `verbs` is both ends — enough for the unambiguous exec verbs, and narrow enough
    that a token buried in the middle cannot decide the effect.

    `head` is stricter: the leading token, plus the trailing one only when a dotted namespace
    makes it the method name (`file.read`, `secrets.get`). The read verbs are ordinary English
    words, so they are matched against `head` alone — otherwise appending or prefixing one would
    make any name a recognized read (`exfiltrate_everything_status`, `wibble_lookup`).
    """
    segment = name.rsplit(".", 1)[-1]
    toks = _name_tokens(segment) or _name_tokens(name)
    if not toks:
        return set(), None, set()
    verbs = {toks[0], toks[-1]}
    head = verbs if "." in name else {toks[0]}
    return verbs, toks[-1], head


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
    # `decision` always means WHAT WAS ENFORCED, and stays 3-valued — every existing caller
    # compares it by string. The truthful verdict goes here; None means "same as decision".
    would_decision: Optional[Decision] = None
    mode: str = "enforce"
    unrecognized: bool = False

    @property
    def approved(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def tripwire_triggered(self) -> bool:
        """Whether the truthful verdict was anything other than ALLOW."""
        return (self.would_decision or self.decision) is not Decision.ALLOW

    def to_dict(self) -> dict:
        d = {
            "tool_name": self.tool_name,
            "effect_class": self.effect_class.value,
            "provenance": self.provenance.value,
            "decision": self.decision.value,
            "reason": self.reason,
            "violations": self.violations,
            "commit_token": self.commit_token,
        }
        # Keys are ADDED only in observe mode; enforce-mode output stays byte-for-byte
        # identical to pre-observe releases. That is the compatibility contract.
        if self.mode != "enforce":
            d["mode"] = self.mode
            d["would_decision"] = (self.would_decision or self.decision).value
            d["tripwire_triggered"] = self.tripwire_triggered
        return d


def _resolve(kwarg, policy, field_name: str, default):
    """Explicit kwarg (not None) > policy.<field_name> > built-in default."""
    if kwarg is not None:
        return kwarg
    value = getattr(policy, field_name, None)
    return default if value is None else value


def _coerce_effect(tool: str, value) -> EffectClass:
    """Accept an EffectClass or its string value in a tool_effects map."""
    if isinstance(value, EffectClass):
        return value
    try:
        return EffectClass(value)
    except ValueError:
        raise ValueError(
            f"tool_effects[{tool!r}]: invalid effect {value!r} — "
            f"expected one of {sorted(e.value for e in EffectClass)}"
        ) from None


def _json_default(value) -> str:
    """Stringify a param json cannot encode. A __str__ that raises must not take the
    authorization decision down with it — the token only needs a stable stand-in."""
    try:
        return str(value)
    except Exception:
        return f"<unstringable {type(value).__name__} at {id(value):#x}>"


# Prefix marking a dict key that `_normalize` rewrote. A key that already starts with it is
# rewritten too (see `_normalize`), so the rewritten and pass-through forms can never coincide.
_KEY_TAG = "\x00"


def _tag_key(key) -> str:
    """
    A type-qualified string form of a dict key.

    json.dumps silently coerces int/float/bool/None keys to strings, so `{1: "a"}` and
    `{"1": "a"}` canonicalize identically today — and a collision here is an attacker swapping
    params between PREVIEW and COMMIT while the token still validates. The type code is what
    keeps them apart. Note `{True: "x"}` and `{1: "x"}` are equal dicts to Python (True == 1
    hashes as the same key), so the bool check must precede the int one.
    """
    try:
        if isinstance(key, str):
            return _KEY_TAG + "s:" + key
        if isinstance(key, bool):
            return f"{_KEY_TAG}b:{key!r}"
        if isinstance(key, int):
            return f"{_KEY_TAG}i:{key!r}"
        if isinstance(key, float):
            return f"{_KEY_TAG}f:{key!r}"
        if key is None:
            return _KEY_TAG + "n:"
        if isinstance(key, tuple):
            return f"{_KEY_TAG}t:[{','.join(_tag_key(el) for el in key)}]"
    except Exception:
        pass
    # Anything else is identified, not stringified: two distinct objects sharing a __str__ must
    # not collapse onto one key, and __str__/__repr__ may raise (same posture as _json_default).
    # A rebuilt key object gets a new id and so fails the token check — fail-closed, which is the
    # correct direction when the alternative is a silent collision.
    return f"{_KEY_TAG}o:{type(key).__name__}:{id(key):#x}"


def _normalize(value, seen: set[int]):
    """
    Rewrite `value` so json.dumps(sort_keys=True) cannot fail on it.

    Two failure modes it removes: a key json cannot encode at all (tuple, object), and mixed key
    types that `sort_keys` cannot order. `default=` does not help — it only ever sees values.

    Anything already JSON-clean is returned unchanged (by identity), so the canonical form of
    ordinary string-keyed params — and every commit token in flight — is byte-for-byte what it
    was before. `seen` holds the ids on the current path, so a self-referential params dict
    terminates instead of recursing forever (json's own encoder tracks cycles the same way).
    """
    if isinstance(value, dict):
        if id(value) in seen:
            return f"{_KEY_TAG}cycle:{id(value):#x}"
        seen.add(id(value))
        try:
            # Tag every key or none: a dict where only the bad keys were tagged could coincide
            # with a pass-through dict that literally holds the tagged spelling.
            tag = any(not isinstance(k, str) or str.startswith(k, _KEY_TAG) for k in value)
            out, changed = {}, tag
            for k, v in value.items():
                nv = _normalize(v, seen)
                changed = changed or nv is not v
                out[_tag_key(k) if tag else k] = nv
            return out if changed else value
        finally:
            seen.discard(id(value))

    if isinstance(value, (list, tuple)):
        if id(value) in seen:
            return f"{_KEY_TAG}cycle:{id(value):#x}"
        seen.add(id(value))
        try:
            items = [_normalize(v, seen) for v in value]
            if all(a is b for a, b in zip(items, value)):
                return value
            return items
        finally:
            seen.discard(id(value))

    return value


def _canonical(tool_name: str, params: dict) -> str:
    """Deterministic, normalized serialization of an action for binding the commit token."""
    return json.dumps({"tool": tool_name.strip().lower(), "params": _normalize(params, set())},
                      sort_keys=True, separators=(",", ":"), default=_json_default)


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

    def __init__(
        self,
        policy=None,
        *,
        default_untrusted: bool = True,
        mode: Optional[str] = None,
        tool_effects: Optional[dict] = None,
        strict: Optional[bool] = None,
        sink: Optional[Callable[[dict], None]] = None,
        capture_content: Optional[bool] = None,
    ):
        self.policy = policy
        self.default_untrusted = default_untrusted
        self._vault: dict[str, str] = {}
        self._counter = 0

        # Precedence: explicit kwarg (not None) > policy field > built-in default.
        self.mode = _resolve(mode, policy, "mode", "enforce")
        if self.mode not in ("enforce", "observe"):
            raise ValueError(f"invalid mode {self.mode!r} — expected 'enforce' or 'observe'")
        self.strict = bool(_resolve(strict, policy, "strict_unknown_tools", False))
        self.sink = sink
        self.capture_content = capture_content

        # tool_effects MERGES rather than overrides: the policy file is the org's tool
        # inventory, the kwarg is a local addition. Kwarg wins per key.
        merged = dict(getattr(policy, "tool_effects", None) or {})
        merged.update(tool_effects or {})
        self.tool_effects: dict[str, EffectClass] = {
            str(k).strip().lower(): _coerce_effect(k, v) for k, v in merged.items()
        }

    # -- effect classification -------------------------------------------------
    def classify(self, tool_name: str) -> EffectClass:
        """The effect class of `tool_name`. Signature is load-bearing — many callers."""
        return self._classify(tool_name)[0]

    def _classify(self, tool_name: str) -> tuple[EffectClass, bool]:
        """(effect, recognized). `recognized` is False only at the step-4 fallback."""
        t = tool_name.strip().lower()
        # 0. Caller-supplied inventory wins over everything, so a user can FIX a false
        #    positive on their own tool name — a fill-gaps-only map could not do that.
        if t in self.tool_effects:
            return self.tool_effects[t], True

        # 1. Exact whole-string match against the curated sink sets (most specific).
        if t in _CODE_EVAL_TOOLS:
            return EffectClass.CODE_EVAL, True
        if t in _SHELL_SINK_TOOLS:
            return EffectClass.SHELL, True
        if t in _SECRET_TOOLS:
            return EffectClass.SECRET_READ, True
        if t in _MEMORY_WRITE_TOOLS:
            return EffectClass.MEMORY_WRITE, True
        if t in _FILE_WRITE_TOOLS:
            return EffectClass.FILE_WRITE, True
        if t in _NETWORK_TOOLS:
            return EffectClass.NETWORK, True

        # 2. Token-level match for namespaced / snake_case / camelCase names that missed the
        #    exact sets. Ordered most-dangerous-first so a critical sink always wins over the
        #    benign READ fallback (e.g. `get_shell` -> SHELL, not READ).
        toks = _name_tokens(tool_name)
        if not toks:
            # A name with no usable tokens ("", "***") matched nothing — same posture as
            # the step-4 fallback, so strict mode must gate it rather than wave it through.
            return EffectClass.READ, False
        tset = set(toks)
        verbs, trailing, head = _verb_tokens(tool_name)

        # Exec effects (shell / code-eval) — severity-5, capability "exec". The verb decides;
        # the shell/interpreter tokens only qualify which of the two labels applies.
        shell_obj = bool(tset & _SHELL_TOKENS)
        code_obj = bool(tset & _INTERPRETER_TOKENS)
        exec_verb = (
            bool(verbs & _EXEC_VERBS_STRONG)
            or trailing in _EXEC_VERBS_TRAILING
            or (bool(verbs & _EXEC_VERBS_WEAK) and (shell_obj or code_obj))
        )
        # A name that is nothing but an interpreter/exec word (`bash`, `python`, `compile`) is a
        # request to run it, as is one that asks for a shell by name (`get_shell`, `open_terminal`).
        bare_exec = len(toks) == 1 and bool(
            tset & (_SHELL_TOKENS | _INTERPRETER_TOKENS | _EXEC_VERBS_WEAK)
        )
        shell_target = trailing in _SHELL_TOKENS
        # Unsafe YAML load (`yaml.load` / `yaml_load` / `load_yaml`) is an RCE deserialization sink,
        # but the safe `yaml.safe_load` must NOT trip — so match yaml+load only when not "safe".
        yaml_unsafe = ("yaml" in tset) and bool(tset & {"load", "loads"}) and ("safe" not in tset)
        if exec_verb or bare_exec or shell_target or (tset & _RCE_TOKENS) or yaml_unsafe:
            if (shell_obj or trailing in _EXEC_VERBS_TRAILING) and not (tset & _RCE_TOKENS):
                return EffectClass.SHELL, True
            # Interpreter namespace (python.exec), a bare exec/eval verb, or an unsafe
            # deserialization sink.
            return EffectClass.CODE_EVAL, True

        # Secret reads: a strong standalone token, a known secret-store token combo, a qualifier +
        # a generic secret noun, or any read of the environment. Checked before the READ-verb
        # fallback so `get_api_key` / `cat_env` are SECRET_READ, not READ. The env branch matches
        # read verbs at the SAME head positions as the fallback, so every env read denies
        # consistently and `environment_report` is not swept in.
        if (
            (tset & _SECRET_STRONG)
            or any(combo <= tset for combo in _SECRET_STORE_COMBOS)
            or ((tset & _SECRET_QUALIFIERS) and (tset & _SECRET_NOUNS))
            or ((tset & _SECRET_ENV_TOKENS)
                and bool(head & (_READ_VERBS | _SECRET_EXTRA_READ_VERBS)))
        ):
            return EffectClass.SECRET_READ, True

        # Memory writes (checked before file writes: "write_memory" is a memory write).
        if (tset & _MEMORY_TOKENS) and (tset & _MEMORY_WRITE_VERBS):
            return EffectClass.MEMORY_WRITE, True

        # File writes.
        if (tset & _FILE_WRITE_STRONG) or ((tset & _FILE_MUTATE_VERBS) and (tset & _FILE_NOUNS)):
            return EffectClass.FILE_WRITE, True

        # Network / external-effect actions.
        if (tset & _NETWORK_STRONG) or (tset & _NETWORK_VERBS):
            return EffectClass.NETWORK, True

        # 3. Read verb in a verb position -> READ.
        #
        # Known residual gap (deliberately not reclassified here): names whose harm lives in the
        # *arguments*, not the name — `sql.query` (a SELECT read vs a DROP), `dns_lookup` (a read
        # vs an exfil channel), `load_and_run` — classify READ. Promoting them by name alone would
        # over-block the common benign read; discriminating them needs argument inspection, which
        # is out of scope for name-based classification. Likewise a plain `read_certificate` stays
        # READ (a public cert is not secret); the private-key/cert BUNDLE forms `pkcs12`/`keystore`
        # are strong secret tokens and deny.
        if head & _READ_VERBS:
            return EffectClass.READ, True

        # 4. Nothing matched. Unrecognized names fall back to READ — the pre-existing posture.
        #    Gating them instead (fail-closed on unrecognized) is NOT viable at this classifier's
        #    coverage: unrecognized is the majority class over realistic tool corpora (~50% of
        #    names: `git_diff`, `create_issue`, `add_comment`), so gating it puts ~75% of untrusted
        #    tool calls in front of a human, and a guard that prompts that often gets turned off.
        #    Widen coverage first, track the unrecognized rate, then gate. See PR #21.
        #    `strict=True` and the `unrecognized` field on every decision record are how a
        #    caller opts into gating, and how they measure the rate before doing so.
        return EffectClass.READ, False

    # -- the policy decision (deterministic, no LLM) ---------------------------
    def _decide(self, effect: EffectClass, provenance: Provenance,
                recognized: bool = True) -> tuple[Decision, str, list[str]]:
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
            # Strict fires for UNTRUSTED only: a trusted call has no attacker in the loop, and
            # the boundary already allows trusted->shell, so gating trusted here would be
            # stricter than the shell rule. Capability denial above still wins.
            if self.strict and not recognized:
                return (Decision.NEEDS_APPROVAL,
                        "unrecognized tool name; strict mode requires approval", violations)
            if effect in _APPROVAL_EFFECTS:
                return (Decision.NEEDS_APPROVAL,
                        f"untrusted-derived {effect.value} effect requires human approval", violations)

        # 3. Trusted input, or low-severity effect.
        return Decision.ALLOW, f"{provenance.value} input into {effect.value} effect", violations

    # -- preview / commit ------------------------------------------------------
    def preview(self, tool_name: str, params: dict,
                values: Iterable[Value] = ()) -> PreviewResult:
        effect, recognized = self._classify(tool_name)
        provs = [v.provenance for v in values]
        if provs:
            provenance = provs[0]
            for p in provs[1:]:
                provenance = provenance.worst(p)
        else:
            provenance = Provenance.UNTRUSTED if self.default_untrusted else Provenance.TRUSTED

        decision, reason, violations = self._decide(effect, provenance, recognized)
        canonical = _canonical(tool_name, params)

        would_decision = None
        if self.mode == "observe":
            # Observe mode reports the truthful verdict but enforces ALLOW, so a token is
            # issued and commit() runs. That is the whole point of the mode, and it is opt-in.
            would_decision = decision
            if decision is not Decision.ALLOW:
                reason = f"observe mode: would {decision.value} — {reason}"
                decision = Decision.ALLOW

        token = None
        if decision is Decision.ALLOW:
            token = hashlib.sha256(canonical.encode()).hexdigest()

        result = PreviewResult(
            tool_name=tool_name, params=params, effect_class=effect, provenance=provenance,
            decision=decision, reason=reason, canonical=canonical,
            commit_token=token, violations=violations,
            would_decision=would_decision, mode=self.mode, unrecognized=not recognized,
        )

        # Local import: jataayu.core.audit imports THIS module at its top level, so a
        # module-level import here is a circular import.
        from jataayu.core.audit import capture_content_enabled, emit_decision

        record = {
            "rail_type": "effect_boundary",
            "tool_name": tool_name,
            "effect_class": effect.value,
            "provenance": provenance.value,
            "decision": result.decision.value,
            "would_decision": (would_decision or result.decision).value,
            "tripwire_triggered": result.tripwire_triggered,
            "mode": self.mode,
            "reason": result.reason,
            "violations": violations,
            "unrecognized": not recognized,
        }
        if capture_content_enabled(self.capture_content):
            record["params"] = params
        emit_decision(record, self.sink)

        return result

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
