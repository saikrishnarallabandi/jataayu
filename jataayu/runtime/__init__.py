"""Versioned, host-independent requests for native agent adapters."""

import hashlib
import json
from pathlib import Path

from jataayu import (
    __version__,
    jataayu_authorize_action,
    jataayu_check_inbound,
    jataayu_check_outbound,
    jataayu_check_tool_return,
    jataayu_check_memory_read,
    jataayu_recover_outbound,
    jataayu_vet_skill,
)

SCHEMA_VERSION = 1
# Host aliases carry effects here, never independently in JavaScript/Python adapters.
TOOL_EFFECTS = {
    "apply_patch": "file_write",
    "write": "file_write",
    "edit": "file_write",
    "sessions_send": "network",
    "terminal": "shell",
    "memory_get": "read",
    "memory_search": "read",
}
MEMORY_TOOLS = {"memory_search", "memory_get"}


def fingerprint():
    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    for file in sorted(root.rglob("*.py")):
        digest.update(str(file.relative_to(root)).encode())
        digest.update(file.read_bytes())
    return digest.hexdigest()


FINGERPRINT = fingerprint()


def dispatch(request):
    """Only adapter-owned inputs enter here; the model cannot select policy/trust."""
    if not isinstance(request, dict) or request.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported adapter request schema")
    op = request.get("operation")
    config = request.get("config", {})
    if not isinstance(config, dict):
        raise ValueError("config must be an object")
    content = request.get("content", "")
    if not isinstance(content, str):
        raise ValueError("content must be text")
    policy = {"policy_file": config.get("policyFile"), "agent": config.get("agent")}
    surface = request.get("surface", "unknown")
    if not isinstance(surface, str):
        raise ValueError("surface must be text")
    if op == "health":
        result = {"status": "ready"}
    elif op == "authorize":
        origins = request.get("origins", [])
        if not isinstance(origins, list) or any(not isinstance(x, str) for x in origins):
            raise ValueError("origins must be a list of host-attributed source labels")
        untrusted = not origins or any(x not in ("owner", "system") for x in origins)
        result = jataayu_authorize_action(
            request["tool_name"],
            request["params"],
            untrusted=untrusted,
            **policy,
            strict=True,
            include_metadata=True,
            tool_effects={**TOOL_EFFECTS, **config.get("toolEffects", {})},
        )
        # Receipt metadata contains no action arguments, free-text findings or tokens.
        configured = {str(k).strip().lower() for k in config.get("toolEffects", {})}
        name = request["tool_name"].strip().lower()
        if name in configured:
            source = "configured_inventory"
        elif name in TOOL_EFFECTS:
            source = "adapter_inventory"
        elif result["classification_source"] == "unknown":
            source = "unknown"
        else:
            source = (
                "policy_inventory" if result["classification_source"] == "inventory" else "builtin"
            )
        result["classification_source"] = source
        result["reason_code"] = (
            "unknown_tool"
            if source == "unknown"
            else "policy_violation"
            if result.get("violations")
            else "untrusted_effect"
            if untrusted and result["decision"] != "allow"
            else "authorized"
        )
        policy_hash = hashlib.sha256()
        policy_hash.update(
            json.dumps(
                {
                    "agent": config.get("agent"),
                    "tool_effects": config.get("toolEffects", {}),
                    "strict": True,
                },
                sort_keys=True,
            ).encode()
        )
        if config.get("policyFile"):
            policy_hash.update(Path(config["policyFile"]).read_bytes())
        result["policy_fingerprint"] = policy_hash.hexdigest()
    elif op in ("inbound", "tool_return"):
        if op == "inbound":
            result = jataayu_check_inbound(content, surface=surface)
        elif request.get("tool_name") in MEMORY_TOOLS | set(config.get("memoryTools", [])):
            result = jataayu_check_memory_read(content)
        else:
            result = jataayu_check_tool_return(content, tool_name=request.get("tool_name"))
    elif op in ("outbound", "recover"):
        names = config.get("protectedNames", [])
        if surface in ("whatsapp-group", "group-chat", "discord-channel"):
            names = config.get("strictProtectedNames", names)
        if op == "outbound":
            result = jataayu_check_outbound(content, surface, protected_names=names, **policy)
        else:
            result = jataayu_recover_outbound(
                content,
                surface,
                protected_names=names,
                **policy,
                use_llm=config.get("recoverUseLlm", False),
                max_attempts=config.get("recoverAttempts", 2),
                llm_backend=config.get("llmBackend"),
                llm_model=config.get("llmModel"),
                llm_url=config.get("llmUrl"),
                llm_token=config.get("llmToken"),
            )
    elif op == "vet":
        result = jataayu_vet_skill(request["source_path"], name=request.get("name"), use_llm=False)
    else:
        raise ValueError("Unknown adapter operation")
    return {
        "schema_version": SCHEMA_VERSION,
        "core_version": __version__,
        "core_fingerprint": FINGERPRINT,
        "result": result,
    }
