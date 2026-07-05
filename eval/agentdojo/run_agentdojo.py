"""
Run AgentDojo with (and without) the Jataayu defense and report the standard
AgentDojo triple: utility under no attack, utility under attack, targeted ASR.

Usage (from the eval venv that has both agentdojo==0.1.35 and jataayu installed):

    python eval/agentdojo/run_agentdojo.py \
        --model gpt-4o-2024-05-13 \
        --suite workspace \
        --attack important_instructions \
        --user-tasks user_task_0 user_task_1 user_task_2 \
        --variants baseline jataayu \
        --out eval/results/agentdojo_workspace_smoke.json

Omit --user-tasks to run the whole suite. The Jataayu defense is deterministic
and LLM-free, so all API cost comes from the agent --model.

Pinned against agentdojo 0.1.35.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx
import openai

from agentdojo.agent_pipeline import (
    AgentPipeline,
    InitQuery,
    PipelineConfig,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.llms.local_llm import LocalLLM
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import (
    aggregate_results,
    benchmark_suite_with_injections,
    benchmark_suite_without_injections,
    get_suite,
)
from agentdojo.logging import OutputLogger

sys.path.insert(0, str(Path(__file__).resolve().parent))
from jataayu_defense import JataayuPIDetector  # noqa: E402

# --- LocalLLM parse fix (AgentDojo 0.1.35) -----------------------------------
# AgentDojo's _parse_model_output does json.loads() on the raw body between
# <function=name> and </function>. Local models produce two body shapes that
# json.loads rejects, dropping the tool call ("[debug] broken JSON: ...") and
# stalling the agent:
#   (1) EMPTY body — Qwen emits a zero-arg call as `<function=get_current_day>
#       </function>`, ignoring the prompt's "include {}" rule. Because the
#       workspace agent's mandated first action is the no-arg get_current_day,
#       EVERY task stalled on step 1 -> uniform 0 utility.
#   (2) TRAILING garbage after a complete JSON object — most often a doubled
#       closing brace (`{...}}`), which invalidates the whole string.
# Fix: normalize an empty body to {}, and when the body doesn't parse, salvage
# the first brace-balanced JSON object (string/escape aware) and use that.
import json as _json  # noqa: E402
import re as _re  # noqa: E402
import agentdojo.agent_pipeline.llms.local_llm as _local_llm  # noqa: E402

_orig_parse = _local_llm._parse_model_output
_EMPTY_FN_CALL = _re.compile(r"(<function\s*=\s*[^>]+>)\s*(</function>)")
_OPEN_FN = _re.compile(r"<function\s*=\s*[^>]+>")


def _balanced_json(s: str) -> str | None:
    """Return the first brace-balanced {...} object in s (respecting strings and
    escapes), or None. Salvages `{...}}`, `{...} trailing text`, etc."""
    start = s.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(s)):
        c = s[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return s[start:i + 1]
    return None


def _parse_model_output_fixed(completion: str):
    fixed = _EMPTY_FN_CALL.sub(r"\1{}\2", completion)
    m = _OPEN_FN.search(fixed)
    if m:
        start = m.end()
        end = fixed.find("</function>", start)
        end = end if end != -1 else len(fixed)
        body = fixed[start:end].strip()
        if body:
            try:
                _json.loads(body)
            except ValueError:
                salvaged = _balanced_json(body)
                if salvaged is not None:
                    fixed = fixed[:start] + salvaged + fixed[end:]
    return _orig_parse(fixed)


_local_llm._parse_model_output = _parse_model_output_fixed


def _make_llm(model: str, model_id: str | None, local_base_url: str | None):
    """Return the agent LLM element. For a hosted model, defer to AgentDojo's
    from_config wiring; for `local`, build a LocalLLM pointed directly at an
    OpenAI-compatible endpoint (e.g. an ollama host on the tailnet) so we don't
    depend on AgentDojo's hardcoded localhost:{port}."""
    if model == "local":
        if not (model_id and local_base_url):
            raise ValueError("--model-id and --local-base-url are required for --model local")
        # OPENAI_API_KEY carries the bearer token for auth'd gateways (e.g. the
        # gateway OAuth gateway); defaults to EMPTY for open local endpoints
        # (ollama). verify=False accepts the gateway's self-signed TLS cert.
        client = openai.OpenAI(
            api_key=os.environ.get("OPENAI_API_KEY", "EMPTY"),
            base_url=local_base_url,
            http_client=httpx.Client(verify=False, timeout=600.0),
        )
        return LocalLLM(client, model_id, tool_delimiter="tool")
    # hosted: let from_config build the provider-correct client, then extract the llm
    cfg_pipe = AgentPipeline.from_config(PipelineConfig(
        llm=model, model_id=None, defense=None,
        system_message_name=None, system_message=None,
    ))
    # the llm is the 3rd element (SystemMessage, InitQuery, llm, ToolsExecutionLoop)
    return cfg_pipe.elements[2]


def _build_pipeline(model, with_jataayu, min_status, model_id=None, local_base_url=None):
    """Assemble the standard AgentDojo pipeline (SystemMessage, InitQuery, llm,
    ToolsExecutionLoop); if with_jataayu, splice the detector into the loop just
    before the agent LLM (AgentDojo's defense position)."""
    llm = _make_llm(model, model_id, local_base_url)
    # resolve the default system message via the config validator
    cfg = PipelineConfig(llm="local", model_id="x", defense=None,
                         system_message_name=None, system_message=None)
    loop_elements = [ToolsExecutor()]
    if with_jataayu:
        loop_elements.append(JataayuPIDetector(min_status=min_status, raise_on_injection=False))
    loop_elements.append(llm)
    pipeline = AgentPipeline([
        SystemMessage(cfg.system_message),
        InitQuery(),
        llm,
        ToolsExecutionLoop(loop_elements),
    ])
    tag = model if model != "local" else f"local:{model_id}"
    pipeline.name = (f"jataayu_{min_status.lower()}_{tag}" if with_jataayu
                     else f"baseline_{tag}")
    return pipeline


def _run_variant(model, suite, attack_name, user_tasks, with_jataayu, min_status, logdir,
                 model_id=None, local_base_url=None, injection_tasks=None):
    pipeline = _build_pipeline(model, with_jataayu, min_status, model_id, local_base_url)

    # AgentDojo's TraceLogger reads logdir from the active Logger context.
    with OutputLogger(str(logdir), live=None):
        util = benchmark_suite_without_injections(
            pipeline, suite, logdir=logdir, force_rerun=True,
            user_tasks=user_tasks or None,
        )
        attack = load_attack(attack_name, suite, pipeline)
        atk = benchmark_suite_with_injections(
            pipeline, suite, attack, logdir=logdir, force_rerun=True,
            user_tasks=user_tasks or None, injection_tasks=injection_tasks or None,
        )
    return {
        "pipeline": pipeline.name,
        "defense": "jataayu" if with_jataayu else "none",
        "utility_no_attack": aggregate_results([util["utility_results"]]),
        "utility_under_attack": aggregate_results([atk["utility_results"]]),
        "attack_success_rate": aggregate_results([atk["security_results"]]),
        "n_utility_cases": len(util["utility_results"]),
        "n_attack_cases": len(atk["security_results"]),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--suite", default="workspace",
                    choices=["workspace", "travel", "banking", "slack"])
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--user-tasks", nargs="*", default=None,
                    help="subset e.g. user_task_0 user_task_1; omit for full suite")
    ap.add_argument("--variants", nargs="+", default=["baseline", "jataayu"],
                    choices=["baseline", "jataayu"])
    ap.add_argument("--min-status", default="HIGH", choices=["HIGH", "MEDIUM"])
    ap.add_argument("--model-id", default=None, help="ollama/vLLM model name when --model local")
    ap.add_argument("--local-base-url", default=None,
                    help="OpenAI-compatible base URL when --model local, e.g. http://dgx-pavan:11434/v1")
    ap.add_argument("--injection-tasks", nargs="*", default=None,
                    help="subset of injection tasks; omit for all")
    ap.add_argument("--logdir", default="./runs/agentdojo")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    suite = get_suite("v1.2.1", args.suite)
    logdir = Path(args.logdir)

    rows = []
    for variant in args.variants:
        print(f"[run] {variant} on {args.suite}/{args.attack} "
              f"({'full suite' if not args.user_tasks else args.user_tasks})", flush=True)
        rows.append(_run_variant(
            args.model, suite, args.attack, args.user_tasks,
            with_jataayu=(variant == "jataayu"),
            min_status=args.min_status, logdir=logdir,
            model_id=args.model_id, local_base_url=args.local_base_url,
            injection_tasks=args.injection_tasks,
        ))

    report = {
        "model": args.model_id if args.model == "local" and args.model_id else args.model,
        "suite": args.suite, "attack": args.attack,
        "user_tasks": args.user_tasks or "ALL",
        "agentdojo_version": "0.1.35", "results": rows,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print("\n=== summary ===")
    for r in rows:
        print(f"{r['defense']:>8}: util(no-atk)={r['utility_no_attack']:.3f} "
              f"util(atk)={r['utility_under_attack']:.3f} ASR={r['attack_success_rate']:.3f}")
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
