"""Probe candidate HF dataset IDs: which load, their splits/columns, a sample row.
Run with eval/.venv-hf python. Network-dependent; logs failures, never raises."""

import sys
import json
from datasets import load_dataset

CANDIDATES = [
    # (hf_id, config)  -- indirect
    ("MAlmasabi/BIPIA-GPT", None),
    ("microsoft/llmail-inject-challenge", None),
    ("nvidia/Nemotron-IPI", None),
    ("prodnull/CloneGuard", None),
    ("uiuc-kang-lab/InjecAgent", None),
    # direct
    ("hackaprompt/hackaprompt-dataset", None),
    ("reshabhs/SPML_Chatbot_Prompt_Injection", None),
    ("xTRam1/safe-guard-prompt-injection", None),
    ("jackhhao/jailbreak-classification", None),
    ("deepset/prompt-injections", None),
    ("Lakera/gandalf_ignore_instructions", None),
    ("yahma/prompt-injections", None),
]


def probe(hf_id, config):
    try:
        # streaming first to avoid full download
        ds = load_dataset(hf_id, config, streaming=True)
        splits = list(ds.keys())
        first_split = splits[0]
        it = iter(ds[first_split])
        row = next(it)
        cols = list(row.keys())
        sample = {k: (str(v)[:120]) for k, v in row.items()}
        print(
            json.dumps(
                {
                    "id": hf_id,
                    "config": config,
                    "ok": True,
                    "splits": splits,
                    "columns": cols,
                    "sample": sample,
                }
            )
        )
    except Exception as e:
        print(
            json.dumps(
                {
                    "id": hf_id,
                    "config": config,
                    "ok": False,
                    "err": f"{type(e).__name__}: {str(e)[:200]}",
                }
            )
        )


if __name__ == "__main__":
    for hf_id, cfg in CANDIDATES:
        probe(hf_id, cfg)
        sys.stdout.flush()
