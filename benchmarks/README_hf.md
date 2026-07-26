# HF eval venv (`benchmarks/.venv-hf`)

Dedicated, CPU-only virtualenv for the Hugging Face dataset runners in `benchmarks/`.
Separate from `benchmarks/.venv` (which carries the AgentDojo stack). The inbound and
outbound fast paths are pure regex/CPU, so **torch and transformers are
deliberately not installed** — none of the runners below need them.

## Build

```bash
cd /home/user/projects/jataayu
python3 -m venv benchmarks/.venv-hf
benchmarks/.venv-hf/bin/pip install --upgrade pip
benchmarks/.venv-hf/bin/pip install datasets scikit-learn numpy huggingface_hub
benchmarks/.venv-hf/bin/pip install -e .          # editable jataayu
```

## Activate

```bash
source benchmarks/.venv-hf/bin/activate
# or invoke directly without activating:
benchmarks/.venv-hf/bin/python benchmarks/run_injection_bench.py --dataset deepset/prompt-injections
```

## Runners

Fast-path inbound injection sweep (writes `benchmarks/results/<dataset>_<surface>_fastpath.json`):

```bash
for ds in deepset/prompt-injections xTRam1/safe-guard-prompt-injection \
          jackhhao/jailbreak-classification reshabhs/SPML_Chatbot_Prompt_Injection \
          Lakera/gandalf_ignore_instructions allenai/wildjailbreak \
          hackaprompt/hackaprompt-dataset; do
  benchmarks/.venv-hf/bin/python benchmarks/run_injection_bench.py --dataset "$ds" --surface unknown
done
```

`allenai/wildjailbreak` (config `eval`) and `hackaprompt/hackaprompt-dataset` are
gated — they require access approval + `huggingface-cli login` (already granted for
this checkout). Gandalf and hackaprompt are **all-positive** (injection-only), so
their JSON reports recall only; ROC/PR-AUC are `null`.

Leave-One-Dataset-Out honesty artifact (writes `benchmarks/results/lodo_fastpath.json`):

```bash
benchmarks/.venv-hf/bin/python benchmarks/run_lodo_fastpath.py --surface unknown
```

Outbound PII bench, gretelai primary (writes the `--out` JSON):

```bash
benchmarks/.venv-hf/bin/python benchmarks/run_outbound_privacy_bench.py \
  --source gretelai --hf-limit 400 --surface public \
  --out benchmarks/results/outbound_privacy_gretelai.json
```

## Gated datasets (need access approval + login)

`hackaprompt/hackaprompt-dataset` and `allenai/wildjailbreak` are **gated** on the
Hub. The runners skip them with a recorded reason rather than blocking the sweep.
To include them, request access on each dataset page, then:

```bash
benchmarks/.venv-hf/bin/huggingface-cli login
```

`allenai/wildjailbreak` is ODC-BY and additionally requires attribution
(Jiang et al., WildTeaming, 2024) in any published results.
