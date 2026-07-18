---
title: Jataayu Prompt-Injection Detector
emoji: 🛡️
colorFrom: red
colorTo: indigo
sdk: gradio
sdk_version: 6.20.0
app_file: app.py
pinned: false
---

# Jataayu Prompt-Injection Detector

Interactive demo for [srallaba/Jataayu.promptinjection.v0.1](https://huggingface.co/srallaba/Jataayu.promptinjection.v0.1)
— a LoRA adapter on `Qwen/Qwen3.5-0.8B` that detects prompt-injection and jailbreak attacks in
text that is about to be fed to an AI agent.

Paste text an agent might receive; the demo returns a continuous **`P(INJECTION)`** score read as
the two-class softmax over the model's first verdict token (`INJECTION` vs `BENIGN`):

```
score = softmax([logit_INJECTION, logit_BENIGN])[INJECTION]
```

## Intended use

This is a **defence-in-depth suspicion signal, not a sole control.** A high score is a reason to
sandbox, strip, or escalate a piece of text before an agent acts on it. A low score is not a
safety guarantee — do not use it as the only thing standing between untrusted text and a
privileged action.

## Notes

- The judge framing in `app.py` is byte-identical to the model's training/eval prompt. Changing it
  changes the scores — an earlier reworded reconstruction scored 0.96 where the real framing
  scores ~1.00 on the same weights.
- Runs in fp32 on ZeroGPU: the forward pass is wrapped in `@spaces.GPU`, which is where the GPU is
  actually allocated; everything outside it is CPU-only. fp32 is kept deliberately — the published
  scores were measured at fp32 and dtype changes can shift them.
- `transformers` is pinned to 5.14.1, the first stable line that ships the Qwen3.5 (`qwen3_5`)
  architecture. Older 4.57.x raises `KeyError: 'qwen3_5'`.
