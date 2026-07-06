#!/bin/bash
# Run on the vast.ai instance: install deps + pre-download Qwen3-8B.
set -e
pip install -q -U transformers peft trl datasets accelerate bitsandbytes wandb scikit-learn
python3 -c "
from huggingface_hub import snapshot_download
snapshot_download('Qwen/Qwen3-8B', ignore_patterns=['*.pth','*.gguf'])
print('model cached')
"
python3 -c "import torch,transformers,peft,trl,bitsandbytes as bnb; print('torch',torch.__version__,'cuda',torch.cuda.is_available(),torch.cuda.get_device_name(0),'| bnb',bnb.__version__)"
echo BOOTSTRAP_DONE
