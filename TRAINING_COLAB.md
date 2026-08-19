# 🚀 Google Colab Training Notebook: Fine-Tuning CyberSecAI Models

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/)

This guide provides an end-to-end, copy-paste-ready training pipeline to fine-tune open-weights Code LLMs (such as **Qwen2.5-Coder-7B-Instruct** or **DeepSeek-Coder-6.7B**) on the **CyberSecAI Multi-Dataset Stack**:
- 🥇 **PrimeVul (ICSE 2025)**: Core vulnerability detection & CWE localization.
- 🥈 **VulnRepairEval (2025/2026)**: Functional PoC exploit-based patch verification.
- 🥉 **DiverseVul & Zenodo Patches**: Multi-language generalization (Python, JS, Java, PHP, C/C++).
- 🛡️ **CyberFixBench**: Closed-loop platform telemetry (*Detect → Exploit Proof → Unified Patch → Verification*).

---

## Cell 1: Hardware Check & Package Installation

> **Note:** Run on **GPU Runtime** (Free Google Colab **T4**, or Colab Pro **A100 / L4 / V100**).

```python
# 1. Verify GPU
!nvidia-smi

# 2. Install Unsloth for 2x-5x faster QLoRA training & 70% less VRAM usage
!pip install -q "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
!pip install -q --no-deps "xformers<0.0.27" "trl<0.9.0" peft accelerate bitsandbytes
!pip install -q datasets transformers evaluate scikit-learn
```

---

## Cell 2: Load Base Model with 4-bit Quantization

```python
import torch
from unsloth import FastLanguageModel

# Maximum context window (supports long code functions)
max_seq_length = 4096 
dtype = None # Auto detection (Float16 for T4/V100, Bfloat16 for Ampere/A100/L4)
load_in_4bit = True # 4-bit QLoRA for fast training on single GPU

# Recommended Base Models:
# - "unsloth/Qwen2.5-Coder-7B-Instruct-bnb-4bit" (State of the art 2025/2026 code LLM)
# - "unsloth/deepseek-coder-6.7b-instruct-bnb-4bit"
model_name = "unsloth/Qwen2.5-Coder-7B-Instruct-bnb-4bit"

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=model_name,
    max_seq_length=max_seq_length,
    dtype=dtype,
    load_in_4bit=load_in_4bit,
)

print(f"✓ Model {model_name} loaded successfully in 4-bit!")
```

---

## Cell 3: Configure QLoRA Parameter-Efficient Fine-Tuning

```python
model = FastLanguageModel.get_peft_model(
    model,
    r=16, # LoRA rank (16 or 32 for high fidelity)
    target_modules=[
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj"
    ],
    lora_alpha=32,
    lora_dropout=0, # Optimized 0 dropout for Unsloth
    bias="none",
    use_gradient_checkpointing="unsloth", # Reduces VRAM by 60%
    random_state=42,
)

model.print_trainable_parameters()
```

---

## Cell 4: Ingest & Format the CyberSecAI Dataset Stack (PrimeVul & VulnRepairEval)

```python
import json
from datasets import Dataset

# 1. Fetch PrimeVul Curated Instruction Dataset
!git clone https://github.com/stephanas-code/AI-Application-Security-Auditor-Platform.git
!python AI-Application-Security-Auditor-Platform/data_pipeline/dataset_fetcher.py

# 2. Load the processed ChatML JSONL training sets
def load_jsonl(filepath):
    data = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                data.append(json.loads(line))
    return data

detection_samples = load_jsonl("AI-Application-Security-Auditor-Platform/datasets/processed/train_detection_chatml.jsonl")
remediation_samples = load_jsonl("AI-Application-Security-Auditor-Platform/datasets/processed/train_remediation_chatml.jsonl")

# Combine multi-task training sets
all_training_samples = detection_samples + remediation_samples
print(f"✓ Ingested {len(all_training_samples)} multi-task security training samples.")

# Format with ChatML / Tokenizer Chat Template
def format_chatml_prompts(batch):
    texts = []
    for messages in batch["messages"]:
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
        texts.append(text)
    return {"text": texts}

dataset = Dataset.from_list(all_training_samples)
dataset = dataset.map(format_chatml_prompts, batched=True)
print("Sample Tokenized Prompt:\n", dataset[0]["text"][:400], "...")
```

---

## Cell 5: Launch Supervised Fine-Tuning (SFTTrainer)

```python
from trl import SFTTrainer
from transformers import TrainingArguments

trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset,
    dataset_text_field="text",
    max_seq_length=max_seq_length,
    dataset_num_proc=2,
    packing=False, # Can be True for faster short sequence training
    args=TrainingArguments(
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        warmup_steps=10,
        max_steps=120, # Increase to 500-1000 for full production epoch
        learning_rate=2e-4,
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        logging_steps=10,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        seed=42,
        output_dir="cybersec_qwen_checkpoints",
    ),
)

print("🚀 Starting Fine-Tuning on CyberSecAI Multi-Dataset Stack...")
trainer_stats = trainer.train()
print(f"✓ Training Complete in {trainer_stats.metrics['train_runtime']:.2f}s!")
```

---

## Cell 6: Benchmark & Evaluate on Unseen Code (PrimeVul & VulnRepairEval)

```python
FastLanguageModel.for_inference(model) # 2x faster inference

test_code = """
def authenticate_user(username, password_raw):
    # Authenticate via SQL database
    sql_query = "SELECT * FROM users WHERE username = '" + username + "' AND pass = '" + password_raw + "'"
    cursor = db.cursor()
    cursor.execute(sql_query)
    user = cursor.fetchone()
    return user
"""

messages = [
    {"role": "system", "content": "You are an expert Application Security (AppSec) Static Analysis & Vulnerability Detection Model."},
    {"role": "user", "content": f"Perform deep static security analysis on the following python function.\nDetermine if it contains security vulnerabilities. If vulnerable, identify the CWE, root cause, and line numbers.\n\n```python\n{test_code}\n```"}
]

inputs = tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=True, return_tensors="pt").to("cuda")

outputs = model.generate(input_ids=inputs, max_new_tokens=512, use_cache=True, temperature=0.1)
response = tokenizer.batch_decode(outputs)

print("\n--- AI Model Vulnerability Analysis Output ---")
print(response[0].split("<|im_start|>assistant")[-1].replace("<|im_end|>", ""))
```

---

## Cell 7: Export Model for Local Deployment in the AppSec Platform

```python
# 1. Export as GGUF for local Ollama / llama.cpp deployment (Q4_K_M)
model.save_pretrained_gguf("cybersec_ai_model_gguf", tokenizer, quantization_method="q4_k_m")
print("✓ GGUF model exported to 'cybersec_ai_model_gguf/'")

# 2. Push to Hugging Face Hub (Optional)
# model.push_to_hub_merged("your_username/CyberSecAI-Qwen2.5-7B", tokenizer, save_method="merged_16bit")
```

---

## 🎯 How to use this fine-tuned model in your Platform:
1. Copy the exported `cybersec_ai_model_gguf` file to your server.
2. In your platform root, create an Ollama Modelfile or serve via `llama-server`:
   ```bash
   ollama create cybersec-ai -f Modelfile
   ```
3. Set your platform environment:
   ```env
   LOCAL_AI_ENDPOINT="http://localhost:11434/api/generate"
   ```
