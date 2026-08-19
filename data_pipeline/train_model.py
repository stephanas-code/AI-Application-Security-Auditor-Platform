#!/usr/bin/env python3
"""
==============================================================================
CyberSecAI Model Training Runner (Local / GPU Cluster)
==============================================================================
Fine-tunes Code LLMs on PrimeVul, VulnRepairEval, and CyberFixBench datasets
using Hugging Face TRL & PEFT (QLoRA).
"""

import os
import sys
import json
import argparse
import torch

def main():
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="Train CyberSecAI Vulnerability & Remediation Model")
    parser.add_argument("--model-name", type=str, default="Qwen/Qwen2.5-Coder-7B-Instruct", help="Base model identifier")
    parser.add_argument("--data-path", type=str, default="datasets/processed/train_detection_chatml.jsonl", help="Training JSONL path")
    parser.add_argument("--output-dir", type=str, default="checkpoints/cybersec_ai_v1", help="Output directory")
    parser.add_argument("--epochs", type=int, default=3, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=2, help="Per-device batch size")
    parser.add_argument("--learning-rate", type=float, default=2e-4, help="Learning rate")
    args = parser.parse_args()

    print("\n====================================================================")
    print("🚀 CyberSecAI Model Training Pipeline")
    print("====================================================================")
    print(f"Base Model:    {args.model_name}")
    print(f"Dataset Path:  {args.data_path}")
    print(f"Output Path:   {args.output_dir}")
    print(f"CUDA Available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"GPU Device:    {torch.cuda.get_device_name(0)}")
    print("--------------------------------------------------------------------\n")

    if not os.path.exists(args.data_path):
        print(f"[!] Dataset not found at {args.data_path}. Running dataset fetcher first...")
        from dataset_fetcher import main as fetch_main
        fetch_main()

    print("[*] Ready for fine-tuning. For fast 1-click cloud GPU training, use TRAINING_COLAB.md")


if __name__ == "__main__":
    main()
