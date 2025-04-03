---
license: apache-2.0
size_categories:
- n<1K
dataset_info:
  features:
  - name: messages
    list:
    - name: content
      dtype: string
    - name: role
      dtype: string
  splits:
  - name: train
    num_bytes: 1960367
    num_examples: 201
  download_size: 540262
  dataset_size: 1960367
configs:
- config_name: default
  data_files:
  - split: train
    path: data/train-*
---


More details on how one can fine-tune a model using this dataset are available on our [blog](https://www.patched.codes/blog/a-comparative-study-of-fine-tuning-gpt-4o-mini-gemini-flash-1-5-and-llama-3-1-8b).

You can also use the [static analysis eval](https://huggingface.co/datasets/patched-codes/static-analysis-eval) as an evaluation benchmark for the fine-tuned models.