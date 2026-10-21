
#### prompt

| system (prompt, n=1234, 418 pos / 816 neg) | precision | recall | F1 | FPR | TP/FP/FN/TN |
|---|---|---|---|---|---|
| rules only (any hit) | 100.0% [100.0, 100.0] | 20.8% [16.6, 25.1] | 34.5% [28.4, 40.1] | 0.0% [0.0, 0.0] | 87/0/331/816 |
| rules only (block-severity hits) | 100.0% [100.0, 100.0] | 20.6% [16.5, 24.9] | 34.1% [28.3, 39.9] | 0.0% [0.0, 0.0] | 86/0/332/816 |
| Laya only @ shipped threshold 0.90 (t=0.900) | 79.7% [75.5, 83.7] | 76.8% [72.4, 80.8] | 78.2% [74.5, 81.2] | 10.1% [8.0, 12.1] | 321/82/97/734 |
| Laya only @ dev recall-at-1%-FPR threshold (t=0.994) | 98.3% [96.5, 99.6] | 56.2% [50.6, 61.4] | 71.5% [66.8, 75.7] | 0.5% [0.1, 1.0] | 235/4/183/812 |
| rules OR Laya @ 0.90 (t=0.900) | 80.3% [76.3, 84.2] | 80.1% [75.9, 83.9] | 80.2% [76.7, 83.2] | 10.1% [8.0, 12.1] | 335/82/83/734 |
| rules OR Laya @ dev 1%-FPR threshold (t=0.994) | 98.5% [96.8, 99.7] | 61.7% [56.3, 66.7] | 75.9% [71.7, 79.5] | 0.5% [0.1, 1.0] | 258/4/160/812 |
| rules OR Laya @ dev combined-1%-FPR threshold (t=0.994) | 98.5% [96.8, 99.7] | 61.7% [56.3, 66.7] | 75.9% [71.7, 79.5] | 0.5% [0.1, 1.0] | 258/4/160/812 |

Laya risk score ranking: AUROC 0.901 [0.8806, 0.921], AP 0.881 [0.8526, 0.9055]; mean score positives 0.8645, negatives 0.3265.

| question variant | AUROC | AP | recall@1%FPR (this split) |
|---|---|---|---|
| shipped_jailbreak | 0.873 | 0.793 | 0.000 |
| shipped_prompt_injection | 0.879 | 0.786 | 0.000 |
| c_attack | 0.826 | 0.746 | 0.227 |
| c_attack_ab | 0.807 | 0.703 | 0.158 |
| c_persona | 0.901 | 0.881 | 0.598 |
| c_control | 0.818 | 0.799 | 0.478 |

Per-source breakdown (Laya threshold 0.9943):

| source / class | n | rules flag | Laya flag | combined flag |
|---|---|---|---|---|
| deepset/prompt-injections | neg:benign_general | 202 | 0 | 0 | 0 |
| deepset/prompt-injections | pos:injection | 140 | 21 | 33 | 49 |
| jackhhao/jailbreak-classification | neg:benign_general | 140 | 0 | 3 | 3 |
| jackhhao/jailbreak-classification | pos:jailbreak | 135 | 37 | 128 | 129 |
| sahil2801/CodeAlpaca-20k | neg:benign_coding | 219 | 0 | 0 | 0 |
| synthetic/prompts | neg:benign_coding_agent | 22 | 0 | 0 | 0 |
| synthetic/prompts | neg:benign_coding_hard | 24 | 0 | 0 | 0 |
| xTRam1/safe-guard-prompt-injection | neg:benign_general | 209 | 0 | 1 | 1 |
| xTRam1/safe-guard-prompt-injection | pos:injection | 143 | 29 | 74 | 80 |

#### tool_output

| system (tool_output, n=267, 151 pos / 116 neg) | precision | recall | F1 | FPR | TP/FP/FN/TN |
|---|---|---|---|---|---|
| rules only (any hit) | 90.5% [82.7, 97.0] | 37.8% [31.3, 44.2] | 53.3% [46.2, 59.8] | 5.2% [1.7, 9.5] | 57/6/94/110 |
| rules only (block-severity hits) | 88.7% [79.6, 96.3] | 31.1% [25.8, 36.0] | 46.1% [39.8, 51.6] | 5.2% [1.7, 9.5] | 47/6/104/110 |
| Laya only @ shipped threshold 0.90 (t=0.900) | 54.5% [45.6, 61.9] | 52.3% [41.4, 63.6] | 53.4% [44.4, 61.1] | 56.9% [47.4, 64.7] | 79/66/72/50 |
| Laya only @ dev recall-at-1%-FPR threshold (t=1.000) | - | 0.0% [0.0, 0.0] | 0.0% [0.0, 0.0] | 0.0% [0.0, 0.0] | 0/0/151/116 |
| rules OR Laya @ 0.90 (t=0.900) | 60.2% [52.9, 66.7] | 68.2% [60.1, 75.2] | 64.0% [57.8, 68.6] | 58.6% [49.1, 66.4] | 103/68/48/48 |
| rules OR Laya @ dev 1%-FPR threshold (t=1.000) | 90.5% [82.7, 97.0] | 37.8% [31.3, 44.2] | 53.3% [46.2, 59.8] | 5.2% [1.7, 9.5] | 57/6/94/110 |
| rules OR Laya @ dev combined-1%-FPR threshold (t=1.000) | 90.5% [82.7, 97.0] | 37.8% [31.3, 44.2] | 53.3% [46.2, 59.8] | 5.2% [1.7, 9.5] | 57/6/94/110 |

Laya risk score ranking: AUROC 0.509 [0.4532, 0.5768], AP 0.583 [0.5027, 0.6669]; mean score positives 0.7719, negatives 0.7491.

| question variant | AUROC | AP | recall@1%FPR (this split) |
|---|---|---|---|
| shipped_agent_directed | 0.489 | 0.576 | 0.000 |
| shipped_jailbreak | 0.525 | 0.597 | 0.000 |
| c_hidden | 0.494 | 0.579 | 0.000 |
| c_hidden_ab | 0.487 | 0.565 | 0.000 |
| c_hijack | 0.470 | 0.548 | 0.000 |
| c_override | 0.509 | 0.583 | 0.000 |

Per-source breakdown (Laya threshold 1.0):

| source / class | n | rules flag | Laya flag | combined flag |
|---|---|---|---|---|
| local/python-package-READMEs | neg:benign_real_readme | 53 | 1 | 0 | 1 |
| synthetic/tool_output | neg:benign_apidocs | 4 | 0 | 0 | 0 |
| synthetic/tool_output | neg:benign_changelog | 4 | 0 | 0 | 0 |
| synthetic/tool_output | neg:benign_code | 7 | 0 | 0 | 0 |
| synthetic/tool_output | neg:benign_email | 2 | 0 | 0 | 0 |
| synthetic/tool_output | neg:benign_forum | 6 | 0 | 0 | 0 |
| synthetic/tool_output | neg:benign_html | 3 | 0 | 0 | 0 |
| synthetic/tool_output | neg:benign_issue | 2 | 0 | 0 | 0 |
| synthetic/tool_output | neg:benign_json | 3 | 0 | 0 | 0 |
| synthetic/tool_output | neg:benign_log | 3 | 0 | 0 | 0 |
| synthetic/tool_output | neg:benign_notes | 7 | 0 | 0 | 0 |
| synthetic/tool_output | neg:benign_readme | 3 | 0 | 0 | 0 |
| synthetic/tool_output | neg:benign_yaml | 4 | 0 | 0 | 0 |
| synthetic/tool_output | neg:legit_imperative | 8 | 1 | 0 | 1 |
| synthetic/tool_output | neg:quotes_injection | 7 | 4 | 0 | 4 |
| synthetic/tool_output | pos:explicit | 48 | 35 | 0 | 35 |
| synthetic/tool_output | pos:multilingual | 48 | 14 | 0 | 14 |
| synthetic/tool_output | pos:obfuscated | 7 | 4 | 0 | 4 |
| synthetic/tool_output | pos:paraphrase | 48 | 4 | 0 | 4 |

#### command

| system (command, n=577, 108 pos / 469 neg) | precision | recall | F1 | FPR | TP/FP/FN/TN |
|---|---|---|---|---|---|
| rules only (any hit) | 98.4% [94.5, 100.0] | 58.3% [47.9, 67.6] | 73.3% [64.4, 80.2] | 0.2% [0.0, 0.7] | 63/1/45/468 |
| rules only (block-severity hits) | 100.0% [100.0, 100.0] | 42.6% [31.8, 53.0] | 59.7% [48.3, 69.3] | 0.0% [0.0, 0.0] | 46/0/62/469 |

| question variant | AUROC | AP | recall@1%FPR (this split) |
|---|---|---|---|
| c_destructive | 0.803 | 0.470 | 0.056 |
| c_destructive_ab | 0.772 | 0.428 | 0.018 |
| c_scope | 0.775 | 0.392 | 0.009 |

#### output

| system (output, n=182, 91 pos / 91 neg) | precision | recall | F1 | FPR | TP/FP/FN/TN |
|---|---|---|---|---|---|
| rules only (any hit) | 100.0% [100.0, 100.0] | 61.5% [33.3, 87.5] | 76.2% [50.0, 93.3] | 0.0% [0.0, 0.0] | 56/0/35/91 |
| rules only (block-severity hits) | 100.0% [100.0, 100.0] | 38.5% [9.1, 66.7] | 55.6% [16.7, 80.0] | 0.0% [0.0, 0.0] | 35/0/56/91 |
| Laya only @ shipped threshold 0.90 (t=0.900) | 94.6% [81.8, 100.0] | 38.5% [23.4, 54.3] | 54.7% [37.4, 69.2] | 2.2% [0.0, 5.6] | 35/2/56/89 |
| Laya only @ dev recall-at-1%-FPR threshold (t=0.921) | 96.4% [85.0, 100.0] | 29.7% [16.1, 44.4] | 45.4% [27.7, 61.0] | 1.1% [0.0, 3.4] | 27/1/64/90 |
| rules OR Laya @ 0.90 (t=0.900) | 97.2% [90.6, 100.0] | 75.8% [54.5, 94.5] | 85.2% [69.0, 96.3] | 2.2% [0.0, 5.6] | 69/2/22/89 |
| rules OR Laya @ dev 1%-FPR threshold (t=0.921) | 98.5% [93.8, 100.0] | 73.6% [51.8, 92.9] | 84.3% [67.4, 95.9] | 1.1% [0.0, 3.4] | 67/1/24/90 |
| rules OR Laya @ dev combined-1%-FPR threshold (t=0.921) | 98.5% [93.8, 100.0] | 73.6% [51.8, 92.9] | 84.3% [67.4, 95.9] | 1.1% [0.0, 3.4] | 67/1/24/90 |

Laya risk score ranking: AUROC 0.915 [0.8706, 0.9567], AP 0.915 [0.8197, 0.9592]; mean score positives 0.7702, negatives 0.251.

| question variant | AUROC | AP | recall@1%FPR (this split) |
|---|---|---|---|
| shipped_sensitive_data | 0.915 | 0.915 | 0.297 |
| c_secret | 0.854 | 0.834 | 0.000 |
| c_secret_ab | 0.924 | 0.930 | 0.407 |
| c_secret_value | 0.824 | 0.826 | 0.286 |

Per-source breakdown (Laya threshold 0.9214):

| source / class | n | rules flag | Laya flag | combined flag |
|---|---|---|---|---|
| synthetic/secrets | neg:notsecret_b64_blob | 2 | 0 | 0 | 0 |
| synthetic/secrets | neg:notsecret_build_id | 4 | 0 | 0 | 0 |
| synthetic/secrets | neg:notsecret_color_css | 4 | 0 | 0 | 0 |
| synthetic/secrets | neg:notsecret_git_sha | 15 | 0 | 0 | 0 |
| synthetic/secrets | neg:notsecret_ids | 3 | 0 | 0 | 0 |
| synthetic/secrets | neg:notsecret_integrity | 6 | 0 | 0 | 0 |
| synthetic/secrets | neg:notsecret_lock_hash | 7 | 0 | 0 | 0 |
| synthetic/secrets | neg:notsecret_placeholder | 4 | 0 | 1 | 1 |
| synthetic/secrets | neg:notsecret_prose | 9 | 0 | 0 | 0 |
| synthetic/secrets | neg:notsecret_sha256 | 13 | 0 | 0 | 0 |
| synthetic/secrets | neg:notsecret_short_sha | 3 | 0 | 0 | 0 |
| synthetic/secrets | neg:notsecret_uuid | 11 | 0 | 0 | 0 |
| synthetic/secrets | neg:notsecret_vocab | 10 | 0 | 0 | 0 |
| synthetic/secrets | pos:anthropic_key | 7 | 7 | 4 | 7 |
| synthetic/secrets | pos:aws_access_key | 7 | 7 | 3 | 7 |
| synthetic/secrets | pos:aws_secret_key | 7 | 7 | 0 | 7 |
| synthetic/secrets | pos:bearer | 7 | 0 | 6 | 6 |
| synthetic/secrets | pos:datadog_key | 7 | 7 | 1 | 7 |
| synthetic/secrets | pos:github_fine | 7 | 7 | 1 | 7 |
| synthetic/secrets | pos:github_pat | 7 | 7 | 1 | 7 |
| synthetic/secrets | pos:hf_token | 7 | 0 | 0 | 0 |
| synthetic/secrets | pos:jwt | 7 | 7 | 1 | 7 |
| synthetic/secrets | pos:pem_private_key | 7 | 7 | 5 | 7 |
| synthetic/secrets | pos:stripe_live | 7 | 0 | 2 | 2 |
| synthetic/secrets | pos:stripe_restricted | 7 | 0 | 1 | 1 |
| synthetic/secrets | pos:twilio_sk | 7 | 0 | 2 | 2 |
