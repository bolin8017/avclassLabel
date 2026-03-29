# AVClass Label

> Batch-label malware families from VirusTotal JSON reports using AVClass.

[![CI](https://github.com/bolin8017/avclassLabel/actions/workflows/ci.yml/badge.svg)](https://github.com/bolin8017/avclassLabel/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## 專案介紹

在惡意程式研究中，研究人員經常需要將大量 VirusTotal 掃描報告轉換為標準化的惡意程式家族標籤。手動逐一處理不僅耗時，且容易出錯。

**AVClass Label** 是一款命令列工具，能夠批次處理整個資料夾（含子資料夾）中的 VirusTotal JSON 報告，透過 [AVClass](https://github.com/malicialab/avclass) 引擎自動產生惡意程式家族分類標籤，並將結果整合輸出為 CSV 檔案，適用於大規模惡意程式資料集的前處理工作。

## 功能特色

- **遞迴掃描** -- 自動遍歷輸入資料夾及所有子資料夾中的 JSON 報告
- **多執行緒處理** -- 使用 `ThreadPoolExecutor` 並行處理，大幅縮短標註時間
- **即時進度顯示** -- 透過 `tqdm` 進度條即時呈現檔案掃描與標註進度
- **CSV 輸出** -- 產生 `fileName,label` 格式的 CSV 檔，方便後續分析
- **錯誤容忍** -- 自動處理格式錯誤的 JSON 檔案與子程序執行異常，不中斷整體流程
- **暫存檔清理** -- 處理過程中產生的暫存檔案會自動清除，保持工作目錄整潔

## 安裝方式

### 前置需求

- Python >= 3.10
- [AVClass](https://github.com/malicialab/avclass) (`avclass` 指令需可在 PATH 中執行)

### 從原始碼安裝

```bash
git clone https://github.com/bolin8017/avclassLabel.git
cd avclassLabel
pip install .
```

### 安裝開發版本（含測試與 lint 工具）

```bash
pip install -e ".[dev]"
```

### 從 Git 直接安裝

```bash
pip install git+https://github.com/bolin8017/avclassLabel.git
```

## 使用方法

### 基本用法

```bash
avclass-label -i /path/to/vt-reports
```

### CLI 參數

| 參數 | 簡寫 | 說明 | 預設值 |
|------|------|------|--------|
| `--input_folder` | `-i` | VirusTotal JSON 報告所在的資料夾路徑（必填） | -- |
| `--max-workers` | `-w` | 平行處理的最大執行緒數量 | `min(32, CPU 核心數 + 4)` |
| `--verbose` | `-v` | 啟用 DEBUG 層級日誌輸出 | 關閉 |

### 完整範例

```bash
# 標註單一資料夾中的報告
avclass-label -i ./dataset/reports

# 使用完整參數名稱
avclass-label --input_folder ./dataset/reports

# 限制為 4 個執行緒
avclass-label -i ./dataset/reports -w 4

# 啟用詳細日誌
avclass-label -i ./dataset/reports -v

# 組合使用：限制執行緒數並啟用詳細日誌
avclass-label -i ./dataset/reports -w 4 -v

# 透過 Python 模組方式執行
python -m avclass_label -i ./dataset/reports
```

### 執行輸出

```
INFO: Found 1200 JSON files.
Labeling: 100%|█████████████████████████| 1200/1200 [02:15<00:00, 8.87file/s]
INFO: Labeled 1200 files in 135.42 seconds.
INFO: Output label.csv path: /absolute/path/to/dataset/reports/label.csv
```

## 輸出格式

工具會在輸入資料夾下產生 `label.csv` 檔案，格式如下：

```csv
fileName,label
0a1b2c3d4e5f,wannacry
1b2c3d4e5f6a,emotet
2c3d4e5f6a7b,trickbot
3d4e5f6a7b8c,Error
```

| 欄位 | 說明 |
|------|------|
| `fileName` | JSON 報告的檔案名稱（不含 `.json` 副檔名） |
| `label` | AVClass 辨識出的惡意程式家族名稱；若處理失敗則標記為 `Error` |

結果會依照 `fileName` 進行字母排序。

## 技術架構

重構後的專案採用模組化設計：

```
src/avclass_label/
├── __init__.py      # 套件初始化與版本資訊
├── __main__.py      # 支援 python -m avclass_label 執行進入點
├── cli.py           # 命令列介面：引數解析與主流程入口
├── config.py        # 組態管理：輸入路徑、輸出路徑等設定
└── labeler.py       # 核心邏輯：JSON 處理、AVClass 呼叫、多執行緒排程
```

| 模組 | 職責 |
|------|------|
| `cli.py` | 解析命令列參數，初始化設定並啟動標註流程 |
| `config.py` | 管理輸入資料夾路徑與輸出 CSV 路徑等組態 |
| `labeler.py` | 遞迴掃描 JSON 檔案、轉換格式、呼叫 AVClass 子程序、多執行緒並行處理，以及結果彙整輸出 |

## 開發指南

### 環境設定

```bash
git clone https://github.com/bolin8017/avclassLabel.git
cd avclassLabel
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### 執行測試

```bash
pytest
```

### 執行程式碼檢查

```bash
# 檢查程式碼風格
ruff check src/ tests/

# 自動修正可修復的問題
ruff check --fix src/ tests/

# 格式化程式碼
ruff format src/ tests/
```

### CI 流程

專案透過 GitHub Actions 自動執行以下檢查：

- `ruff check` -- 程式碼風格與品質檢查
- `ruff format --check` -- 程式碼格式驗證
- `pytest` -- 單元測試

## 未來改進方向

- **自訂輸出路徑** -- 新增 `--output` 參數，允許使用者指定 CSV 輸出位置
- **支援 AVClass2** -- 整合 [AVClass2](https://github.com/malicialab/avclass) 以取得更細緻的標籤資訊（如行為標籤）
- **JSON/JSONL 輸出格式** -- 除 CSV 外支援 JSON Lines 輸出格式
- **Docker 支援** -- 提供 Dockerfile，簡化環境建置流程
- **統計摘要報告** -- 標註完成後自動產生家族分佈統計

## License

本專案採用 [MIT License](LICENSE) 授權。

## Acknowledgments

- [AVClass](https://github.com/malicialab/avclass) -- 由 MaliciaLab 開發的惡意程式標籤工具，本專案的核心分類引擎
- [VirusTotal](https://www.virustotal.com/) -- 提供多引擎掃描報告的惡意程式分析平台
- [tqdm](https://github.com/tqdm/tqdm) -- 提供直覺的進度條顯示功能
