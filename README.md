# PE File Analyzer 🛡️

A simple Python-based **Portable Executable (PE)** analysis tool that extracts key metadata, section details, entropy values, imports/exports, and basic packing indicators.

This project is useful for **malware analysis**, **reverse engineering**, and **threat research**.

---

## 🚀 Features

- Extracts PE metadata:
  - Machine type
  - Entry point
  - Image base
  - Compile timestamp
- Section analysis:
  - Virtual Size vs Raw Size
  - Permissions (R/W/X)
  - Section entropy calculation
  - RWX section detection
- Import table parsing:
  - Lists DLLs and imported functions
- Export table parsing (if available)
- Packing suspicion indicators:
  - High entropy sections
  - Missing/empty import table

---

## 🧰 Requirements

Install dependencies using:

```bash
pip install -r requirements.txt
```
## ▶️ Usage

Run the script:
```bash
python pe_analyzer.py <path_to_exe_or_dll>
```
```bash
exaple: python pe_analyzer.py sample.exe
```
## 📂 Project Structure

```bash
pe-analyzer/
│── pe_analyzer.py
│── requirements.txt
│── README.md
│── utils/
│     ├── entropy.py
│     ├── pe_parser.py
│     └── formatter.py
└── output_samples/
      └── sample_report.txt

```

## 🔍 What is Entropy?

Entropy is used to measure randomness in a section.

Low entropy → normal data/code

High entropy (7.2 - 8.0) → may indicate packing/encryption/compression

## 🧠 Malware Analysis Use Case

This tool helps quickly identify suspicious PE traits such as:

Packed binaries

Encrypted sections

Loader behavior patterns

RWX sections (common in injectors/shellcode loaders)



⚠ Disclaimer

This tool is intended for educational and research purposes only.
Use only on files you have permission to analyze.
