# ASTRA — AI Security Tech Risk Analyst

ASTRA is an experimental Python-based vulnerability research tool that accepts a technology/version string, normalizes its identity with Google Gemini, and searches the NIST National Vulnerability Database (NVD). It includes two scan paths and a multi-technology regression runner.

> **Status:** Experimental / actively developing  
> **Use:** Authorized defensive security and vulnerability management only.

## Features

- Gemini-assisted vendor/product/version normalization.
- Plan A: NVD CPE discovery followed by CVE retrieval for the selected CPE.
- Plan B: when no CPE match is found, NVD keyword discovery followed by Gemini-based candidate validation.
- OpenJDK alternate keyword lookup (`JDK {version}`) when the initial OpenJDK keyword search yields no candidates.
- CVE IDs, severity/CVSS data where available, descriptions, and NVD links.
- Scan logging and a regression runner with aggregate counts and elapsed runtime.

## Scan flow

```text
Technology + version
        |
        v
Gemini normalization
        |
        v
NVD CPE lookup
   |             |
 CPE found    No CPE match
   |             |
   v             v
CVE lookup    NVD keyword search
                 |
                 v
          Gemini validation
```

Plan A reports CVEs returned by the selected CPE lookup. A CPE-associated CVE count is not, by itself, proof that a particular installed build or deployment is exploitable; verify applicability and vendor advisories before treating a result as a confirmed vulnerability. Plan B statuses are model-assisted classifications and should also be reviewed.

## Project structure

```text
astra-security-scanner-github/
├── astra_scan.py
├── normalize_product.py
├── product_mapping.py
├── nvd_cpe.py
├── cve_search.py
├── nvd_keyword_search.py
├── gemini_keyword_validator.py
├── nvd_keyword_validator.py
├── keyword_generator.py
├── vulnerability_validator.py
├── regress_test.py
├── tests/
├── tools/
├── requirements.txt
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

## Requirements

- Python 3.9+ (use a currently supported Python release where possible)
- Internet access
- Google Gemini API key
- Optional NVD API key for improved NVD rate limits

## Installation

```bash
git clone https://github.com/<your-username>/astra-security-scanner.git
cd astra-security-scanner
python -m venv .venv
```

Activate the environment:

**Windows PowerShell**
```powershell
.venv\Scripts\Activate.ps1
```

**Linux/macOS**
```bash
source .venv/bin/activate
```

Install dependencies and configure credentials:

```bash
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in `GEMINI_API_KEY`; optionally add `NVD_API_KEY`. The application reads environment variables. If using a `.env` file, ensure your shell or your preferred environment loader exports those variables before running the scripts.

PowerShell example:
```powershell
$env:GEMINI_API_KEY="your_gemini_api_key"
$env:NVD_API_KEY="your_nvd_api_key"  # optional
```

Bash example:
```bash
export GEMINI_API_KEY="your_gemini_api_key"
export NVD_API_KEY="your_nvd_api_key"  # optional
```

**Never commit `.env`, API keys, tokens, or private data.**

## Usage

Run the interactive scanner:

```bash
python astra_scan.py
```

Run the multi-technology regression test:

```bash
python regress_test.py
```

The regression list currently includes Apache HTTPD, RabbitMQ, Erlang, OpenJDK, Eclipse Temurin, Python, PostgreSQL, Tomcat, Spring Boot, and Angular. It prints per-technology method/status/CVE counts, aggregate Plan A/Plan B and validation counts, and total elapsed time in seconds and minutes. Network/API latency affects runtime and results.

## Interpretation notes

- NVD records and CPE matching can have coverage or mapping gaps.
- The current CPE selection logic should be reviewed before production use; matching the first returned CPE may not always represent the intended distribution/product build.
- Plan A's regression tally labels CPE-returned records as `AFFECTED` to match the current project reporting convention; that label is a scanner tally convention, not independent proof of version applicability.
- Plan B's Gemini classification is model-assisted, may be uncertain, and requires analyst review.
- NVD and Gemini services may impose rate limits, change response formats, or be temporarily unavailable.

## Security and responsible use

Use ASTRA only for authorized defensive assessment. Do not scan systems or applications without permission. Avoid publishing internal scan logs, customer details, secrets, or sensitive asset information.

## License

MIT. See [LICENSE](LICENSE).
