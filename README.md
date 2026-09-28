# ASTRA — AI-Assisted Security Tech Risk Analyst

**Tagline:** Know Your Stack. Find Your Risk.

ASTRA is an experimental Python tool for application-security and vulnerability-management workflows. It accepts a software technology/version, normalizes the product name with Gemini, searches NIST's National Vulnerability Database (NVD), and displays CVE information.

> Use only for authorized defensive security work. ASTRA is a research/prototype project, not a substitute for vendor advisories or a complete vulnerability-management platform.

## Current capabilities

- Gemini-assisted technology normalization (vendor, product, version, confidence).
- Deterministic product-name mappings for supported technologies.
- NVD CPE lookup (Plan A) and CVE retrieval for the selected CPE.
- If CPE lookup returns no matches, Plan B performs an NVD keyword search and uses Gemini to classify candidates as `AFFECTED`, `NOT AFFECTED`, or `UNABLE TO VALIDATE`.
- Console output and local logs for scan/validation results.
- A regression runner and basic normalizer test file.

**Important current implementation note:** `keyword_generator.py` is a standalone keyword-generation experiment. The current `astra_scan.py` Plan B calls `validate_technology()` from `gemini_keyword_validator.py`, which currently searches NVD with one combined `technology + version` keyword. The multi-keyword generator is not yet wired into the end-to-end scanner.

## Workflow

```text
Technology + installed version
             |
             v
    Gemini normalization
             |
             v
   Product identity mapping
             |
             v
      NVD CPE lookup
        /       \
  CPE found    No CPE result
      |             |
      v             v
 NVD CVE API   NVD keyword search
      |             |
      v             v
 Display CVEs   Fetch CVE details + NVD version criteria
                    |
                    v
              Gemini validation
                    |
                    v
        AFFECTED / NOT AFFECTED /
             UNABLE TO VALIDATE
```

A keyword match is only a discovery result; it does not prove that an installed version is affected. Treat `UNABLE TO VALIDATE` as unresolved, not as safe or vulnerable.

## Repository structure

```text
astra-security-scanner-github/
├── astra_scan.py                 # Main scanner; Plan A and Plan B orchestration
├── normalize_product.py          # Gemini product normalization
├── product_mapping.py            # Deterministic vendor/product aliases
├── nvd_cpe.py                    # NVD CPE API lookup
├── cve_search.py                 # NVD CVE search by CPE
├── nvd_keyword_search.py         # NVD CVE keyword search
├── gemini_keyword_validator.py   # Plan B CVE detail retrieval and validation
├── keyword_generator.py          # Standalone Gemini keyword-generation experiment
├── nvd_keyword_validator.py      # Additional keyword validation utility
├── vulnerability_validator.py    # Validation utility
├── regress_test.py               # Multi-technology regression runner
├── tests/                        # Test/example scripts
├── tools/                        # Experimental browser utility
├── requirements.txt
├── .env.example                  # Environment variable names only
├── .gitignore
├── LICENSE
└── README.md
```

## Requirements

- Python 3.10 or newer recommended.
- Internet connection.
- Gemini API key for normalization and Gemini-based validation.
- NVD API key is optional, but recommended for higher NVD request limits.

## Installation

### Windows PowerShell

```powershell
git clone https://github.com/<your-username>/astra-security-scanner.git
cd astra-security-scanner
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
pip install -r requirements.txt
```

### Linux / macOS

```bash
git clone https://github.com/<your-username>/astra-security-scanner.git
cd astra-security-scanner
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Configure API keys

The Python modules read keys from environment variables. Set them in your shell before running the scanner.

### Windows PowerShell

```powershell
$env:GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
$env:NVD_API_KEY="YOUR_NVD_API_KEY"  # Optional
```

### Linux / macOS

```bash
export GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
export NVD_API_KEY="YOUR_NVD_API_KEY"  # Optional
```

`.env.example` documents the variable names. The current code does not automatically load a `.env` file, so shell environment variables must be set unless you add a dotenv loader yourself.

**Never commit real API keys, tokens, `.env` files, scan logs, or customer data.** If a key was ever committed or shared, revoke/rotate it.

## Run ASTRA

```bash
python astra_scan.py
```

Enter a technology and version when prompted, for example:

```text
Enter technology and version (example: PostgreSQL 15.17): Tomcat 10.1.59
```

The scanner first attempts the CPE workflow. If the NVD CPE request itself fails, it returns an NVD error; it does not treat a request failure as a no-match and switch to Plan B.

## Run supporting scripts

```bash
python keyword_generator.py
python nvd_keyword_search.py
python regress_test.py
```

`keyword_generator.py` requires `GEMINI_API_KEY`. It may return only the original technology/version keyword when the Gemini call fails. Gemini API availability and quotas are controlled by Google; a 503 response is a service-availability error and is not, by itself, proof that your quota is exhausted.

## Output and logs

The scanner creates a `logs/` directory at runtime. Logs and generated validation JSON are intentionally excluded from this repository package to avoid publishing environment-specific scan output.

## Accuracy and limitations

- NVD search coverage depends on product naming, CPE records, API results, and pagination behavior.
- The current CPE flow selects the first CPE returned by the lookup; verify product identity and version applicability before relying on findings.
- Plan B uses keyword search for candidate discovery. Gemini classifications are AI-assisted and should be reviewed against NVD records and vendor advisories.
- CVSS severity is not the same as exploitability in a particular deployment.
- Network errors, API limits, model availability, and incomplete metadata can affect results.

## Security and responsible use

Use ASTRA only for systems and software inventories you are authorized to assess. Do not include secrets, private customer data, internal hostnames, or sensitive infrastructure details in prompts or published logs.

## License

MIT. See [`LICENSE`](LICENSE).
