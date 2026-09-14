# Astra Security Scanner

A lightweight Python-based vulnerability assessment tool that combines **AI-assisted technology normalization** with **NVD CPE discovery** and **CVE enumeration**.

The project is designed for application/security engineers who need a repeatable way to turn technology/version strings such as `PostgreSQL 15.17` or `Apache HTTPD 2.4.68` into normalized products, discover matching CPEs, and retrieve associated CVEs from the **NIST National Vulnerability Database (NVD)**.

> **Status:** Experimental / actively developing  
> **Primary use:** Authorized security testing and vulnerability management

## Features

- 🤖 **AI-assisted product normalization**
  - Converts human-readable technology strings into vendor, product, and version fields.
  - Uses OpenRouter for the normalization step.
- 🔎 **NVD CPE discovery**
  - Searches the NVD CPE API using the normalized product and version.
- 🛡️ **CVE enumeration**
  - Queries the NVD CVE API using a selected CPE.
  - Extracts CVE ID, severity, CVSS score, and English description.
  - Supports CVSS v4.0, v3.1, v3.0, and v2 data when present.
- 🧪 **Regression testing**
  - Includes a reusable technology list for checking scanner behavior across multiple products.
- 🔐 **Secret-safe configuration**
  - API credentials are read from environment variables rather than stored in source code.

## Architecture

```text
Technology + Version
        │
        ▼
┌─────────────────────────┐
│ AI Product Normalizer   │
│ OpenRouter              │
└────────────┬────────────┘
             │
             ▼
 Vendor / Product / Version
             │
             ▼
┌─────────────────────────┐
│ NVD CPE Discovery       │
└────────────┬────────────┘
             │
             ▼
          CPE Name
             │
             ▼
┌─────────────────────────┐
│ NVD CVE Search          │
└────────────┬────────────┘
             │
             ▼
     CVE / Severity / CVSS
```

## Project Structure

```text
astra-security-scanner/
├── astra_scan.py                 # Main end-to-end scanner
├── normalize_product.py          # AI-assisted technology normalization
├── nvd_cpe.py                    # NVD CPE discovery
├── cve_search.py                 # NVD CVE lookup
├── regress_test.py               # Multi-technology regression runner
├── ai.py                         # Simple CVE lookup example
│
├── tests/
│   └── test_normalizer.py       # Normalizer test/example
│
├── tools/
│   └── cvedetails_browser_test.py # Experimental browser test
│
├── requirements.txt
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

## Requirements

- Python 3.9+
- Internet access
- An OpenRouter API key for AI normalization

The NVD APIs used by this project are publicly accessible. NVD may impose rate limits; production-scale scanning should account for API limits and caching.

## Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/astra-security-scanner.git
cd astra-security-scanner
```

Create a virtual environment:

### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

Create a `.env` file manually, or export the variable in your shell.

### Windows PowerShell

```powershell
$env:OPENROUTER_API_KEY="your_api_key"
```

### Linux / macOS

```bash
export OPENROUTER_API_KEY="your_api_key"
```

You can also copy `.env.example` as a reference.

**Never commit your real API key to GitHub.**

## Usage

Run the main scanner:

```bash
python astra_scan.py
```

Enter a technology and version when prompted:

```text
Enter technology and version (example: PostgreSQL 15.17): PostgreSQL 15.17
```

The scanner performs three stages:

```text
[1/3] AI product normalization
[2/3] NVD CPE discovery
[3/3] NVD CVE discovery
```

Example output:

```text
ASTRA SECURITY SCAN

Input Technology: PostgreSQL 15.17

[1/3] Normalizing technology...

Normalized Product:
Vendor     : PostgreSQL
Product    : PostgreSQL
Version    : 15.17
Confidence : 1.0

[2/3] Searching NVD for CPE...

[3/3] Searching NVD for CVEs...

CVE RESULTS
...
```

## Regression Testing

Run the included regression suite:

```bash
python regress_test.py
```

The current test list includes technologies such as:

- Apache HTTPD
- RabbitMQ
- Erlang
- OpenJDK
- Eclipse Temurin
- Python
- PostgreSQL
- Tomcat
- Spring Boot
- Angular

The regression runner is intended as a starting point for building a more formal automated test framework.

## Example Workflow

Input:

```text
Spring Boot 3.5.15
```

The tool attempts to determine:

```json
{
  "vendor": "...",
  "product": "Spring Boot",
  "version": "3.5.15",
  "confidence": 1.0
}
```

It then searches NVD for candidate CPEs and uses a selected CPE to retrieve matching CVEs.

## Important Design Considerations

### CPE selection

The current implementation selects the **first CPE returned by the NVD search**.

This is intentionally simple and is one of the main areas for future improvement. A production-grade scanner should rank and validate candidate CPEs using:

- Vendor match
- Product match
- Exact version match
- Version range information
- Edition/platform fields
- CPE applicability metadata
- Confidence scoring

### AI normalization

AI output is treated as untrusted input. The scanner validates that a response can be parsed as JSON, but additional schema validation is recommended.

### CVE coverage

A CVE search result does not automatically mean that the installed software is vulnerable in every deployment. Applicability, configuration, affected version ranges, attack prerequisites, and vendor advisories must be evaluated before declaring a finding exploitable.

## Security

This project is intended for **authorized vulnerability assessment and defensive security work**.

Do not scan systems or applications without permission.

Never commit:

- API keys
- Passwords
- Access tokens
- Cookies
- Private certificates
- Internal hostnames or sensitive customer data

## Roadmap

Planned improvements:

- [ ] CPE ranking and exact-version validation
- [ ] NVD API key support and rate-limit handling
- [ ] Retry/backoff logic
- [ ] Structured JSON output
- [ ] CSV/HTML report generation
- [ ] CVE deduplication
- [ ] CVSS sorting and filtering
- [ ] Affected-version validation
- [ ] Vendor advisory correlation
- [ ] CLI arguments instead of interactive input
- [ ] Automated unit tests with mocked NVD/OpenRouter responses
- [ ] Batch technology input from CSV
- [ ] Historical scan comparison
- [ ] CI workflow for regression testing

## Disclaimer

Astra Security Scanner is a vulnerability-management utility and should be used only against assets for which you have explicit authorization.

The presence of a CVE in NVD does not by itself prove that a particular deployment is vulnerable.

## License

MIT License. See [`LICENSE`](LICENSE).
