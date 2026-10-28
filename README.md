# Threat Intelligence Aggregator

A small Python command-line project that collects Indicators of
Compromise (IoCs) from **AlienVault OTX** subscribed pulses and
optionally **VirusTotal Intelligence Search**, normalizes the records,
removes duplicates, and exports JSON and CSV files.

> **Access note:** AlienVault OTX requires an API key for subscribed
> pulses. VirusTotal Intelligence Search may require a plan that grants
> access to that endpoint. The program reports access/rate-limit errors
> instead of pretending that data was collected.

## Features

-   Pulls IoCs from AlienVault OTX subscribed pulses.
-   Supports VirusTotal Intelligence Search queries.
-   Normalizes indicator fields across providers.
-   Deduplicates by indicator type and value while retaining source
    attribution.
-   Writes `indicators.json` and `indicators.csv`.
-   Uses environment variables for API keys.
-   Handles common authentication, permission, rate-limit, timeout, and
    network errors.

## Project files

``` text
threat-intelligence-aggregator/
├── threat_intelligence_aggregator.py
├── requirements.txt
├── requirements.pdf
├── project_report.pdf
├── sandip_university_logo.png
└── README.md
```

## Requirements

-   Python 3.10+
-   `requests` Python package
-   AlienVault OTX API key
-   VirusTotal API key (optional; Intelligence Search access may be
    required)

## Setup

### 1. Create and activate a virtual environment

**Windows (PowerShell):**

``` powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS/Linux:**

``` bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

``` bash
python -m pip install -r requirements.txt
```

### 3. Set API keys

**Windows PowerShell:**

``` powershell
$env:OTX_API_KEY="your_otx_api_key"
$env:VT_API_KEY="your_virustotal_api_key"
$env:VT_SEARCH_QUERY="type:ip"
```

**macOS/Linux:**

``` bash
export OTX_API_KEY="your_otx_api_key"
export VT_API_KEY="your_virustotal_api_key"
export VT_SEARCH_QUERY="type:ip"
```

Get keys from the official provider websites: - AlienVault OTX:
https://otx.alienvault.com/ - VirusTotal: https://www.virustotal.com/

Do not paste real API keys into source code, screenshots, reports, or
public repositories.

## Run

Collect from both providers:

``` bash
python threat_intelligence_aggregator.py --limit 10
```

Collect only OTX:

``` bash
python threat_intelligence_aggregator.py --skip-vt
```

Collect only VirusTotal:

``` bash
python threat_intelligence_aggregator.py --skip-otx --vt-query "type:ip"
```

Choose an output directory:

``` bash
python threat_intelligence_aggregator.py --limit 20 --out results
```

After a successful run, the output directory contains: -
`indicators.json` --- structured output with collection timestamp and
records. - `indicators.csv` --- spreadsheet-friendly output.

If an API key is missing, the source is skipped with a warning. If a
provider rejects the request, check the key, permissions, plan, query
syntax, rate limit, and internet connection.

## Output fields

  -----------------------------------------------------------------------
  Field                               Meaning
  ----------------------------------- -----------------------------------
  `indicator`                         Indicator value, such as an IP,
                                      domain, URL, or file hash

  `type`                              Provider-reported indicator or
                                      object type

  `source`                            Provider(s) supplying the record

  `pulse`                             OTX pulse name, when available

  `first_seen`                        Provider-supplied
                                      creation/submission time, when
                                      available

  `collected_at`                      UTC time the record was normalized

  `description`                       Provider-supplied description/name,
                                      when available

  `source_id`                         Provider object/indicator ID, when
                                      available
  -----------------------------------------------------------------------

## How it works

1.  Read credentials from environment variables.
2.  Request subscribed pulses from the OTX API and/or search VirusTotal
    Intelligence.
3.  Convert provider records into a common schema.
4.  Deduplicate records by normalized type and indicator.
5.  Export JSON and CSV files.

## Limitations and responsible use

-   This is an educational aggregator, not a full SIEM or automated
    incident-response system.
-   Indicator data can be stale, incomplete, or incorrectly classified;
    validate before acting.
-   API access and quotas vary by provider and account plan.
-   The default VirusTotal query is `type:ip`; adjust it to a query
    supported by your account.
-   Do not use collected indicators to target systems. Use the data for
    defensive analysis, detection engineering, and authorized security
    work.
-   Respect provider terms, rate limits, and data-sharing rules.

## Suggested future improvements

-   Add pagination and incremental collection.
-   Add tests with mocked API responses.
-   Add caching, structured logging, and configurable retry/backoff.
-   Add a local dashboard and scheduled collection.
-   Add a scoring model with transparent, explainable rules.

## License

For academic/demo use. Add a license file if you intend to publish or
distribute the project.
