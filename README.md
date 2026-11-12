# py-monitor

Python analytics that pulls telemetry from **Azure Application Insights** and
**AWS X-Ray**, merges it into one event stream, and reports anomalous
behaviour: suspicious transaction patterns as well as latency and error spikes.

It ships with a **dummy-data mode** that produces realistic payloads in each
cloud's native format, with known anomalies injected, so the whole pipeline
runs locally without any cloud access.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/py-monitor                      # dummy data, console report
.venv/bin/py-monitor --format html -o reports/report.html
.venv/bin/pytest
```

The core uses only the standard library (Python 3.11+). The cloud SDKs are optional:

```bash
.venv/bin/pip install -e ".[azure,aws]"
```

See [docs/sample_report.html](docs/sample_report.html) for an example HTML report.

## What it detects

| Detector | Category | Fires when | Key settings |
|---|---|---|---|
| `rapid_repeat_transfer` | transaction | The **same amount** leaves the **same account** at least `min_count` times within `window_minutes` | 3 within 5 min |
| `transaction_velocity` | transaction | One account makes more than `max_count` transfers, or moves more than `max_total`, within a window | 10 / 20,000 per 10 min |
| `structuring` | transaction | Repeated transfers fall just under a reporting threshold (smurfing) | 3 within 10% below 10,000 in 24 h |
| `latency_spike` | performance | An operation's p90 latency in a 5-minute bucket reaches `ratio` times its own baseline | 3x |
| `error_rate` | reliability | A service's failure rate in a bucket reaches `max(min_error_rate, baseline x multiplier)` | 10% / 5x |

Severity runs from low to critical. For example, a repeated transfer becomes **high**
when there are at least 5 repeats or the total reaches 10,000.

## How it works

```
 Azure App Insights ──(KQL via azure-monitor-query)──┐
                                                     ├─> LogEvent stream ─> de-dupe ─> detectors ─> report
 AWS X-Ray ─────(get_trace_summaries/batch_get_traces)┘                                            console / json / html
```

* **Connectors** (`src/py_monitor/connectors/`) map native payloads onto one
  `LogEvent` model: request, dependency, exception or transaction.
  * *App Insights* runs a `union AppRequests, AppDependencies, AppExceptions, AppEvents`
    query against the workspace. Transfers are `customEvents` (default name
    `FundsTransfer`). Their property names are configurable through `property_map`.
  * *X-Ray* splits the window into 6-hour chunks (the API limit), fetches full
    traces 5 at a time, and reads transaction fields from segment **annotations**
    (`account_id`, `amount`, `currency`, `counterparty`, `txn_id`).
  * X-Ray trace ids are converted to the W3C form, so one request can be followed
    across both clouds.
* **De-duplication**: a transfer that both clouds log (same transaction id) is
  counted once and tagged `seen_in: [aws_xray, azure_appinsights]`. Without this,
  every transfer would be counted twice and the velocity rules would fire on normal traffic.
* **Resilience**: if one source or one detector fails, the error is recorded in
  the report and the rest of the run continues.

## Dummy scenario

`connectors/dummy_data.py` simulates `mobile-banking-api` on Azure calling
`payments-service` on AWS, with about 60 accounts of normal traffic. It injects:

| Account / service | Anomaly |
|---|---|
| `ACC-1007` | 5 x 2,500.00 GBP to the same payee within about 3 minutes |
| `ACC-1013` | 14 transfers of varying amounts within 10 minutes |
| `ACC-1042` | 4 transfers of 9,750 to 9,950 GBP over about 90 minutes |
| `mobile-banking-api` | About 35% HTTP 500 responses for 12 minutes |
| `payments-service` | About 20x latency for 20 minutes |

The output is deterministic for a given `--seed` and window (`--end`, `--hours`).

## Running against real data

1. Copy `config/settings.example.toml` to `config/settings.toml` (git-ignored) and adjust it.
2. **Azure**: set `workspace_id` or `APPINSIGHTS_WORKSPACE_ID`. Authentication uses
   `DefaultAzureCredential` (`az login`, managed identity, or a service principal
   in environment variables). The identity needs *Log Analytics Reader* on the workspace.
3. **AWS**: set `region` or `AWS_REGION`. The standard credential chain is used.
   The role needs `xray:GetTraceSummaries` and `xray:BatchGetTraces`.
4. Run it:

```bash
.venv/bin/py-monitor --live --config config/settings.toml --hours 1 --fail-on high
```

`--fail-on <severity>` exits with code 2 when an anomaly at or above that
severity is found, which is handy for cron jobs, CI or alerting wrappers.

## CLI

```
py-monitor [--live] [--config FILE] [--hours N] [--end ISO8601]
           [--format console|json|html] [-o FILE] [--seed N]
           [--fail-on low|medium|high|critical] [-v]
```

## Project layout

```
src/py_monitor/
  models.py              LogEvent: the normalised event shared by everything
  connectors/            azure_appinsights.py, aws_xray.py, dummy_data.py
  detectors/             transaction.py (repeat, velocity, structuring), operational.py (latency, errors)
  engine.py              collect -> de-dupe -> detect -> AnalysisReport
  config.py              defaults + TOML + env overrides, builds sources and detectors
  reporting/             console, json, html
  cli.py
tests/                   unit tests per detector and connector, plus end-to-end runs on dummy data
```

## Adding a detector

Subclass `Detector`, implement `detect(events) -> list[Anomaly]`, add it to
`REGISTRY` in `detectors/__init__.py`, and give it a `[detectors.<name>]` section
in the config. The helpers in `detectors/base.py` (`sliding_bursts`, `bucketize`,
`group_by`) cover most windowing needs.
