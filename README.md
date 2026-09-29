# Mini SOC / SIEM Investigation Lab

A small defensive cybersecurity lab demonstrating security monitoring, detection, alert triage and incident investigation using synthetic authentication and endpoint logs.

## What it demonstrates
- Log ingestion and analysis
- Detection rule design
- Brute-force detection
- Detection of successful login after repeated failures
- Off-hours authentication detection
- PowerShell process monitoring
- Alert severity and triage
- Structured incident reporting
- Python unit testing

## Run

```bash
python detect.py
python -m unittest test_detect.py
```

No external services are required.

## Repository structure

- `sample_logs.csv` - synthetic authentication and endpoint events
- `detect.py` - detection and alerting logic
- `test_detect.py` - unit tests
- `detection_rules.json` - documented detection rules
- `INCIDENT_REPORT.md` - investigation findings and analyst workflow

## Scope

This is a local SIEM-style simulation built for learning and portfolio demonstration. It does not represent production SOC experience or use a commercial SIEM.
