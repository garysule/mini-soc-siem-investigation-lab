# Mini SOC / SIEM Investigation Lab

## Objective
Simulate a small Security Operations Centre workflow using synthetic authentication and endpoint logs. The lab ingests events, applies detection rules, creates alerts, and documents investigation priorities.

## Scenario
The dataset contains normal authentication activity plus:
- repeated failed logins followed by a successful login
- off-hours privileged authentication
- PowerShell process execution

## Detection and triage
The Python detection engine applies four rules:
1. Brute-force threshold
2. Success after repeated failures
3. Off-hours authentication
4. PowerShell execution

Alerts are assigned severity to demonstrate prioritisation. The lab treats the data as synthetic and does not represent a real incident.

## Investigation findings
- `j.smith` from `10.10.2.15` generated repeated failures followed by a successful login. This is the highest-priority authentication sequence for investigation.
- `admin` authenticated to `server-44` at 22:41 and then launched command shell and PowerShell. This should be reviewed because it combines privileged access, off-hours activity and endpoint execution.
- `m.lee` generated three failures followed by a successful login, which is worth reviewing but falls below the four-failure brute-force threshold used by the lab.

## Analyst workflow demonstrated
Collect logs -> detect -> triage -> investigate context -> document findings -> recommend containment/escalation.

## Limitations
This is a local, simulated SIEM-style lab. It does not claim production experience with Microsoft Sentinel, Splunk, Elastic, or another commercial SIEM. The logs are synthetic.
