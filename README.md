# SOC Alert Triage Lab

##  Overview

This project simulates a real-world Security Operations Center (SOC) workflow. It focuses on log analysis, threat detection, and incident response.

##  Objectives


- Understand SOC log data and event flow
- Build Python-based log parsing logic
- Detect suspicious authentication behavior
- Implement threshold and time-window based detection
- Reduce false positives using basic whitelist logic
- Classify alert severity using scoring logic
- Attach MITRE ATT&CK mappings to detections
- Preserve evidence lines for analyst review
- Recommend basic response actions
- Document detections in a Sigma-style rule format

##  Features (In Progress)

- [x] Basic log ingestion
- [x] Failed login detection
- [x] IP-based brute force detection
- [x] Alert severity classification
- [ ] Time-window brute force detection
- [ ] Successful login after failed attempts
- [ ] False positive handling / whitelist
- [ ] Evidence capture
- [ ] MITRE ATT&CK mapping
- [ ] Response recommendations
- [ ] Sigma-style rule documentation
- [ ] Markdown reporting

##  Project Structure (Planned)

soc-lab/
├── logs/
├── detection/
├── reports/
└── main.py

##  How to Run

```bash
python main.py
```

##  Learning Focus

This project is built step-by-step with deep understanding of:

* Data flow
* Detection logic
* Python basics
* SOC methodologies

