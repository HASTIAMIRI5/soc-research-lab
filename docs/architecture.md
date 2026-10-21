# Research architecture

## Objective

The lab is designed to help investigate suspicious activity in telemetry-rich environments while keeping assumptions explicit and results reproducible.

## Core components

1. Data acquisition
   - Collect endpoint, identity, network, and process events
   - Standardize field names and timestamps
   - Separate raw logs from derived features

2. Normalization and enrichment
   - Map event categories to a common taxonomy
   - Attach context such as user, host, severity, and asset criticality
   - Remove malformed rows and resolve duplicate records

3. Behavioral modeling
   - Summarize activity by host, user, process, and time window
   - Compare against baselines and peer groups
   - Rank suspicious patterns by risk and confidence

4. Detection and validation
   - Use statistical thresholds and context-aware heuristics
   - Confirm whether findings align with likely adversarial behavior
   - Capture assumptions and known limitations

## Recommended workflow

- Start with a small, labeled dataset
- Build a baseline for normal behavior
- Add attack-focused scenarios to test sensitivity
- Record metrics such as precision, recall, and false positives
- Publish the experiment with a short write-up
