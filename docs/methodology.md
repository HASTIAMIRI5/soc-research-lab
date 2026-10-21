# Research architecture

## Objective

The project is designed to support structured security telemetry research, from acquisition and normalization to anomaly detection and evidence-backed findings.

## Core components

1. Data layer
   - raw CSV telemetry
   - normalized event records
   - reference datasets and baselines

2. Analysis layer
   - host summaries
   - user summaries
   - process summaries
   - anomaly detection metrics

3. Research layer
   - experiment notes
   - assumptions and limitation tracking
   - validation results and recommendations

4. Delivery layer
   - command-line demos
   - Python package for reuse
   - notebook-based exploratory analysis

## Data flow

Telemetry is loaded from CSV files, normalized into dictionaries, and then transformed into structured summaries. Risky indicators are surfaced through event counts, severity baselines, and suspicious process profiles.

## Recommended next evolutions

- add a richer threat taxonomy
- include behavioral baselines per asset class
- correlate identity, endpoint, and network telemetry
- surface detections in JSON and Markdown outputs
