# Baseline observation

## Objective

Assess the synthetic endpoint dataset for outlier activity and unusual event patterns.

## Dataset

- `data/synthetic_endpoint_telemetry.csv`

## Method

- load telemetry events
- aggregate by host, user, and process
- compare each host against median event volume
- flag processes with elevated severity values

## Result

The current dataset is small but includes multiple suspicious signals, especially around credential access and execution chains tied to PowerShell and network activity. Those patterns are useful for building a baseline for more advanced detection work.

## Next steps

- add more realistic attacker simulation scenarios
- correlate process execution with execution time and host behavior
- expand into identity and network telemetry
