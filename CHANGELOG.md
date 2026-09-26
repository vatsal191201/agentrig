# Changelog

## Unreleased

- Fix false positives in `acknowledged_then_violated` and the live tripwire:
  directory traversal is not a forbidden file read, and `command_pattern`
  matches executable positions instead of ordinary arguments. Preserve genuine
  file reads, wrapped and shell commands, and decoy-token detection.
