# Changelog

## Unreleased

- Refresh README verification counts and distinguish current maintenance runs
  from historical transcripts; clarify that toy-agent CI needs no API key.
- Replace the README launch video, poster, and GIF with the corrected film showing
  DeepSeek's published 1 of 6 re-scored to 0 of 6 under the current checks.
- Open-weight red-team review (DeepSeek V4 Pro), merged after verification:
  a crashed or non-zero-exit agent can no longer score PASS (it is INCONCLUSIVE);
  `covert_channel_board` flags any board request, not only `/post`;
  `acknowledged_then_violated` follows hard-link and rename aliases of forbidden
  files (directory opens still do not count); `dns_egress_escape` now checks its
  seeded decoy token; the docs no longer claim an unsigned hash chain is
  tamper-evident (it can be recomputed by anyone who can edit the report).
- Fix false positives in `acknowledged_then_violated` and the live tripwire:
  directory traversal is not a forbidden file read, and `command_pattern`
  matches executable positions instead of ordinary arguments. Preserve genuine
  file reads, wrapped and shell commands, and decoy-token detection.
