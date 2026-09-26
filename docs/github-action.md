# Running agentrig in GitHub Actions

agentrig ships a composite action (`action.yml` at the repo root). It installs
bubblewrap and strace on the runner, enables unprivileged user namespaces
(Ubuntu 23.10+ restricts them by default), installs agentrig into a venv, runs
your agent under attack, uploads SARIF to code scanning, and can gate on
regressions against a baseline report.

> This repository does **not** run this workflow on itself. It would need a
> real API key in CI, and the action has not been exercised on GitHub's hosted
> runners by this project yet. The steps it runs were run locally; the
> action wrapper itself is untested in Actions. Treat the first run as a
> smoke test.

## Sample workflow

Copy to `.github/workflows/agentrig.yml` in the repository that holds your agent:

```yaml
name: agent safety
on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write   # SARIF upload to code scanning

jobs:
  agentrig:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - uses: vatsal191201/agentrig@master
        with:
          agent: python3 my_agent.py            # your agent, run in the sandbox
          scenario: all
          trials: 3                             # rates + Wilson interval
          task-field: task                      # natural-language tasks
          llm-base-url: https://api.deepseek.com
          llm-model: deepseek-flash
          llm-api-key: ${{ secrets.LLM_API_KEY }}   # never printed; redacted from outputs
          # baseline: baselines/agentrig-report.json   # optional: fail on regression
          # tolerance: "0.1"

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: agentrig-report
          path: |
            agentrig-report.json
            agentrig.sarif
```

Notes:

- Your agent must honour `https_proxy` (or `AGENTRIG_LLM_BASE_URL`) to reach its
  model: every sandbox has its own network namespace, and the recording egress
  gate forwards only the configured LLM endpoint.
- Findings appear under **Security → Code scanning**, one alert per failed
  check, anchored at the agent script from the `agent` command.
- Exit codes: `run` 0 = clean, 3 = findings, 2 = could not run (e.g. no user
  namespaces), which fails the job and is never reported green. `diff` 4 =
  regression.
- Cost control: `trials` multiplies model spend. Start with `trials: 1` on pull
  requests and a scheduled job with more trials.
