# Contributing to DumbSlab

Use the [issue chooser](https://github.com/tstout729/dumbslab/issues/new/choose) to report bugs, suggest features or ask public questions. Search existing issues first. Include reproduction steps for bugs and explain the problem a feature would solve. Keep credentials, private workspace content and personal information out of issues and pull requests.

For billing, account access or private support, email [simplycoo+dumbslab@mail.grokbot.com](mailto:simplycoo+dumbslab@mail.grokbot.com). Report vulnerabilities through the private routes in [SECURITY.md](SECURITY.md).

## Development

See [README.md](README.md#development) for local startup commands and [AGENTS.md](AGENTS.md) for architecture, conventions and checks. The web app uses plain ES modules without a build step. The Rust core is shared by the native server and Cloudflare Worker.

Create a branch from main and keep each pull request focused on one change. Add meaningful tests for changed behavior, especially permissions; new behavior needs an end-to-end test in `crates/server/tests/api.rs`. Run the relevant local checks listed in AGENTS.md before submitting.

Explain the problem, resulting behavior and verification in the pull request. Link the relevant issue if one exists. Never commit secrets, local environment files or customer data.
