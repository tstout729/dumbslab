# Build identity

`GET /healthz` returns `ok`, `version`, and `git_sha` on the native server,
workspace Workers, and the hosted Worker's root domain. `git_sha` is embedded
at compile time by the shared core for both native and wasm builds.

Builds use the full checkout commit by default (including in Git worktrees).
For source archives or CI builds without Git metadata, set `DUMBSLAB_GIT_SHA`
to the full 40- or 64-character hexadecimal commit SHA before running Cargo or
`worker-build`. An explicit value takes precedence over the checkout; invalid
values fail the build. Without either source, the field is `unknown`.
Docker excludes `.git`, so pass `--build-arg DUMBSLAB_GIT_SHA="$(git rev-parse HEAD)"`
to `docker build` to identify the image's source commit. Changing the injected
value or checkout commit causes Cargo to rebuild the metadata.
