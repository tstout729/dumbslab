# Vendored telemetry SDKs

Loaded only when the host configures session recordings or error reports (`web/telemetry.js`). Each file is the published build, unmodified except that the trailing `//# sourceMappingURL=` line is removed (the maps aren't vendored).

| File | Source | SHA-256 of the published file |
| --- | --- | --- |
| `posthog/array.no-external.js` | `posthog-js@1.438.15`, `dist/array.no-external.js` (the version Quill's `tests/e2e/package.json` pins) | `8158bcdb7cf0a421e36c58fc523e61532a43d8030096668ae323bdc9d95e9aa0` |
| `posthog/posthog-recorder.js` | `posthog-js@1.438.15`, `dist/posthog-recorder.js` (rrweb, so recordings need no script from the server) | `9b0296518f44db4d075d8ff8c1e665200ff3448e5d5ccc3c4718078ce6369711` |
| `sentry/bundle.min.js` | `@sentry/browser@11.10.0`, `https://browser.sentry-cdn.com/11.10.0/bundle.min.js` (errors only) | `fbc2ddccc2431b84ba24478cbfd987f75b59c3e4d3102753ad5bb687f28b5210` |

Licenses: posthog-js is Apache-2.0 (`posthog/LICENSE`) and bundles rrweb, MIT (`posthog/LICENSE-rrweb`). Sentry's SDK is MIT (`sentry/LICENSE`).

To update, bump posthog-js in Quill first (its end-to-end test proves the server accepts that version), then replace the files, record the new hashes and run `node --check` on each.
