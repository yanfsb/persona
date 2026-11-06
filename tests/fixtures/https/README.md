# Synthetic HTTPS Git fixture

`test-ca.key` and `server.key` are deliberately disposable test-only keys. The
local smart-HTTP server uses the leaf certificate for `127.0.0.1`; CI installs
only `test-ca.crt` into its ephemeral Linux trust store so native Git exercises
its normal TLS verification. Never reuse these keys or certificates outside
this local test fixture. The fixture contacts no external Git/provider service.
