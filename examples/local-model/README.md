# Actual local inference

Build Ghost with `make build`, then run `sh scripts/test-local-model.sh` from the
repository. The script prepares checksum-pinned model/image inputs, a temporary
TLS service on an internal Docker network and a read-only Python project. Actual
model tokens must be produced through the session broker; direct access to that
same model IP/port and the internet must fail.

See [the complete integration guide](../../docs/integrations.md). The model is a
small transport fixture, not a clinically useful assistant. Setup downloads need
internet; inference is local, uses only synthetic text and does not require a
paid API key. The script removes its temporary resources after the run.
