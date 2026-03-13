# Changelog

All notable changes to this project will be documented in this file.

## v0.1.0

Initial public OSS release.

### Added

- Guarded large language model (LLM) pipeline with prompt and output inspection.
- Runtime interceptor for tool execution policy enforcement and approval workflows.
- Policy engine with declarative rules and YAML policy bundle support.
- Unified runtime event model across LLM-stage and tool-stage security flows.
- Audit API for querying persisted runtime events and sink delivery failures.
- Multi-sink runtime event delivery with file, memory, and webhook sinks.
- Webhook sink retry/backoff support and optional HMAC signing for event authenticity.
