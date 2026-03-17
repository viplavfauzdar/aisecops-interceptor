# Changelog

All notable changes to this project will be documented in this file.

## v0.2.0

### Added

- `/explain` endpoint for structured, non-executing decision inspection.
- `dry_run` mode for evaluating requests without executing tools.
- Default high-risk tool presets that require approval unless explicitly overridden.
- Swagger / OpenAPI request and response examples for the main API endpoints.
- Capability metadata in explain output, including readable capability risk context.
- Normalized external `policies/` configuration with clear separation between policy behavior and capability mappings.

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
