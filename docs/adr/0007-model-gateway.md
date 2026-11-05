# 7. One gateway for every model call, plain HTTP, AI optional

Status: accepted

## Context
Teams use different providers, often several, and some cannot send data outside their network at all.

## Decision
All model calls go through `ModelGateway`, which enforces an input cap and a deadline and converts every failure into
`ModelUnavailable`. Providers (Gemini, Ollama, Anthropic, OpenAI-compatible) are thin HTTP adapters with no SDKs.
Keys come from the environment. Every feature has a rules-only path; tests use a scripted provider.

## Consequences
- Switching to a local model is a configuration change.
- Provider-specific features (structured output schemas, caching) are used only where the plain API exposes them.
