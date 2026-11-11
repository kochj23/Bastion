# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-11-11

### Changed
- **AI: migrated to NovaAIKit 1.0.0.** All AI now runs through the shared `NovaAIKit`
  package via a single `AppAI.shared` object (appID `bastion`). One settings panel
  (`NovaAISettingsView`), one status indicator (`NovaAIStatusIndicator`), eight selectable
  backends (Ollama, MLX, TinyLLM, TinyChat, OpenWebUI, Nova Gateway, OpenRouter, OpenAI)
  plus Auto failover, per-backend model pickers, editable/validated URLs, retries, and
  output validation. Every AI feature keeps a built-in, rule-based fallback for when AI is
  off or no backend is reachable.

### Removed
- The in-app AI client stack: `AIBackendManager` (+extensions), `LLMLoadBalancer`,
  `ModelRegistry`, `OpenRouterProvider`, `KeychainStore`, `LLMSupport`/`LLMBackendType`,
  `EthicalAIGuardian`, `AIBackendStatusMenu`, and the `UnifiedAICapabilities` modules.
- The Google Cloud, Azure, AWS Bedrock, and IBM Watson backends (not part of NovaAIKit).

### Security
- API keys now live only in the macOS Keychain under `com.jkoch.bastion.<backend>`,
  https only, and are never surfaced as plaintext. Obsolete Google/Azure/AWS/IBM secrets
  from previous builds are scrubbed from the Keychain on first launch, and legacy
  `AIBackendManager_*` UserDefaults settings are migrated once.

## [Unreleased]

### Added
- **Multi-model LLM load balancing.** Ported the shared, network-free load balancer
  (`ModelRegistry`, `LoadBalancer`, `OpenRouterProvider`, `KeychainStore`) and a new
  `LLMLoadBalancer` service that spreads AI work across every discovered model. Three
  persisted toggles (all local / all frontier / Nova Gateway) compose the pool, with
  round-robin / least-busy selection and per-backend health-gating. Nova is never
  required — the balancer works with local (Ollama/MLX) and/or frontier (OpenRouter)
  models alone; the Nova Gateway is one optional backend that is dropped from the pool
  when its health check fails. Configurable in **Settings → AI Load Balancer**.
- **"Explain this finding" (AI).** New Explain action on security findings that routes
  the finding through the balanced LLM and returns a plain-English summary (what it
  means, why it matters, suggested remediation) in a sheet. The prompt is built by a
  pure, unit-tested `FindingExplainer.explainPrompt(for:)`; secret-like fields are
  redacted before anything reaches the LLM. The feature degrades gracefully when no
  backend is reachable and never blocks Bastion's core security functions.

### Security
- Redaction of secret-like content (passwords, API keys, tokens, bearer/basic auth,
  HTTP basic-auth in URLs, AWS access-key ids, PEM private keys) from finding text
  before it is sent to any LLM backend.

### Planned
- Performance improvements
- Additional features based on community feedback

## [1.0.0] - 2025-01-01

### Added
- Initial release
- Core functionality
- macOS native interface
- MIT License

---

*For detailed release notes, see [GitHub Releases](https://github.com/kochj23/Bastion/releases).*
