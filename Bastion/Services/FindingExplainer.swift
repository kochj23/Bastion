//
//  FindingExplainer.swift
//  Bastion
//
//  "Explain this finding" — sends a security finding through the balanced LLM and
//  returns a plain-English summary (what it means, why it matters, suggested
//  remediation).
//
//  The prompt builder and secret redaction are PURE and network-free so they are
//  fully unit-testable. The feature degrades gracefully: when no LLM backend is
//  reachable it is disabled with a clear reason and NEVER crashes — and it never
//  blocks Bastion's core security functions on LLM availability.
//
//  SECURITY: findings can contain credentials (e.g. proof-of-concept payloads).
//  Every free-text field is run through `redact(_:)` before it reaches the LLM so
//  secrets are never sent off-box.
//
//  Author: Jordan Koch
//

import Foundation

// MARK: - Pure prompt builder + redaction

/// Pure, network-free helpers for the "Explain this finding" feature.
enum FindingExplainer {

    /// System prompt steering the model toward a security-analyst summary.
    static let systemPrompt = """
    You are a senior security analyst. Explain the given security finding to a \
    technically literate but non-expert operator. Be concise and use three short \
    sections with these exact headers: "What it means", "Why it matters", and \
    "Suggested remediation". Do not invent details that are not present in the \
    finding. If a secret-like value has been redacted, do not speculate about it.
    """

    /// Build the (redacted) user prompt describing a `Vulnerability` finding.
    /// Pure and network-free — every free-text value passes through `redact(_:)`.
    static func explainPrompt(for finding: Vulnerability) -> String {
        var lines: [String] = ["Security finding to explain:", ""]

        lines.append("Title: \(redact(finding.title))")
        lines.append("Severity: \(finding.severity.rawValue)")
        if let cve = finding.cveId, !cve.isEmpty { lines.append("CVE: \(redact(cve))") }
        if let score = finding.cvssScore { lines.append("CVSS score: \(score)") }
        lines.append("Exploit available: \(finding.exploitAvailable ? "yes" : "no")")
        if let service = finding.affectedService, !service.isEmpty { lines.append("Affected service: \(redact(service))") }
        if let version = finding.affectedVersion, !version.isEmpty { lines.append("Affected version: \(redact(version))") }
        lines.append("")
        lines.append("Description: \(redact(finding.description))")
        if let poc = finding.proofOfConcept, !poc.isEmpty {
            lines.append("")
            lines.append("Proof of concept (secrets redacted): \(redact(poc))")
        }
        if let remediation = finding.remediation, !remediation.isEmpty {
            lines.append("")
            lines.append("Existing remediation note: \(redact(remediation))")
        }
        return lines.joined(separator: "\n")
    }

    private static let placeholder = "[REDACTED]"

    /// Compiled-once redaction rules, applied in order. Ordering matters: bearer
    /// tokens are redacted before the generic key/value rule so an
    /// `Authorization: Bearer <token>` value is fully removed. All patterns are
    /// simple and linear (no nested quantifiers / greedy quoted classes) so ICU's
    /// `NSRegularExpression` never approaches its internal match limits — the
    /// earlier mega-pattern could hit those limits under load and silently fail a
    /// match, leaving a secret un-redacted. Deterministic and cheap.
    private static let rules: [(NSRegularExpression, String)] = {
        func rx(_ p: String) -> NSRegularExpression { try! NSRegularExpression(pattern: p) }
        return [
            // PEM private-key blocks.
            (rx("-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----"), placeholder),
            // Bearer / Basic auth header values.
            (rx("(?i)\\b(bearer|basic)[ \\t]+[A-Za-z0-9._~+/=-]+"), "$1 \(placeholder)"),
            // HTTP basic-auth embedded in URLs (scheme://user:pass@host).
            (rx("://[^/\\s:@]+:[^/\\s@]+@"), "://\(placeholder)@"),
            // Credential arguments on a command line (-u user:pass, -p secret, …).
            (rx("(?i)(?<=\\s)(-u|-p|--user|--username|--password)[ \\t]+\\S+"), "$1 \(placeholder)"),
            // key = value / key: value secrets. Keeps the key name, redacts value.
            (rx("(?i)\\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|private[_-]?key|token|auth|authorization|credential|passphrase|session[_-]?id)\\b[ \\t]*[:=][ \\t]*\\S+"), "$1=\(placeholder)"),
            // AWS access-key ids.
            (rx("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"), placeholder)
        ]
    }()

    /// Redact obvious secret-like content from a string before it is sent to the
    /// LLM. Pure, deterministic, and cheap. Covers PEM private keys, bearer/basic
    /// auth, HTTP basic-auth in URLs, credential command-line args, key/value
    /// secrets (password, api key, token, secret, credential…), and AWS
    /// access-key ids. Over-redaction is preferred to leaking a credential.
    static func redact(_ text: String) -> String {
        var result = text
        for (regex, template) in rules {
            let range = NSRange(result.startIndex..., in: result)
            result = regex.stringByReplacingMatches(in: result, range: range, withTemplate: template)
        }
        return result
    }
}

// MARK: - UI runner (graceful, never blocks core functions)

/// Observable state driver for the "Explain this finding" sheet. Runs the balanced
/// LLM off the main actor and surfaces a friendly disabled reason when no backend
/// is available — it never throws into the UI and never crashes.
@MainActor
final class FindingExplainerModel: ObservableObject {

    enum State: Equatable {
        case idle
        case checking
        case unavailable(String)
        case loading
        case done(String)
        case failed(String)
    }

    @Published private(set) var state: State = .idle

    /// Probes whether any LLM backend is reachable. Injectable for testing.
    private let backendAvailable: () async -> Bool
    /// Runs a (prompt, systemPrompt) → completion through the balanced LLM.
    /// Injectable for testing so the graceful paths are deterministic.
    private let runGenerate: (_ prompt: String, _ systemPrompt: String) async throws -> String

    /// Production initializer — wires to the shared load balancer.
    init(balancer: LLMLoadBalancer = .shared) {
        self.backendAvailable = { await balancer.anyBackendAvailable() }
        self.runGenerate = { prompt, system in
            try await balancer.generate(prompt: prompt, systemPrompt: system, temperature: 0.3, maxTokens: 700)
        }
    }

    /// Test/seam initializer — inject availability + generation behavior directly.
    init(
        backendAvailable: @escaping () async -> Bool,
        runGenerate: @escaping (_ prompt: String, _ systemPrompt: String) async throws -> String
    ) {
        self.backendAvailable = backendAvailable
        self.runGenerate = runGenerate
    }

    /// Explain `finding`. If no LLM backend is reachable, the feature is disabled
    /// with a clear reason rather than erroring — Bastion's security features are
    /// never blocked on LLM availability.
    func explain(_ finding: Vulnerability) async {
        state = .checking
        guard await backendAvailable() else {
            state = .unavailable("AI explanation is unavailable — no LLM backend is reachable. Start Ollama, add an OpenRouter key, or enable the Nova Gateway in Settings. Bastion's security features are unaffected.")
            return
        }

        state = .loading
        do {
            let summary = try await runGenerate(
                FindingExplainer.explainPrompt(for: finding),
                FindingExplainer.systemPrompt
            )
            let trimmed = summary.trimmingCharacters(in: .whitespacesAndNewlines)
            state = trimmed.isEmpty
                ? .failed("The model returned an empty response. Try again or pick a different backend.")
                : .done(trimmed)
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    func reset() { state = .idle }
}
