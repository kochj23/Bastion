//
//  FindingExplainerTests.swift
//  BastionTests
//
//  Tests for the pure "Explain this finding" prompt builder, secret redaction,
//  and the graceful no-backend / success / failure paths of the runner.
//
//  Copyright © 2026 Jordan Koch. All rights reserved.
//

import XCTest
@testable import Bastion

final class FindingExplainerTests: XCTestCase {

    // MARK: - Helpers

    private func sampleFinding(poc: String? = nil) -> Vulnerability {
        var v = Vulnerability(
            title: "OpenSSH Remote Code Execution",
            description: "Pre-auth RCE in the exposed OpenSSH service.",
            severity: .critical,
            cveId: "CVE-2021-41617"
        )
        v.cvssScore = 9.8
        v.exploitAvailable = true
        v.affectedService = "OpenSSH"
        v.affectedVersion = "8.4"
        v.proofOfConcept = poc
        return v
    }

    // MARK: - Prompt builder (pure)

    func testExplainPromptIncludesKeyFields() {
        let prompt = FindingExplainer.explainPrompt(for: sampleFinding())
        XCTAssertTrue(prompt.contains("OpenSSH Remote Code Execution"))
        XCTAssertTrue(prompt.contains("Critical"))
        XCTAssertTrue(prompt.contains("CVE-2021-41617"))
        XCTAssertTrue(prompt.contains("9.8"))
        XCTAssertTrue(prompt.contains("Exploit available: yes"))
        XCTAssertTrue(prompt.contains("OpenSSH"))
    }

    func testExplainPromptIsDeterministicAndNetworkFree() {
        let finding = sampleFinding()
        XCTAssertEqual(FindingExplainer.explainPrompt(for: finding),
                       FindingExplainer.explainPrompt(for: finding))
    }

    func testExplainPromptOmitsAbsentOptionalFields() {
        let bare = Vulnerability(title: "Weak TLS", description: "TLS 1.0 enabled.", severity: .medium)
        let prompt = FindingExplainer.explainPrompt(for: bare)
        XCTAssertFalse(prompt.contains("Proof of concept"))
        XCTAssertFalse(prompt.contains("CVE:"))
        XCTAssertTrue(prompt.contains("Weak TLS"))
    }

    // MARK: - Redaction

    func testRedactionRemovesSecretsFromPrompt() {
        let poc = "curl -u admin:SuperSecret123 http://t/  password=Hunter2  api_key=sk-live-abcdef1234567890"
        let finding = sampleFinding(poc: poc)
        let prompt = FindingExplainer.explainPrompt(for: finding)

        // No plaintext secret survives into the prompt.
        XCTAssertFalse(prompt.contains("Hunter2"))
        XCTAssertFalse(prompt.contains("SuperSecret123"))
        XCTAssertFalse(prompt.contains("sk-live-abcdef1234567890"))
        XCTAssertTrue(prompt.contains("[REDACTED]"))
        // Non-secret structure is preserved.
        XCTAssertTrue(prompt.contains("Proof of concept"))
    }

    func testRedactVariousSecretForms() {
        XCTAssertFalse(FindingExplainer.redact("password: hunter2").contains("hunter2"))
        XCTAssertFalse(FindingExplainer.redact("token=abc.def.ghi").contains("abc.def.ghi"))
        XCTAssertFalse(FindingExplainer.redact("Authorization: Bearer eyJabc123").contains("eyJabc123"))
        XCTAssertFalse(FindingExplainer.redact("https://user:p4ss@host/x").contains("p4ss"))
        XCTAssertFalse(FindingExplainer.redact("key AKIAIOSFODNN7EXAMPLE here").contains("AKIAIOSFODNN7EXAMPLE"))
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
        XCTAssertFalse(FindingExplainer.redact(pem).contains("MIIabc"))
    }

    func testRedactLeavesBenignTextUnchanged() {
        let benign = "The service exposes an outdated banner on port 22."
        XCTAssertEqual(FindingExplainer.redact(benign), benign)
    }

    // MARK: - Runner paths (graceful, never crashes)

    @MainActor
    func testRunnerUnavailableWhenNoBackend() async {
        let model = FindingExplainerModel(
            backendAvailable: { false },
            runGenerate: { _, _ in XCTFail("must not call the LLM when no backend"); return "" }
        )
        await model.explain(sampleFinding())
        guard case .unavailable(let reason) = model.state else {
            return XCTFail("expected .unavailable, got \(model.state)")
        }
        XCTAssertTrue(reason.contains("unavailable"))
    }

    @MainActor
    func testRunnerSuccessProducesSummary() async {
        let model = FindingExplainerModel(
            backendAvailable: { true },
            runGenerate: { prompt, system in
                XCTAssertTrue(system.contains("security analyst"))
                XCTAssertFalse(prompt.isEmpty)
                return "What it means: bad. Why it matters: worse. Suggested remediation: patch."
            }
        )
        await model.explain(sampleFinding())
        guard case .done(let text) = model.state else {
            return XCTFail("expected .done, got \(model.state)")
        }
        XCTAssertTrue(text.contains("Suggested remediation"))
    }

    @MainActor
    func testRunnerEmptyResponseFails() async {
        let model = FindingExplainerModel(
            backendAvailable: { true },
            runGenerate: { _, _ in "   " }
        )
        await model.explain(sampleFinding())
        guard case .failed = model.state else {
            return XCTFail("expected .failed, got \(model.state)")
        }
    }

    @MainActor
    func testRunnerThrownErrorIsSurfacedNotCrashed() async {
        let model = FindingExplainerModel(
            backendAvailable: { true },
            runGenerate: { _, _ in throw LLMError.noBackendAvailable }
        )
        await model.explain(sampleFinding())
        guard case .failed = model.state else {
            return XCTFail("expected .failed, got \(model.state)")
        }
    }

    @MainActor
    func testRunnerNeverSendsSecretToGenerate() async {
        let poc = "password=Hunter2 api_key=sk-live-XYZ"
        var capturedPrompt = ""
        let model = FindingExplainerModel(
            backendAvailable: { true },
            runGenerate: { prompt, _ in capturedPrompt = prompt; return "ok" }
        )
        await model.explain(sampleFinding(poc: poc))
        XCTAssertFalse(capturedPrompt.contains("Hunter2"))
        XCTAssertFalse(capturedPrompt.contains("sk-live-XYZ"))
    }
}
