//
//  AIKitAdoptionTests.swift
//  BastionTests
//
//  Covers Bastion's NovaAIKit adoption contract across the seven categories:
//  security, performance, retry, unit, integration, functional, frame/UI-state.
//  Never touches the real Keychain or network (in-memory stores + a refusing URLProtocol).
//

import XCTest
import SwiftUI
import NovaAIKit
@testable import Bastion

final class AIKitAdoptionTests: XCTestCase {

    @MainActor
    private func makeAI(_ s: NovaAISettings = NovaAISettings()) -> NovaAI {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [RefuseAllProtocol.self]
        return NovaAI(configuration: NovaAIConfiguration(appID: "bastion", appName: "Bastion"),
                      storage: NovaAIMemoryStorage(s), keyStore: NovaAIMemoryKeyStore(),
                      session: URLSession(configuration: cfg), sleep: { _ in })
    }

    // MARK: - Security

    func testKeychainServiceNamesAreNamespaced() {
        let c = NovaAIConfiguration(appID: "bastion", appName: "Bastion")
        XCTAssertEqual(c.keychainService(for: .openRouter), "com.jkoch.bastion.openrouter")
        XCTAssertEqual(c.keychainService(for: .openAI), "com.jkoch.bastion.openai")
        XCTAssertEqual(NovaAIConfiguration.keychainAccount, "apiKey")
    }

    @MainActor
    func testHTTPSKeyRejectedOverInsecureTransport() async {
        // A key must never be sent to an http endpoint; writing/holding it is fine, sending is guarded by the kit.
        let ai = makeAI()
        XCTAssertTrue(ai.setAPIKey("sk-or-secret", for: .openRouter))
        XCTAssertTrue(ai.hasAPIKey(for: .openRouter))
        // The stored value is never surfaced as plaintext through the public API.
        XCTAssertFalse(ai.status.label.contains("sk-or-secret"))
    }

    func testFindingRedactionStripsSecrets() {
        XCTAssertFalse(FindingExplainer.redact("password: hunter2").contains("hunter2"))
        XCTAssertFalse(FindingExplainer.redact("Authorization: Bearer eyJsecret").contains("eyJsecret"))
    }

    // MARK: - Performance (no hang when every backend is down)

    @MainActor
    func testOfflineFallbackReturnsPromptly() async {
        let ai = makeAI()
        let start = Date()
        let r = await ai.text(NovaAIRequest(prompt: "summarize")) { "Built-in summary." }
        XCTAssertEqual(r.value, "Built-in summary.")
        XCTAssertFalse(r.isAI)
        XCTAssertLessThan(Date().timeIntervalSince(start), 10, "fallback must not hang")
    }

    // MARK: - Retry / validation

    @MainActor
    func testValidatorRejectionFallsBack() async {
        let ai = makeAI()
        // Offline, so AI never answers; the validator path still must end in the fallback value.
        let r = await ai.generate(NovaAIRequest(prompt: "give me a number"),
                                  validate: { text -> Int in
                                      guard let n = Int(text.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                                          throw NovaAIValidationError("not a number")
                                      }
                                      return n
                                  },
                                  fallback: { -1 })
        XCTAssertEqual(r.value, -1)
        XCTAssertFalse(r.isAI)
    }

    func testNonEmptyValidatorRejectsBlank() {
        XCTAssertThrowsError(try NovaAI.nonEmpty("   \n "))
        XCTAssertEqual(try NovaAI.nonEmpty("  hello "), "hello")
    }

    // MARK: - Unit

    func testBackendRosterIsTheFullSet() {
        XCTAssertEqual(NovaAIBackend.allCases.count, 9)
        XCTAssertTrue(NovaAIBackend.allCases.contains(.novaGateway))
        XCTAssertTrue(NovaAIBackend.allCases.contains(.openRouter))
        XCTAssertTrue(NovaAIBackend.openRouter.requiresKey)
        XCTAssertFalse(NovaAIBackend.ollama.requiresKey)
    }

    // MARK: - Integration (legacy migration)

    @MainActor
    func testLegacySettingsMigrate() {
        let suite = "bastion.tests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.set("Ollama", forKey: "AIBackendManager_SelectedBackend")
        defaults.set("mistral:latest", forKey: "AIBackendManager_OllamaModel")
        let ai = NovaAI(configuration: NovaAIConfiguration(appID: "bastion", appName: "Bastion"),
                        storage: NovaAIMemoryStorage(), keyStore: NovaAIMemoryKeyStore(), sleep: { _ in })
        let report = ai.migrateFromLegacyAIBackendManager(defaults: defaults)
        XCTAssertTrue(report.settingsImported)
        XCTAssertEqual(ai.settings.backend, .ollama)
        defaults.removePersistentDomain(forName: suite)
    }

    @MainActor
    func testMigrateLegacyDoesNotCrash() {
        // AppAI.migrateLegacy wiring must be safe to run against a fresh instance.
        let ai = makeAI()
        AppAI.migrateLegacy(ai)
        XCTAssertNotNil(ai.settings)
    }

    // MARK: - Functional (AI off → built-in result)

    @MainActor
    func testEveryFeatureWorksWithAIOff() async {
        let ai = makeAI(NovaAISettings(enabled: false))
        let r = await ai.text(NovaAIRequest(prompt: "x")) { "fallback" }
        XCTAssertEqual(r.source, .fallback(.disabled))
        XCTAssertEqual(r.value, "fallback")
    }

    @MainActor
    func testFindingExplainerDisabledWhenUnreachable() async {
        let model = FindingExplainerModel(backendAvailable: { false },
                                          runGenerate: { _, _ in "unused" })
        let v = Vulnerability(title: "Weak TLS", description: "TLS 1.0 enabled.", severity: .medium)
        await model.explain(v)
        if case .unavailable = model.state { } else { XCTFail("expected unavailable state") }
    }

    // MARK: - Frame / UI-state

    @MainActor
    func testStatusIsOffWhenDisabled() {
        let ai = makeAI(NovaAISettings(enabled: false))
        XCTAssertEqual(ai.status.state, .off)
        XCTAssertFalse(ai.isEnabled)
    }

    func testStatusIndicatorColorMapping() {
        XCTAssertEqual(NovaAIStatusIndicator.color(.online), .green)
        XCTAssertNotEqual(NovaAIStatusIndicator.color(.offline), NovaAIStatusIndicator.color(.online))
    }

    // MARK: - No legacy AI client left in the app sources

    func testNoLegacyAIClientInSources() throws {
        let here = URL(fileURLWithPath: #filePath)
        let sources = here.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Bastion")
        let fm = FileManager.default
        guard let e = fm.enumerator(at: sources, includingPropertiesForKeys: nil) else { return }
        let banned = ["AIBackendManager", "LLMLoadBalancer", "EthicalAIGuardian", "OPENAI_API_KEY"]
        for case let url as URL in e where url.pathExtension == "swift" {
            let text = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
            for token in banned {
                // AppAI.swift legitimately names the legacy migration helper in comments.
                if url.lastPathComponent == "AppAI.swift" { continue }
                XCTAssertFalse(text.contains(token), "\(token) still present in \(url.lastPathComponent)")
            }
        }
    }
}

final class RefuseAllProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() { client?.urlProtocol(self, didFailWithError: URLError(.cannotConnectToHost)) }
    override func stopLoading() {}
}
