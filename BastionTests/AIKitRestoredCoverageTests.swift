//
//  AIKitRestoredCoverageTests.swift
//  BastionTests
//
//  Restores the behavior coverage of the three test files removed in the NovaAIKit
//  migration (AIBackendTests, LoadBalancerTests, OpenRouterFailoverTests), rewritten
//  against NovaAIKit / AppAI. Each old assertion is re-expressed against the kit's
//  public contract. Never touches the real network or Keychain (in-memory stores +
//  stub URLProtocols).
//

import XCTest
import NovaAIKit
@testable import Bastion

final class AIKitRestoredCoverageTests: XCTestCase {

    @MainActor
    private func makeAI(_ s: NovaAISettings = NovaAISettings(),
                        keys: [NovaAIBackend: String] = [:],
                        proto: URLProtocol.Type = RefuseAllProtocol.self) -> NovaAI {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [proto]
        let ai = NovaAI(configuration: NovaAIConfiguration(appID: "bastion", appName: "Bastion"),
                        storage: NovaAIMemoryStorage(s), keyStore: NovaAIMemoryKeyStore(),
                        session: URLSession(configuration: cfg), sleep: { _ in })
        for (b, v) in keys { _ = ai.setAPIKey(v, for: b) }
        return ai
    }

    // =====================================================================
    // MARK: - Replaces AIBackendTests (backend enum + errors + app models)
    // =====================================================================

    /// Old: allCases.count == 6 and contains the five local backends + auto.
    /// New: the full NovaAIKit roster (9) still contains every backend the app used.
    func testAllBackendCases() {
        let all = NovaAIBackend.allCases
        XCTAssertEqual(all.count, 9)
        for b in [NovaAIBackend.ollama, .mlx, .tinyLLM, .tinyChat, .openWebUI, .auto] {
            XCTAssertTrue(all.contains(b), "missing \(b)")
        }
    }

    /// Old: every backend has a non-empty icon and description.
    func testBackendIconsAndSummaries() {
        for b in NovaAIBackend.allCases {
            XCTAssertFalse(b.symbolName.isEmpty, "\(b) needs a symbol")
            XCTAssertFalse(b.summary.isEmpty, "\(b) needs a summary")
            XCTAssertFalse(b.displayName.isEmpty, "\(b) needs a display name")
        }
    }

    /// Old: AIBackend was Codable and round-tripped.
    func testBackendCodableRoundTrip() throws {
        let data = try JSONEncoder().encode(NovaAIBackend.ollama)
        XCTAssertEqual(try JSONDecoder().decode(NovaAIBackend.self, from: data), .ollama)
    }

    /// Old: tested the human-readable rawValues ("Ollama", "MLX Toolkit", "Auto (Prefer Ollama)", …).
    /// New: those exact legacy display names still resolve, via `init?(legacyName:)`.
    func testLegacyDisplayNamesStillResolve() {
        XCTAssertEqual(NovaAIBackend(legacyName: "Ollama"), .ollama)
        XCTAssertEqual(NovaAIBackend(legacyName: "MLX Toolkit"), .mlx)
        XCTAssertEqual(NovaAIBackend(legacyName: "TinyLLM"), .tinyLLM)
        XCTAssertEqual(NovaAIBackend(legacyName: "TinyChat"), .tinyChat)
        XCTAssertEqual(NovaAIBackend(legacyName: "OpenWebUI"), .openWebUI)
        XCTAssertEqual(NovaAIBackend(legacyName: "Auto (Prefer Ollama)"), .auto)
        // Removed clouds collapse to Auto rather than vanishing.
        XCTAssertEqual(NovaAIBackend(legacyName: "Google Cloud AI"), .auto)
        XCTAssertEqual(NovaAIBackend(legacyName: "IBM Watson"), .auto)
    }

    /// Old: AIBackendError cases had meaningful errorDescriptions (noBackendAvailable, MLX, embeddings…).
    /// New: the equivalent NovaAIError cases carry descriptions.
    func testErrorDescriptions() {
        XCTAssertTrue(NovaAIError.noBackendAvailable.errorDescription?.contains("No AI backend") ?? false)
        XCTAssertNotNil(NovaAIError.disabled.errorDescription)
        XCTAssertNotNil(NovaAIError.timedOut.errorDescription)
        XCTAssertNotNil(NovaAIError.emptyResponse.errorDescription)
        XCTAssertTrue(NovaAIError.insecureTransport("example.com").errorDescription?.lowercased().contains("https") ?? false)
        XCTAssertNotNil(NovaAIError.missingKey(.openRouter).errorDescription)
        XCTAssertEqual(NovaAIValidationError("why").errorDescription, "why")
    }

    // --- App planning models (unchanged by the migration; coverage preserved) ---

    func testAttackPlanConstruction() {
        let device = Device(ipAddress: "192.168.1.10")
        let target = PriorityTarget(
            device: device,
            reason: "Most vulnerable",
            attackSequence: ["port_scan", "default_creds"],
            successProbability: 85,
            timeToCompromise: "30 seconds",
            pivotOpportunities: ["SSH key reuse"]
        )
        let chain = AttackChain(description: "Pi to NAS", steps: ["a", "b", "c"])
        let plan = AttackPlan(priorityTargets: [target], attackChains: [chain], overallStrategy: "Start with IoT")
        XCTAssertEqual(plan.priorityTargets.count, 1)
        XCTAssertEqual(plan.attackChains.count, 1)
        XCTAssertEqual(plan.overallStrategy, "Start with IoT")
        XCTAssertEqual(plan.priorityTargets[0].successProbability, 85)
        XCTAssertEqual(plan.attackChains[0].steps.count, 3)
    }

    func testPostExploitationPlan() {
        let plan = PostExploitationPlan(
            recommendations: ["Check /etc/shadow", "Enumerate local network"],
            lateralMovementTargets: ["192.168.1.20 via SSH"],
            privilegeEscalationPaths: ["SUID binary abuse"],
            persistenceMechanisms: ["Cron job backdoor"]
        )
        XCTAssertEqual(plan.recommendations.count, 2)
        XCTAssertEqual(plan.lateralMovementTargets.count, 1)
        XCTAssertEqual(plan.privilegeEscalationPaths.count, 1)
        XCTAssertEqual(plan.persistenceMechanisms.count, 1)
    }

    func testAttackRecommendation() {
        let rec = AttackRecommendation(
            name: "SSH Default Credentials", type: .credentialAttack, successProbability: 40,
            impact: "Shell access", stealth: "Low detection", reasoning: "Default credentials"
        )
        XCTAssertEqual(rec.name, "SSH Default Credentials")
        XCTAssertEqual(rec.type, .credentialAttack)
        XCTAssertEqual(rec.successProbability, 40)
        XCTAssertNotNil(rec.id)
    }

    // =====================================================================
    // MARK: - Replaces LoadBalancerTests (model discovery + failover + health)
    // =====================================================================

    /// Old: ModelRegistry.parseOllamaTags mapped the /api/tags payload to models.
    /// New: listModels(for: .ollama) parses the same payload via the injected session.
    @MainActor
    func testListModelsParsesOllamaTags() async {
        StubRespondProtocol.body = Data(#"{"models":[{"name":"mistral:latest"},{"name":"llama3.2:3b"}]}"#.utf8)
        StubRespondProtocol.status = 200
        let ai = makeAI(NovaAISettings(backend: .ollama), proto: StubRespondProtocol.self)
        let models = await ai.listModels(for: .ollama)
        XCTAssertTrue(models.contains("mistral:latest"))
        XCTAssertTrue(models.contains("llama3.2:3b"))
    }

    /// Old: parseOllamaTags on garbage returned empty.
    /// New: listModels falls back to the backend's fallback list rather than returning junk.
    @MainActor
    func testListModelsGarbageFallsBack() async {
        StubRespondProtocol.body = Data("nonsense".utf8)
        StubRespondProtocol.status = 200
        let ai = makeAI(NovaAISettings(backend: .openRouter), keys: [.openRouter: "sk-or-x"],
                        proto: StubRespondProtocol.self)
        let models = await ai.listModels(for: .openRouter)
        XCTAssertFalse(models.isEmpty) // fallbackModels, never garbage
    }

    /// Old: FailoverPlanner.defaultChain == [.ollama, .mlx, .openRouter] and preserved order.
    /// New: Auto's fixed order is local-first, keyed clouds last; ollama precedes mlx precedes openRouter.
    func testAutoFailoverOrder() {
        let order = NovaAIBackend.autoOrder
        XCTAssertEqual(order.first, .ollama)
        let iOllama = order.firstIndex(of: .ollama)!
        let iMLX = order.firstIndex(of: .mlx)!
        let iRouter = order.firstIndex(of: .openRouter)!
        XCTAssertLessThan(iOllama, iMLX)
        XCTAssertLessThan(iMLX, iRouter)
        XCTAssertEqual(NovaAIBackend.selectable.first, .auto)
    }

    /// Old: LoadBalancer picked the first healthy backend and skipped unreachable ones.
    /// New: refreshStatus probes the chain and selects the first reachable backend.
    @MainActor
    func testStatusPicksFirstReachable() async {
        StubRespondProtocol.body = Data(#"{"models":[{"name":"mistral:latest"}]}"#.utf8)
        StubRespondProtocol.status = 200
        let ai = makeAI(NovaAISettings(backend: .ollama), proto: StubRespondProtocol.self)
        await ai.refreshStatus()
        XCTAssertTrue(ai.status.isReachable)
        XCTAssertEqual(ai.status.activeBackend, .ollama)
    }

    /// Old: all-unhealthy returned nil (no backend).
    /// New: every backend refusing → offline, no active backend, feature still falls back.
    @MainActor
    func testStatusOfflineWhenAllUnreachable() async {
        let ai = makeAI(NovaAISettings(backend: .ollama))   // RefuseAllProtocol
        await ai.refreshStatus()
        XCTAssertFalse(ai.status.isReachable)
        XCTAssertNil(ai.status.activeBackend)
    }

    // =====================================================================
    // MARK: - Replaces OpenRouterFailoverTests (OpenRouter keyed/https/service)
    // =====================================================================

    /// Old: OpenRouterProvider.baseURL / chatCompletionsURL / modelsURL + displayName.
    /// New: the same endpoints and name live on the NovaAIBackend.
    func testOpenRouterEndpointsAndName() {
        XCTAssertEqual(NovaAIBackend.openRouter.defaultURL, "https://openrouter.ai/api/v1")
        XCTAssertEqual(NovaAIBackend.openRouter.chatPath, "/chat/completions")
        XCTAssertEqual(NovaAIBackend.openRouter.modelsPath, "/models")
        XCTAssertEqual(NovaAIBackend.openRouter.displayName, "OpenRouter")
    }

    /// Old: OpenRouter required a key; fallbackModels were non-empty.
    func testOpenRouterRequiresKeyAndHasFallbacks() {
        XCTAssertTrue(NovaAIBackend.openRouter.requiresKey)
        XCTAssertTrue(NovaAIBackend.openRouter.acceptsKey)
        XCTAssertFalse(NovaAIBackend.openRouter.fallbackModels.isEmpty)
        XCTAssertFalse(NovaAIBackend.ollama.requiresKey)
    }

    /// New (security): the Keychain service name is app-namespaced.
    func testKeychainServiceName() {
        let c = NovaAIConfiguration(appID: "bastion", appName: "Bastion")
        XCTAssertEqual(c.keychainService(for: .openRouter), "com.jkoch.bastion.openrouter")
        XCTAssertEqual(c.keychainService(for: .openAI), "com.jkoch.bastion.openai")
    }

    /// New: OpenRouter default is https (keys are never sent over plain http).
    func testOpenRouterIsHTTPS() {
        XCTAssertTrue(NovaAIBackend.openRouter.defaultURL.hasPrefix("https://"))
        XCTAssertTrue(NovaAIBackend.openAI.defaultURL.hasPrefix("https://"))
    }

    /// Old/New: with OpenRouter selected and no key stored, a request does not reach the network
    /// and the feature falls back cleanly (missing key is treated as unavailable).
    @MainActor
    func testOpenRouterMissingKeyFallsBack() async {
        let ai = makeAI(NovaAISettings(backend: .openRouter))   // no key stored
        let r = await ai.text(NovaAIRequest(prompt: "hi")) { "offline-fallback" }
        XCTAssertEqual(r.value, "offline-fallback")
        XCTAssertFalse(r.isAI)
        let probe = await ai.testConnection(.openRouter)
        XCTAssertFalse(probe.reachable)
    }

    /// New: a probe with a stored key but a refusing network is still unreachable (no false "up").
    @MainActor
    func testOpenRouterKeyedButOfflineIsUnreachable() async {
        let ai = makeAI(NovaAISettings(backend: .openRouter), keys: [.openRouter: "sk-or-abc"])
        XCTAssertTrue(ai.hasAPIKey(for: .openRouter))
        let probe = await ai.testConnection(.openRouter)
        XCTAssertFalse(probe.reachable)
    }

    /// New (retry/timeout): the configured timeout stays within the kit's safe range.
    func testTimeoutIsBounded() {
        var s = NovaAISettings()
        s.timeout = 5
        XCTAssertTrue(NovaAISettings.timeoutRange.contains(s.timeout))
    }
}

/// A stub that answers every request with a fixed body + status. Set its statics per test.
final class StubRespondProtocol: URLProtocol {
    nonisolated(unsafe) static var body = Data()
    nonisolated(unsafe) static var status = 200

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let resp = HTTPURLResponse(url: request.url ?? URL(string: "http://localhost")!,
                                   statusCode: Self.status, httpVersion: nil,
                                   headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Self.body)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
