//
//  LLMLoadBalancer.swift
//  Bastion
//
//  Bastion's multi-model LLM load balancer. Mirrors the balanced-dispatch wiring
//  of AIStudio's LLMBackendManager (kochj23/AIStudio) so work is spread across
//  every enabled model on the machine — the single-user version of how Nova's
//  gateway balances load.
//
//  HARD INVARIANT: Nova is NEVER required. With zero Nova this still works using
//  local (Ollama / MLX) and frontier (OpenRouter) models. The Nova Gateway is one
//  OPTIONAL backend: a failed health check simply drops it from the pool and
//  everything else keeps working. Nothing here hard-depends on Nova / PG / the
//  gateway.
//
//  Author: Jordan Koch
//

import Foundation
import Combine

// MARK: - Settings (three toggles, persisted)

/// Load-balancer settings persisted in `UserDefaults`. The three toggles (all
/// local / all frontier / Nova Gateway) and the gateway URL live here; the
/// OpenRouter API key never does (it lives in the Keychain).
@MainActor
final class LLMBalancerSettings: ObservableObject {
    static let shared = LLMBalancerSettings()

    @Published var useAllLocalModels: Bool { didSet { defaults.set(useAllLocalModels, forKey: Keys.useAllLocalModels) } }
    @Published var enableAllFrontierModels: Bool { didSet { defaults.set(enableAllFrontierModels, forKey: Keys.enableAllFrontierModels) } }
    @Published var useNovaGateway: Bool { didSet { defaults.set(useNovaGateway, forKey: Keys.useNovaGateway) } }
    @Published var novaGatewayURL: String { didSet { defaults.set(novaGatewayURL, forKey: Keys.novaGatewayURL) } }
    @Published var ollamaURL: String { didSet { defaults.set(ollamaURL, forKey: Keys.ollamaURL) } }

    private let defaults = UserDefaults.standard

    private enum Keys {
        static let useAllLocalModels = "LLMBalancer_useAllLocalModels"
        static let enableAllFrontierModels = "LLMBalancer_enableAllFrontierModels"
        static let useNovaGateway = "LLMBalancer_useNovaGateway"
        static let novaGatewayURL = "LLMBalancer_novaGatewayURL"
        static let ollamaURL = "LLMBalancer_ollamaURL"
    }

    private init() {
        let d = UserDefaults.standard
        self.useAllLocalModels = d.object(forKey: Keys.useAllLocalModels) as? Bool ?? false
        self.enableAllFrontierModels = d.object(forKey: Keys.enableAllFrontierModels) as? Bool ?? false
        self.useNovaGateway = d.object(forKey: Keys.useNovaGateway) as? Bool ?? false
        self.novaGatewayURL = d.string(forKey: Keys.novaGatewayURL) ?? ModelRegistry.novaGatewayDefaultURL
        self.ollamaURL = d.string(forKey: Keys.ollamaURL) ?? ModelRegistry.ollamaBaseURL
    }
}

// MARK: - Load balancer service

/// Owns backend configurations, runs health checks, and provides a single
/// `generate` entry point that spreads work across the enabled model pool.
@MainActor
final class LLMLoadBalancer: ObservableObject {
    static let shared = LLMLoadBalancer()

    @Published var backends: [LLMBackendType: LLMBackendConfiguration] = [:]
    @Published var resolvedBackend: LLMBackendType?
    @Published var isRefreshing = false

    /// Models currently discovered on this machine for the enabled pool.
    @Published var discoveredModels: [DiscoveredModel] = []

    /// OpenRouter model ids for the frontier pool (falls back to a popular set).
    @Published var openRouterModels: [String] = OpenRouterProvider.fallbackModels

    /// Ordered preference chain for automatic failover: local-first, then frontier.
    let failoverChain: [LLMBackendType] = FailoverPlanner.defaultChain

    /// Pure, network-free balancer that spreads work across the enabled pool.
    let balancer = LoadBalancer()

    /// Balancer policy (least-busy mirrors how Nova's gateway spreads load).
    var balancerPolicy: BalancerPolicy = .leastBusy

    /// Keychain-backed store for the OpenRouter API key.
    let openRouterKeychain = KeychainStore()

    /// True when any load-balancing toggle is on → dispatch through the balanced
    /// path rather than plain automatic failover.
    var isBalancingEnabled: Bool {
        let s = LLMBalancerSettings.shared
        return s.useAllLocalModels || s.enableAllFrontierModels || s.useNovaGateway
    }

    private let session: URLSession

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        self.session = URLSession(configuration: config)

        let settings = LLMBalancerSettings.shared
        backends[.ollama] = LLMBackendConfiguration(type: .ollama, url: settings.ollamaURL)
        backends[.mlx] = LLMBackendConfiguration(type: .mlx)
        backends[.openRouter] = LLMBackendConfiguration(type: .openRouter)
        backends[.novaGateway] = LLMBackendConfiguration(type: .novaGateway, url: settings.novaGatewayURL)
    }

    // MARK: OpenRouter API key (Keychain-backed)

    func setOpenRouterAPIKey(_ key: String) {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { openRouterKeychain.delete() } else { openRouterKeychain.set(trimmed) }
    }

    func openRouterAPIKey() -> String? { openRouterKeychain.get() }
    var hasOpenRouterKey: Bool { openRouterKeychain.hasValue }

    // MARK: Availability

    /// True when at least one backend can currently serve a request. Used to
    /// gate the "Explain this finding" feature so it never crashes when offline.
    func anyBackendAvailable() async -> Bool {
        for backend in [LLMBackendType.ollama, .mlx, .openRouter, .novaGateway] {
            if await checkAvailability(backend) { return true }
        }
        return false
    }

    /// Quick availability probe for a single backend.
    func checkAvailability(_ type: LLMBackendType) async -> Bool {
        switch type {
        case .ollama: return await checkOllama().isConnected
        case .mlx: return await checkMLX().isConnected
        case .openRouter: return await checkOpenRouter().isConnected
        case .novaGateway: return await checkNovaGateway().isConnected
        case .auto: return false
        }
    }

    func refreshAllBackends() async {
        isRefreshing = true
        defer { isRefreshing = false }
        backends[.ollama]?.url = LLMBalancerSettings.shared.ollamaURL
        backends[.novaGateway]?.url = LLMBalancerSettings.shared.novaGatewayURL
        for backend in [LLMBackendType.ollama, .mlx, .openRouter, .novaGateway] {
            let available = await checkAvailability(backend)
            backends[backend]?.status = available ? .connected : .disconnected
        }
    }

    func refreshBackend(_ type: LLMBackendType) async {
        backends[type]?.status = .checking
        let available = await checkAvailability(type)
        backends[type]?.status = available ? .connected : .disconnected
    }

    // MARK: Health checks

    private func checkOllama() async -> BackendStatus {
        let base = backends[.ollama]?.url ?? ModelRegistry.ollamaBaseURL
        guard let url = URL(string: "\(base)/api/tags") else { return .disconnected }
        do {
            let (_, response) = try await session.data(from: url)
            return (response as? HTTPURLResponse)?.statusCode == 200 ? .connected : .disconnected
        } catch { return .disconnected }
    }

    private func checkMLX() async -> BackendStatus {
        // MLX runs in-process via the local `mlx_lm` toolchain. Presence of a
        // Python interpreter or the mlx_lm CLI is enough to consider it usable.
        let fm = FileManager.default
        let candidates = ["/opt/homebrew/bin/mlx_lm.generate", "/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"]
        return candidates.contains(where: { fm.fileExists(atPath: $0) }) ? .connected : .disconnected
    }

    private func checkOpenRouter() async -> BackendStatus {
        guard let key = openRouterAPIKey(), !key.isEmpty,
              let url = URL(string: OpenRouterProvider.modelsURL) else { return .disconnected }
        var request = URLRequest(url: url)
        for (header, value) in OpenRouterProvider.authHeaders(apiKey: key) {
            request.setValue(value, forHTTPHeaderField: header)
        }
        do {
            let (data, response) = try await session.data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { return .disconnected }
            let models = OpenRouterProvider.parseModels(data)
            if !models.isEmpty { openRouterModels = models }
            return .connected
        } catch { return .disconnected }
    }

    private func checkNovaGateway() async -> BackendStatus {
        let base = backends[.novaGateway]?.url ?? ModelRegistry.novaGatewayDefaultURL
        let candidates = ["\(base)/v1/models", "\(base)/"].compactMap { URL(string: $0) }
        for url in candidates {
            do {
                let (_, response) = try await session.data(from: url)
                if (response as? HTTPURLResponse)?.statusCode == 200 { return .connected }
            } catch { continue }
        }
        return .disconnected
    }

    // MARK: - Unified generation entry

    /// Generate a completion. When any balancing toggle is on, spread work across
    /// the healthy enabled pool; otherwise fall through to automatic failover over
    /// the preference chain. Throws `LLMError.noBackendAvailable` when nothing is
    /// reachable — callers must handle that gracefully (never crash).
    func generate(
        prompt: String,
        systemPrompt: String? = nil,
        messages: [ChatMessage] = [],
        temperature: Float = 0.4,
        maxTokens: Int = 1024
    ) async throws -> String {
        if isBalancingEnabled {
            if let result = try await generateBalanced(prompt: prompt, systemPrompt: systemPrompt, messages: messages, temperature: temperature, maxTokens: maxTokens) {
                return result
            }
        }
        return try await generateWithFailover(prompt: prompt, systemPrompt: systemPrompt, messages: messages, temperature: temperature, maxTokens: maxTokens)
    }

    // MARK: - Multi-model load balancing

    /// Discover the enabled balancer pool honoring the three toggles. Resilient:
    /// any unreachable source contributes zero models.
    func discoverEnabledPool() async -> [DiscoveredModel] {
        let settings = LLMBalancerSettings.shared
        let ollamaBase = backends[.ollama]?.url ?? ModelRegistry.ollamaBaseURL
        let novaURL = backends[.novaGateway]?.url ?? settings.novaGatewayURL

        var ollama: [DiscoveredModel] = []
        var mlx: [DiscoveredModel] = []
        var frontier: [DiscoveredModel] = []

        if settings.useAllLocalModels {
            ollama = await ModelRegistry.discoverOllama(baseURL: ollamaBase, session: session)
            mlx = ModelRegistry.discoverMLX()
        }
        if settings.enableAllFrontierModels {
            frontier = ModelRegistry.frontierModels(from: openRouterModels)
        }
        let nova = settings.useNovaGateway ? ModelRegistry.novaGatewayModel(url: novaURL) : nil

        let pool = ModelRegistry.assemblePool(
            ollama: ollama,
            mlx: mlx,
            frontier: frontier,
            novaGateway: nova,
            useAllLocalModels: settings.useAllLocalModels,
            enableAllFrontierModels: settings.enableAllFrontierModels,
            useNovaGateway: settings.useNovaGateway
        )
        discoveredModels = pool
        return pool
    }

    /// Build a `[modelId: Bool]` health map for `pool` by probing each distinct
    /// backend once (health-gating, composed with `FailoverPlanner` semantics).
    private func healthMap(for pool: [DiscoveredModel]) async -> [String: Bool] {
        var backendHealth: [LLMBackendType: Bool] = [:]
        for backend in Set(pool.map { $0.backend }) {
            backendHealth[backend] = await checkAvailability(backend)
        }
        var map: [String: Bool] = [:]
        for model in pool { map[model.id] = backendHealth[model.backend] ?? false }
        return map
    }

    /// Balanced dispatch: pick a model via the `LoadBalancer` over the healthy
    /// enabled pool and route it through the generic path. Returns nil when no
    /// pool / healthy model exists so the caller can fall back cleanly.
    private func generateBalanced(
        prompt: String,
        systemPrompt: String?,
        messages: [ChatMessage],
        temperature: Float,
        maxTokens: Int
    ) async throws -> String? {
        let pool = await discoverEnabledPool()
        guard !pool.isEmpty else { return nil }

        let health = await healthMap(for: pool)
        var remaining = pool
        var lastError: Error?

        while let choice = balancer.next(pool: remaining, health: health, policy: balancerPolicy) {
            balancer.checkOut(choice.id)
            do {
                let result = try await dispatchBalanced(model: choice, prompt: prompt, systemPrompt: systemPrompt, messages: messages, temperature: temperature, maxTokens: maxTokens)
                balancer.checkIn(choice.id)
                resolvedBackend = choice.backend
                return result
            } catch {
                balancer.checkIn(choice.id)
                lastError = error
                remaining.removeAll { $0.id == choice.id }
                continue
            }
        }
        if let lastError = lastError { throw lastError }
        return nil
    }

    /// Route a single balancer-selected model through the appropriate backend
    /// implementation (all OpenAI-compatible backends ride the generic path).
    private func dispatchBalanced(
        model: DiscoveredModel,
        prompt: String,
        systemPrompt: String?,
        messages: [ChatMessage],
        temperature: Float,
        maxTokens: Int
    ) async throws -> String {
        switch model.backend {
        case .ollama:
            return try await generateWithOllama(prompt: prompt, systemPrompt: systemPrompt, messages: messages, temperature: temperature, maxTokens: maxTokens, model: model.modelName)
        case .mlx:
            return try await generateWithMLX(prompt: prompt, systemPrompt: systemPrompt, maxTokens: maxTokens, model: model.modelName)
        case .openRouter:
            guard let key = openRouterAPIKey(), !key.isEmpty else { throw LLMError.noBackendAvailable }
            return try await generateOpenAICompatible(endpoint: model.endpoint, model: model.modelName, headers: OpenRouterProvider.authHeaders(apiKey: key), prompt: prompt, systemPrompt: systemPrompt, messages: messages, temperature: temperature, maxTokens: maxTokens)
        case .novaGateway:
            return try await generateOpenAICompatible(endpoint: model.endpoint, model: model.modelName, headers: [:], prompt: prompt, systemPrompt: systemPrompt, messages: messages, temperature: temperature, maxTokens: maxTokens)
        case .auto:
            throw LLMError.noBackendAvailable
        }
    }

    // MARK: - Automatic failover

    /// Probe the preference chain, then try each healthy backend in order,
    /// falling through on failure.
    private func generateWithFailover(
        prompt: String,
        systemPrompt: String?,
        messages: [ChatMessage],
        temperature: Float,
        maxTokens: Int
    ) async throws -> String {
        var chain = failoverChain
        // Nova Gateway is an optional extra failover target when enabled.
        if LLMBalancerSettings.shared.useNovaGateway { chain.append(.novaGateway) }

        var availability: [LLMBackendType: Bool] = [:]
        for backend in chain { availability[backend] = await checkAvailability(backend) }
        let healthy = FailoverPlanner.orderedHealthy(chain: chain, availability: availability)
        guard !healthy.isEmpty else { throw LLMError.noBackendAvailable }

        var lastError: Error = LLMError.noBackendAvailable
        for backend in healthy {
            do {
                let result = try await generate(on: backend, prompt: prompt, systemPrompt: systemPrompt, messages: messages, temperature: temperature, maxTokens: maxTokens)
                resolvedBackend = backend
                return result
            } catch {
                lastError = error
                continue
            }
        }
        throw lastError
    }

    private func generate(
        on backend: LLMBackendType,
        prompt: String,
        systemPrompt: String?,
        messages: [ChatMessage],
        temperature: Float,
        maxTokens: Int
    ) async throws -> String {
        switch backend {
        case .ollama:
            return try await generateWithOllama(prompt: prompt, systemPrompt: systemPrompt, messages: messages, temperature: temperature, maxTokens: maxTokens, model: nil)
        case .mlx:
            return try await generateWithMLX(prompt: prompt, systemPrompt: systemPrompt, maxTokens: maxTokens, model: nil)
        case .openRouter:
            guard let key = openRouterAPIKey(), !key.isEmpty else { throw LLMError.noBackendAvailable }
            return try await generateOpenAICompatible(endpoint: OpenRouterProvider.chatCompletionsURL, model: openRouterModels.first ?? OpenRouterProvider.defaultModel, headers: OpenRouterProvider.authHeaders(apiKey: key), prompt: prompt, systemPrompt: systemPrompt, messages: messages, temperature: temperature, maxTokens: maxTokens)
        case .novaGateway:
            let base = backends[.novaGateway]?.url ?? ModelRegistry.novaGatewayDefaultURL
            return try await generateOpenAICompatible(endpoint: "\(base)/v1/chat/completions", model: "nova", headers: [:], prompt: prompt, systemPrompt: systemPrompt, messages: messages, temperature: temperature, maxTokens: maxTokens)
        case .auto:
            throw LLMError.noBackendAvailable
        }
    }

    // MARK: - Backend generation implementations

    private func generateWithOllama(
        prompt: String,
        systemPrompt: String?,
        messages: [ChatMessage],
        temperature: Float,
        maxTokens: Int,
        model: String?
    ) async throws -> String {
        let base = backends[.ollama]?.url ?? ModelRegistry.ollamaBaseURL
        guard let url = URL(string: "\(base)/api/chat") else { throw LLMError.invalidURL }

        var apiMessages: [[String: String]] = []
        if let system = systemPrompt, !system.isEmpty { apiMessages.append(["role": "system", "content": system]) }
        for msg in messages where msg.role != .system { apiMessages.append(["role": msg.role.rawValue, "content": msg.content]) }
        apiMessages.append(["role": "user", "content": prompt])

        let body: [String: Any] = [
            "model": model ?? "mistral:latest",
            "messages": apiMessages,
            "stream": false,
            "options": ["temperature": temperature, "num_predict": maxTokens]
        ]

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        request.timeoutInterval = 120

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw LLMError.httpError((response as? HTTPURLResponse)?.statusCode ?? 0)
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let message = json["message"] as? [String: Any],
              let content = message["content"] as? String else {
            throw LLMError.noResponse
        }
        return content
    }

    /// Non-streaming generation against a full OpenAI-compatible endpoint URL.
    /// Used by the balanced dispatch path, OpenRouter, and the Nova Gateway.
    private func generateOpenAICompatible(
        endpoint: String,
        model: String,
        headers: [String: String],
        prompt: String,
        systemPrompt: String?,
        messages: [ChatMessage],
        temperature: Float,
        maxTokens: Int
    ) async throws -> String {
        let apiMessages = OpenAICompatibleRequest.chatMessages(prompt: prompt, systemPrompt: systemPrompt, history: messages)
        var request = try OpenAICompatibleRequest.build(
            endpoint: endpoint,
            model: model,
            messages: apiMessages,
            temperature: temperature,
            maxTokens: maxTokens,
            stream: false,
            headers: headers
        )
        request.timeoutInterval = 120

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw LLMError.httpError((response as? HTTPURLResponse)?.statusCode ?? 0)
        }

        struct OpenAIResponse: Codable {
            struct Choice: Codable {
                struct Message: Codable { let content: String }
                let message: Message
            }
            let choices: [Choice]
        }
        let decoded = try JSONDecoder().decode(OpenAIResponse.self, from: data)
        return decoded.choices.first?.message.content ?? ""
    }

    /// MLX runs in-process via the local `mlx_lm` toolchain. Ported from AIStudio.
    private func generateWithMLX(
        prompt: String,
        systemPrompt: String?,
        maxTokens: Int,
        model: String?
    ) async throws -> String {
        let mlxPath = "/opt/homebrew/bin/mlx_lm.generate"
        let pythonCandidates = ["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"]
        let pythonPath = pythonCandidates.first { FileManager.default.fileExists(atPath: $0) }

        guard FileManager.default.fileExists(atPath: mlxPath) || pythonPath != nil else {
            throw LLMError.mlxNotAvailable
        }

        var fullPrompt = prompt
        if let system = systemPrompt, !system.isEmpty { fullPrompt = "\(system)\n\n\(prompt)" }
        let modelName = model ?? "mlx-community/Llama-3.2-3B-Instruct-4bit"

        let promptFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("bastion_mlx_prompt_\(UUID().uuidString).txt")
        try fullPrompt.write(to: promptFile, atomically: true, encoding: .utf8)

        return try await withCheckedThrowingContinuation { continuation in
            defer { try? FileManager.default.removeItem(at: promptFile) }
            let process = Process()
            if FileManager.default.fileExists(atPath: mlxPath) {
                process.executableURL = URL(fileURLWithPath: mlxPath)
                process.arguments = ["--model", modelName, "--prompt", fullPrompt, "--max-tokens", "\(maxTokens)"]
            } else if let pythonPath {
                process.executableURL = URL(fileURLWithPath: pythonPath)
                process.arguments = ["-c", """
                    from mlx_lm import load, generate
                    with open('\(promptFile.path)', 'r', encoding='utf-8') as f:
                        prompt = f.read()
                    model, tokenizer = load("\(modelName)")
                    response = generate(model, tokenizer, prompt=prompt, max_tokens=\(maxTokens))
                    print(response)
                    """]
            } else {
                continuation.resume(throwing: LLMError.mlxNotAvailable)
                return
            }

            let outputPipe = Pipe()
            process.standardOutput = outputPipe
            process.standardError = Pipe()
            do {
                try process.run()
                process.waitUntilExit()
                guard process.terminationStatus == 0 else {
                    continuation.resume(throwing: LLMError.mlxNotAvailable)
                    return
                }
                let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
                guard let output = String(data: data, encoding: .utf8), !output.isEmpty else {
                    continuation.resume(throwing: LLMError.noResponse)
                    return
                }
                continuation.resume(returning: output.trimmingCharacters(in: .whitespacesAndNewlines))
            } catch {
                continuation.resume(throwing: LLMError.mlxNotAvailable)
            }
        }
    }
}
