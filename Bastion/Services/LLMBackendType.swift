//
//  LLMBackendType.swift
//  Bastion
//
//  LLM backend type identifier + per-backend configuration.
//  Ported from AIStudio so the shared load balancer behaves identically across
//  Jordan Koch's apps. Nova Gateway is always an OPTIONAL backend — the balancer
//  works with zero Nova (local Ollama + frontier OpenRouter alone).
//
//  Author: Jordan Koch
//

import Foundation

/// LLM backend type identifier.
enum LLMBackendType: String, CaseIterable, Codable, Sendable {
    case ollama = "ollama"
    case mlx = "mlx"
    case openRouter = "openrouter"
    case novaGateway = "novagateway"
    case auto = "auto"

    var displayName: String {
        switch self {
        case .ollama: return "Ollama"
        case .mlx: return "MLX Native"
        case .openRouter: return "OpenRouter (Frontier Models)"
        case .novaGateway: return "Nova Gateway"
        case .auto: return "Auto (Prefer Ollama)"
        }
    }

    var icon: String {
        switch self {
        case .ollama: return "network"
        case .mlx: return "cpu"
        case .openRouter: return "cloud"
        case .novaGateway: return "sparkle.magnifyingglass"
        case .auto: return "sparkles"
        }
    }

    var defaultURL: String {
        switch self {
        case .ollama: return ModelRegistry.ollamaBaseURL
        case .mlx: return ""
        case .openRouter: return OpenRouterProvider.baseURL
        case .novaGateway: return ModelRegistry.novaGatewayDefaultURL
        case .auto: return ""
        }
    }

    var description: String {
        switch self {
        case .ollama: return "HTTP-based LLM API (localhost:11434)"
        case .mlx: return "Apple Silicon native inference via MLX"
        case .openRouter: return "Frontier cloud models via OpenRouter (bring your own key)"
        case .novaGateway: return "Nova's gateway — OpenAI-compatible, inherits Nova's own routing (127.0.0.1:18792)"
        case .auto: return "Automatically choose best available backend"
        }
    }
}

/// Configuration for a single LLM backend.
struct LLMBackendConfiguration: Identifiable, Sendable {
    let id: UUID
    let type: LLMBackendType
    var url: String
    var status: BackendStatus

    init(type: LLMBackendType, url: String? = nil) {
        self.id = UUID()
        self.type = type
        self.url = url ?? type.defaultURL
        self.status = .disconnected
    }
}
