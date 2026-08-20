//
//  LLMSupport.swift
//  Bastion
//
//  Shared supporting types for the multi-model LLM load balancer.
//  These mirror the small value types used by AIStudio's balancer so the
//  copied-verbatim pure pieces (ModelRegistry, OpenRouterProvider, KeychainStore)
//  compile unchanged inside Bastion.
//
//  Author: Jordan Koch
//

import Foundation

// MARK: - Chat message

/// Role in a chat conversation.
enum ChatRole: String, Codable, Sendable {
    case system
    case user
    case assistant
}

/// A single chat message passed to an OpenAI-compatible backend.
struct ChatMessage: Identifiable, Codable, Sendable {
    let id: UUID
    let role: ChatRole
    var content: String
    let timestamp: Date

    init(role: ChatRole, content: String) {
        self.id = UUID()
        self.role = role
        self.content = content
        self.timestamp = Date()
    }
}

// MARK: - Backend connection status

/// Connection status for a single LLM backend.
enum BackendStatus: Sendable, Equatable {
    case connected
    case disconnected
    case checking
    case error(String)

    var displayText: String {
        switch self {
        case .connected: return "Connected"
        case .disconnected: return "Disconnected"
        case .checking: return "Checking..."
        case .error(let msg): return "Error: \(msg)"
        }
    }

    var isConnected: Bool {
        if case .connected = self { return true }
        return false
    }
}

// MARK: - Errors

/// Errors surfaced by the load balancer / generation paths.
enum LLMError: LocalizedError, Sendable {
    case noBackendAvailable
    case invalidURL
    case invalidResponse
    case httpError(Int)
    case noResponse
    case mlxNotAvailable

    var errorDescription: String? {
        switch self {
        case .noBackendAvailable:
            return "No LLM backend is available. Start Ollama, add an OpenRouter key, or enable the Nova Gateway."
        case .invalidURL:
            return "Invalid backend URL configuration."
        case .invalidResponse:
            return "Received invalid response from LLM backend."
        case .httpError(let code):
            return "HTTP error \(code) from LLM backend."
        case .noResponse:
            return "No response received from LLM backend."
        case .mlxNotAvailable:
            return "MLX not available. Install: pip install mlx-lm"
        }
    }
}
