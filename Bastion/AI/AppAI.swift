//
//  AppAI.swift
//  Bastion
//
//  The app's single AI object (NovaAIKit). Settings persist in UserDefaults (no secrets);
//  API keys live only in the Keychain under com.jkoch.bastion.<backend> (https only).
//

import NovaAIKit

/// Bastion's one AI object. Replaces the former AIBackendManager / LLMLoadBalancer stack.
@MainActor
enum AppAI {
    static let shared: NovaAI = {
        let ai = NovaAI(configuration: NovaAIConfiguration(
            appID: "bastion",
            appName: "Bastion"
        ))
        AppAI.migrateLegacy(ai)
        return ai
    }()
}

extension AppAI {
    /// One-time migration of the old AIBackendManager settings and any legacy Keychain items.
    /// The removed Google/Azure/AWS/IBM backends are not part of Bastion, but we still scrub any
    /// obsolete secrets a previous build may have written. OpenRouter keys already used the
    /// `com.jkoch.bastion.openrouter` service, which NovaAIKit adopts unchanged.
    static func migrateLegacy(_ ai: NovaAI) {
        // Old AIBackendManager_* UserDefaults (backend, Ollama model, server URLs, on/off).
        ai.migrateFromLegacyAIBackendManager()
        // Scrub any obsolete removed-backend secrets from the old service name, if present.
        ai.keys.deleteObsoleteLegacyItems(service: "com.jkoch.bastion.openrouter")
    }
}
