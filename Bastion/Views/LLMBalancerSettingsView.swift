//
//  LLMBalancerSettingsView.swift
//  Bastion
//
//  Settings surface for the multi-model LLM load balancer: the three balancing
//  toggles (all local / all frontier / Nova Gateway), the OpenRouter key, and the
//  optional Nova Gateway URL.
//
//  Author: Jordan Koch
//

import SwiftUI

struct LLMBalancerSettingsView: View {
    @ObservedObject private var settings = LLMBalancerSettings.shared
    @ObservedObject private var balancer = LLMLoadBalancer.shared

    @State private var openRouterKeyDraft = ""
    @State private var keySaved = false

    var body: some View {
        Form {
            Section("Multi-model load balancing") {
                Toggle("Use all local models", isOn: $settings.useAllLocalModels)
                Text("Spread AI requests across every discovered Ollama + MLX model on this Mac.")
                    .font(.caption).foregroundColor(.secondary)

                Toggle("Enable all frontier models", isOn: $settings.enableAllFrontierModels)
                    .disabled(!balancer.hasOpenRouterKey)
                Text(balancer.hasOpenRouterKey
                     ? "Add OpenRouter's full model list to the balancer pool."
                     : "Add an OpenRouter key below to enable frontier models in the pool.")
                    .font(.caption).foregroundColor(.secondary)

                Toggle("Route through Nova Gateway (optional)", isOn: $settings.useNovaGateway)
                if settings.useNovaGateway {
                    HStack {
                        TextField("Nova Gateway URL", text: $settings.novaGatewayURL)
                            .textFieldStyle(.roundedBorder)
                        Button("Test") { Task { await balancer.refreshBackend(.novaGateway) } }
                    }
                    Text(statusText(for: .novaGateway))
                        .font(.caption).foregroundColor(.secondary)
                }
                Text("Nova Gateway is entirely optional — Bastion works with zero Nova. A failed health check simply drops it from the pool.")
                    .font(.caption).foregroundColor(.secondary)

                if !balancer.discoveredModels.isEmpty {
                    Text("\(balancer.discoveredModels.count) model(s) in the balancer pool")
                        .font(.caption).foregroundColor(.green)
                }
                Button("Refresh model pool") { Task { _ = await balancer.discoverEnabledPool() } }
            }

            Section("OpenRouter (frontier models)") {
                if balancer.hasOpenRouterKey {
                    Label("API key stored in Keychain", systemImage: "key.fill")
                        .foregroundColor(.green)
                    Button("Remove key") {
                        balancer.setOpenRouterAPIKey("")
                        openRouterKeyDraft = ""
                        keySaved = false
                    }
                    .foregroundColor(.red)
                } else {
                    SecureField("OpenRouter API key (sk-or-…)", text: $openRouterKeyDraft)
                        .textFieldStyle(.roundedBorder)
                    Button("Save key") {
                        balancer.setOpenRouterAPIKey(openRouterKeyDraft)
                        keySaved = balancer.hasOpenRouterKey
                        Task { await balancer.refreshBackend(.openRouter) }
                    }
                    .disabled(openRouterKeyDraft.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                Text("Keys are stored in the macOS Keychain, never in UserDefaults.")
                    .font(.caption).foregroundColor(.secondary)
            }

            Section("Local (Ollama)") {
                TextField("Ollama URL", text: $settings.ollamaURL)
                    .textFieldStyle(.roundedBorder)
                Text(statusText(for: .ollama))
                    .font(.caption).foregroundColor(.secondary)
            }
        }
        .padding()
        .task { await balancer.refreshAllBackends() }
    }

    private func statusText(for type: LLMBackendType) -> String {
        let status = balancer.backends[type]?.status ?? .disconnected
        return "\(type.displayName): \(status.displayText)"
    }
}
