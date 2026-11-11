//
//  AIInsightsView.swift
//  Bastion
//
//  🤖 AI-POWERED SECURITY INSIGHTS
//  The "magic" view that shows AI analysis
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import SwiftUI
import NovaAIKit

struct AIInsightsView: View {
    @EnvironmentObject var aiOrchestrator: AIAttackOrchestrator
    @State private var question = ""
    @State private var answer = ""
    @State private var isAsking = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header
                HStack {
                    Text("🤖 AI Security Insights")
                        .font(.title)
                        .bold()
                        .foregroundColor(.white)

                    Spacer()

                    NovaAIStatusIndicator(ai: AppAI.shared)
                }

                // Attack Plan Summary
                if let plan = aiOrchestrator.attackPlan {
                    attackPlanCard(plan)
                }

                // Q&A Interface
                qaInterface

                // Recommendations
                if !aiOrchestrator.attackRecommendations.isEmpty {
                    recommendationsSection
                }
            }
            .padding()
        }
        .background(Color.black.opacity(0.3))
    }

    private func attackPlanCard(_ plan: AttackPlan) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("🎯 AI Attack Strategy")
                .font(.headline)
                .foregroundColor(.white)

            Text(plan.overallStrategy)
                .font(.body)
                .foregroundColor(.white)
                .padding()
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color.cyan.opacity(0.2))
                )

            // Priority targets
            VStack(alignment: .leading, spacing: 12) {
                Text("Priority Targets:")
                    .font(.subheadline)
                    .bold()
                    .foregroundColor(.white)

                ForEach(plan.priorityTargets.prefix(5), id: \.device.id) { target in
                    HStack {
                        Text("\(target.device.ipAddress)")
                            .font(.system(.body, design: .monospaced))
                            .foregroundColor(.cyan)

                        Text(target.reason)
                            .font(.caption)
                            .foregroundColor(.secondary)

                        Spacer()

                        Text("\(target.successProbability)%")
                            .font(.caption)
                            .foregroundColor(probabilityColor(target.successProbability))
                    }
                }
            }

            // Attack chains
            if !plan.attackChains.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("🔗 Attack Chains:")
                        .font(.subheadline)
                        .bold()
                        .foregroundColor(.white)

                    ForEach(plan.attackChains, id: \.description) { chain in
                        Text("• \(chain.description)")
                            .font(.caption)
                            .foregroundColor(.orange)
                    }
                }
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color.white.opacity(0.1))
                .background(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color.cyan, lineWidth: 2)
                )
        )
    }

    private var qaInterface: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("💬 Ask AI About Security")
                .font(.headline)
                .foregroundColor(.white)

            if !answer.isEmpty {
                Text(answer)
                    .font(.body)
                    .foregroundColor(.white)
                    .padding()
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .fill(Color.purple.opacity(0.2))
                    )
            }

            HStack {
                TextField("Ask: 'What's the most critical vulnerability?' or 'How do I fix CVE-2021-41617?'", text: $question)
                    .textFieldStyle(.roundedBorder)
                    .disabled(isAsking)

                Button(isAsking ? "Asking..." : "Ask AI") {
                    askAI()
                }
                .buttonStyle(.borderedProminent)
                .disabled(question.isEmpty || isAsking)
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color.white.opacity(0.1))
        )
    }

    private var recommendationsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("🎯 AI Exploit Recommendations")
                .font(.headline)
                .foregroundColor(.white)

            ForEach(aiOrchestrator.attackRecommendations.prefix(10)) { rec in
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(rec.name)
                            .font(.subheadline)
                            .bold()
                            .foregroundColor(.white)

                        Text(rec.reasoning)
                            .font(.caption)
                            .foregroundColor(.secondary)

                        HStack {
                            Text("Success: \(rec.successProbability)%")
                                .font(.caption)
                                .foregroundColor(probabilityColor(rec.successProbability))

                            Text("•")
                                .foregroundColor(.secondary)

                            Text("Impact: \(rec.impact)")
                                .font(.caption)
                                .foregroundColor(.orange)
                        }
                    }

                    Spacer()
                }
                .padding()
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color.white.opacity(0.1))
                )
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color.white.opacity(0.05))
        )
    }

    private func probabilityColor(_ probability: Int) -> Color {
        if probability >= 80 { return .green }
        if probability >= 60 { return .yellow }
        if probability >= 40 { return .orange }
        return .red
    }

    private func askAI() {
        guard AppAI.shared.isEnabled else {
            answer = "❌ AI backend not available. Please configure Ollama, MLX, or TinyLLM in Settings."
            return
        }

        isAsking = true
        let currentQuestion = question
        question = ""

        Task {
            do {
                let response = try await AppAI.shared.generate(
                    prompt: currentQuestion,
                    systemPrompt: "You are a cybersecurity expert helping analyze network security. Provide clear, actionable advice.",
                    temperature: 0.7,
                    maxTokens: 500
                )

                await MainActor.run {
                    answer = response
                    isAsking = false
                }
            } catch {
                await MainActor.run {
                    answer = "❌ AI Error: \(error.localizedDescription)"
                    isAsking = false
                }
            }
        }
    }
}
