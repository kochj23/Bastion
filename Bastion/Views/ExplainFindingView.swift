//
//  ExplainFindingView.swift
//  Bastion
//
//  Sheet that presents a plain-English, AI-generated explanation of a security
//  finding. Degrades gracefully when no LLM backend is available.
//
//  Author: Jordan Koch
//

import SwiftUI

struct ExplainFindingView: View {
    let finding: Vulnerability
    @StateObject private var model = FindingExplainerModel()
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "sparkles")
                    .foregroundColor(.accentColor)
                Text("Explain: \(finding.title)")
                    .font(.headline)
                    .lineLimit(2)
                Spacer()
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
            }

            Divider()

            ScrollView {
                content
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            Divider()

            HStack {
                if case .done = model.state {
                    Button("Regenerate") { Task { await model.explain(finding) } }
                }
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 560, height: 480)
        .task { await model.explain(finding) }
    }

    @ViewBuilder
    private var content: some View {
        switch model.state {
        case .idle, .checking:
            ProgressView("Checking available AI backends…")
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.top, 40)
        case .loading:
            ProgressView("Asking the balanced LLM…")
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.top, 40)
        case .unavailable(let reason):
            statusBox(icon: "bolt.slash", tint: .orange, title: "AI explanation unavailable", message: reason)
        case .failed(let reason):
            statusBox(icon: "exclamationmark.triangle", tint: .red, title: "Could not generate explanation", message: reason)
        case .done(let text):
            Text(text)
                .font(.system(.body))
                .textSelection(.enabled)
                .padding(.vertical, 4)
        }
    }

    private func statusBox(icon: String, tint: Color, title: String, message: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(title, systemImage: icon)
                .font(.headline)
                .foregroundColor(tint)
            Text(message)
                .font(.callout)
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10).fill(tint.opacity(0.12)))
    }
}
