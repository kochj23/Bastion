//
//  AttackLogView.swift
//  Bastion
//
//  🔥 LIVE ATTACK LOG - Matrix-style hacking terminal
//  This is what makes demos look BADASS
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import SwiftUI

struct AttackLogView: View {
    @State private var logEntries: [LogEntry] = []
    @State private var autoScroll = true

    var body: some View {
        VStack(spacing: 0) {
            // Header with controls
            HStack {
                Text("📝 Live Attack Log")
                    .font(.title2)
                    .bold()
                    .foregroundColor(.white)

                Spacer()

                Toggle("Auto-scroll", isOn: $autoScroll)
                    .toggleStyle(.switch)
                    .foregroundColor(.white)

                Button("Clear") {
                    logEntries.removeAll()
                }
                .buttonStyle(.bordered)

                Button("Export") {
                    exportLog()
                }
                .buttonStyle(.bordered)
            }
            .padding()
            .background(Color.black.opacity(0.5))

            Divider()

            // Terminal-style log
            ScrollView {
                ScrollViewReader { proxy in
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(logEntries) { entry in
                            LogEntryRow(entry: entry)
                                .id(entry.id)
                        }

                        // Auto-scroll anchor
                        Color.clear.frame(height: 1)
                            .id("bottom")
                    }
                    .padding()
                    .onChange(of: logEntries.count) { _ in
                        if autoScroll {
                            withAnimation {
                                proxy.scrollTo("bottom")
                            }
                        }
                    }
                }
            }
            .background(Color.black)
            .font(.system(.body, design: .monospaced))
        }
        .onAppear {
            startDemoLog()
        }
    }

    private func exportLog() {
        let logText = logEntries.map { "[\($0.timestamp)] \($0.message)" }.joined(separator: "\n")
        let savePanel = NSSavePanel()
        savePanel.nameFieldStringValue = "bastion-attack-log-\(Date().timeIntervalSince1970).txt"
        savePanel.begin { response in
            if response == .OK, let url = savePanel.url {
                try? logText.write(to: url, atomically: true, encoding: .utf8)
            }
        }
    }

    private func startDemoLog() {
        // Demo log entries to show capability
        addLog("🎯 BASTION ATTACK ENGINE INITIALIZED", type: .system)
        addLog("🤖 AI Backend: Ollama (mistral) - ACTIVE", type: .success)
        addLog("🛡️ Safety Validator: LOCAL NETWORK ONLY - ENGAGED", type: .info)
        addLog("", type: .info)
        addLog("Type: network scan 192.168.1.0/24", type: .command)
        addLog("", type: .info)
    }

    private func addLog(_ message: String, type: LogEntry.LogType) {
        let entry = LogEntry(
            timestamp: Date(),
            message: message,
            type: type
        )
        logEntries.append(entry)
    }
}

struct LogEntryRow: View {
    let entry: LogEntry

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            // Timestamp
            Text(timeString(entry.timestamp))
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.gray)
                .frame(width: 80, alignment: .leading)

            // Icon
            Text(entry.type.icon)
                .font(.system(.body, design: .monospaced))

            // Message
            Text(entry.message)
                .font(.system(.body, design: .monospaced))
                .foregroundColor(entry.type.color)
                .textSelection(.enabled)
        }
        .padding(.vertical, 1)
    }

    private func timeString(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }
}

struct LogEntry: Identifiable {
    let id = UUID()
    let timestamp: Date
    let message: String
    let type: LogType

    enum LogType {
        case system, info, success, warning, error, critical, command

        var icon: String {
            switch self {
            case .system: return "🎯"
            case .info: return "ℹ️"
            case .success: return "✅"
            case .warning: return "⚠️"
            case .error: return "❌"
            case .critical: return "🔥"
            case .command: return ">"
            }
        }

        var color: Color {
            switch self {
            case .system: return .cyan
            case .info: return .white
            case .success: return .green
            case .warning: return .yellow
            case .error: return .red
            case .critical: return Color(red: 1.0, green: 0.3, blue: 0.3)
            case .command: return .purple
            }
        }
    }
}
