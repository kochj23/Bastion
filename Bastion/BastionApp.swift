//
//  BastionApp.swift
//  Bastion
//
//  Main application entry point with legal warning
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import SwiftUI

@main
struct BastionApp: App {
    @StateObject private var networkScanner = NetworkScanner()
    @StateObject private var cveDatabase = CVEDatabase.shared
    @StateObject private var aiOrchestrator = AIAttackOrchestrator()
    @State private var legalAccepted = false
    @State private var showLegalWarning = true

    var body: some Scene {
        WindowGroup {
            if legalAccepted {
                ContentView()
                    .environmentObject(networkScanner)
                    .environmentObject(cveDatabase)
                    .environmentObject(aiOrchestrator)
                    .frame(minWidth: 1200, minHeight: 800)
            } else {
                LegalWarningView(accepted: $legalAccepted, showWarning: $showWarning)
            }
        }
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .newItem) {}

            CommandMenu("Scan") {
                Button("New Scan") {
                    // Trigger scan
                }
                .keyboardShortcut("n", modifiers: .command)

                Button("Stop Scan") {
                    // Stop scan
                }
                .keyboardShortcut("s", modifiers: .command)

                Divider()

                Button("Quick Scan") {
                    // Quick scan
                }
                .keyboardShortcut("q", modifiers: .command)
            }

            CommandMenu("Attack") {
                Button("🎯 Run AI Attack Plan") {
                    // Execute AI-recommended attacks
                }
                .keyboardShortcut("r", modifiers: .command)

                Divider()

                Button("🔥 SATAN MODE (Full Assault)") {
                    // Unleash EVERYTHING - all exploits, all devices, maximum aggression
                    // THIS IS THE KILLER FEATURE
                }
                .keyboardShortcut("x", modifiers: [.command, .option, .shift])

                Divider()

                Button("🛑 EMERGENCY STOP") {
                    // Stop all attacks immediately
                }
                .keyboardShortcut(".", modifiers: .command)
            }

            CommandMenu("AI") {
                Button("AI Backend Settings...") {
                    // Open AI settings
                }
                .keyboardShortcut("b", modifiers: [.command, .option])

                Divider()

                Text("Backend: \(AIBackendManager.shared.activeBackend?.rawValue ?? "None")")
                    .disabled(true)
            }

            CommandMenu("Windows") {
                Button("Dashboard") {}
                    .keyboardShortcut("1", modifiers: .command)

                Button("Device List") {}
                    .keyboardShortcut("2", modifiers: .command)

                Button("Attack Log") {}
                    .keyboardShortcut("3", modifiers: .command)

                Button("AI Insights") {}
                    .keyboardShortcut("4", modifiers: .command)

                Button("Vulnerabilities") {}
                    .keyboardShortcut("5", modifiers: .command)
            }
        }

        // Settings window
        Settings {
            SettingsView()
                .environmentObject(networkScanner)
                .environmentObject(cveDatabase)
        }
    }
}

// Legal warning view
struct LegalWarningView: View {
    @Binding var accepted: Bool
    @Binding var showWarning: Bool

    var body: some View {
        ZStack {
            ModernColors.backgroundGradient
                .ignoresSafeArea()

            VStack(spacing: 30) {
                Image(systemName: "exclamationmark.shield.fill")
                    .font(.system(size: 80))
                    .foregroundColor(.red)

                Text("⚠️ LEGAL NOTICE")
                    .font(.system(size: 36, weight: .bold, design: .rounded))
                    .foregroundColor(.white)

                Text("WHITE HAT SECURITY TOOL")
                    .font(.system(size: 20, weight: .semibold, design: .rounded))
                    .foregroundColor(ModernColors.accent)

                ScrollView {
                    VStack(alignment: .leading, spacing: 15) {
                        Text("Bastion is a WHITE HAT security testing tool for YOUR OWN network.")
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundColor(.white)

                        Text("UNAUTHORIZED NETWORK SCANNING IS ILLEGAL")
                            .font(.system(size: 18, weight: .bold))
                            .foregroundColor(.red)
                            .padding(.vertical, 10)

                        Group {
                            Text("By using Bastion, you confirm:")
                                .font(.system(size: 14, weight: .semibold))
                                .foregroundColor(.white)

                            bulletPoint("You own or have explicit written permission to test this network")
                            bulletPoint("You will use this tool for defensive security purposes only")
                            bulletPoint("You understand unauthorized access/scanning may violate:")

                            Text("  • Computer Fraud and Abuse Act (CFAA) - USA\n  • Computer Misuse Act - UK\n  • Similar laws in your jurisdiction")
                                .font(.system(size: 12))
                                .foregroundColor(ModernColors.textSecondary)
                                .padding(.leading, 30)
                        }

                        Text("Maximum penalties: $250,000 fine + 20 years imprisonment (USA)")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(.red)
                            .padding(.vertical, 10)

                        Group {
                            Text("This tool is designed for:")
                                .font(.system(size: 14, weight: .semibold))
                                .foregroundColor(.white)

                            bulletPoint("Testing YOUR home network security")
                            bulletPoint("Assessing YOUR office network (with permission)")
                            bulletPoint("Security research in authorized lab environments")
                            bulletPoint("Penetration testing with signed engagement contracts")
                        }

                        Text("DO NOT use on networks you don't own/control.")
                            .font(.system(size: 16, weight: .bold))
                            .foregroundColor(.red)
                            .padding(.vertical, 10)

                        Text("Bastion enforces local IP scanning only (192.168.x.x, 10.x.x.x, 172.16-31.x.x).\nAll activities are logged for audit purposes.")
                            .font(.system(size: 12))
                            .foregroundColor(ModernColors.textSecondary)
                    }
                    .padding(30)
                }
                .frame(maxWidth: 700, maxHeight: 400)
                .background(
                    RoundedRectangle(cornerRadius: 20)
                        .fill(Color.black.opacity(0.5))
                )

                HStack(spacing: 20) {
                    Button("Quit") {
                        NSApplication.shared.terminate(nil)
                    }
                    .buttonStyle(ModernButtonStyle(color: .red, style: .destructive))

                    Button("I Understand and Accept") {
                        UserDefaults.standard.set(true, forKey: "BastionLegalAccepted")
                        UserDefaults.standard.set(Date(), forKey: "BastionLegalAcceptedDate")
                        accepted = true
                        showWarning = false
                    }
                    .buttonStyle(ModernButtonStyle(color: ModernColors.accent, style: .filled))
                }
            }
            .padding(50)
        }
        .frame(width: 900, height: 800)
    }

    private func bulletPoint(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Text("✓")
                .foregroundColor(ModernColors.accentGreen)
                .font(.system(size: 14, weight: .bold))

            Text(text)
                .font(.system(size: 13))
                .foregroundColor(ModernColors.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// Main content view
struct ContentView: View {
    @EnvironmentObject var networkScanner: NetworkScanner
    @EnvironmentObject var cveDatabase: CVEDatabase
    @EnvironmentObject var aiOrchestrator: AIAttackOrchestrator

    @State private var selectedTab = 0

    var body: some View {
        ZStack {
            GlassmorphicBackground()

            VStack(spacing: 0) {
                // Header
                HeaderView()

                // Main content
                TabView(selection: $selectedTab) {
                    DashboardView()
                        .tag(0)

                    DeviceListView()
                        .tag(1)

                    AttackLogView()
                        .tag(2)

                    AIInsightsView()
                        .tag(3)

                    VulnerabilitiesView()
                        .tag(4)
                }
                .tabViewStyle(.automatic)
            }
        }
        .ignoresSafeArea()
    }
}

// Header view
struct HeaderView: View {
    var body: some View {
        HStack {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 28))
                .foregroundColor(ModernColors.accent)

            Text("BASTION")
                .font(.system(size: 28, weight: .bold, design: .rounded))
                .foregroundColor(.white)

            Spacer()

            Text("AI-Powered Security Testing")
                .font(.system(size: 14))
                .foregroundColor(ModernColors.textSecondary)
        }
        .padding()
        .background(
            Rectangle()
                .fill(Color.black.opacity(0.3))
                .background(.ultraThinMaterial)
        )
    }
}

#Preview {
    ContentView()
        .environmentObject(NetworkScanner())
        .environmentObject(CVEDatabase.shared)
        .environmentObject(AIAttackOrchestrator())
}
