//
//  SettingsView.swift
//  Bastion
//
//  Settings and configuration
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var networkScanner: NetworkScanner
    @EnvironmentObject var cveDatabase: CVEDatabase

    var body: some View {
        TabView {
            AIBackendSettingsView()
                .tabItem {
                    Label("AI Backends", systemImage: "brain")
                }

            CVESettingsView(cveDatabase: cveDatabase)
                .tabItem {
                    Label("CVE Database", systemImage: "doc.text.magnifyingglass")
                }

            ScanSettingsView()
                .tabItem {
                    Label("Scanning", systemImage: "network")
                }
        }
        .frame(width: 700, height: 600)
    }
}

struct CVESettingsView: View {
    @ObservedObject var cveDatabase: CVEDatabase

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("CVE Database")
                .font(.title)
                .bold()

            // Status
            HStack {
                if cveDatabase.totalCVEs > 0 {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                    Text("\(cveDatabase.totalCVEs) CVEs indexed")
                } else {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.orange)
                    Text("No CVE database downloaded")
                }
            }

            if let lastUpdate = cveDatabase.lastUpdate {
                Text("Last updated: \(lastUpdate, style: .relative) ago")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Divider()

            // Actions
            VStack(spacing: 12) {
                if cveDatabase.totalCVEs == 0 {
                    Button("Download CVE Database (~2GB)") {
                        Task {
                            try? await cveDatabase.downloadNVDDatabase()
                        }
                    }
                    .buttonStyle(.borderedProminent)

                    Text("First-time download will take 10-20 minutes")
                        .font(.caption)
                        .foregroundColor(.secondary)
                } else {
                    Button("Update CVE Database") {
                        Task {
                            try? await cveDatabase.updateDatabase()
                        }
                    }
                    .buttonStyle(.bordered)
                }

                if cveDatabase.isDownloading {
                    ProgressView(value: cveDatabase.downloadProgress)
                    Text("Downloading: \(Int(cveDatabase.downloadProgress * 100))%")
                        .font(.caption)
                }
            }

            Spacer()
        }
        .padding()
    }
}

struct ScanSettingsView: View {
    @AppStorage("scanTimeout") private var scanTimeout: Double = 5.0
    @AppStorage("maxThreads") private var maxThreads: Int = 100
    @AppStorage("aggressiveScanning") private var aggressive: Bool = false

    var body: some View {
        Form {
            Section("Network Scanning") {
                Slider(value: $scanTimeout, in: 1...30) {
                    Text("Scan Timeout: \(Int(scanTimeout))s")
                }

                Stepper("Threads: \(maxThreads)", value: $maxThreads, in: 10...500, step: 10)

                Toggle("Aggressive Mode", isOn: $aggressive)

                Text("Aggressive mode scans all 65,535 ports (slower but thorough)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Section("Safety") {
                Toggle("Require Confirmation Before Exploits", isOn: .constant(true))
                    .disabled(true)

                Toggle("Log All Activities (Audit Trail)", isOn: .constant(true))
                    .disabled(true)

                Toggle("Local Networks Only", isOn: .constant(true))
                    .disabled(true)

                Text("These safety features cannot be disabled")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
    }
}
