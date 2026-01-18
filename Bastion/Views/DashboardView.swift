//
//  DashboardView.swift
//  Bastion
//
//  Main glassmorphic dashboard with network overview
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var networkScanner: NetworkScanner
    @EnvironmentObject var cveDatabase: CVEDatabase
    @EnvironmentObject var aiOrchestrator: AIAttackOrchestrator

    @State private var networkCIDR = "192.168.1.0/24"
    @State private var isScanning = false
    @State private var showSettings = false

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Scan controls
                scanControlsCard

                // Statistics cards
                statisticsCards

                // Network map
                networkMapCard

                // Recent activity
                recentActivityCard
            }
            .padding()
        }
    }

    // Scan controls card
    private var scanControlsCard: some View {
        VStack(spacing: 15) {
            HStack {
                Text("Network Scan")
                    .modernHeader(size: .medium)

                Spacer()

                if networkScanner.isScanning {
                    ProgressView(value: networkScanner.scanProgress)
                        .frame(width: 150)
                }
            }

            HStack(spacing: 15) {
                TextField("Network CIDR (e.g., 192.168.1.0/24)", text: $networkCIDR)
                    .textFieldStyle(.roundedBorder)
                    .disabled(networkScanner.isScanning)

                Button(networkScanner.isScanning ? "Stop" : "Scan Network") {
                    if networkScanner.isScanning {
                        // Stop scan
                        isScanning = false
                    } else {
                        startScan()
                    }
                }
                .buttonStyle(ModernButtonStyle(
                    color: networkScanner.isScanning ? .red : ModernColors.accent,
                    style: .filled
                ))

                Button("Quick Scan") {
                    quickScan()
                }
                .buttonStyle(ModernButtonStyle(color: ModernColors.accentBlue, style: .outlined))
                .disabled(networkScanner.isScanning)

                Button {
                    showSettings = true
                } label: {
                    Image(systemName: "gearshape.fill")
                }
                .buttonStyle(ModernButtonStyle(color: ModernColors.textSecondary, style: .glass))
            }

            if networkScanner.isScanning {
                HStack {
                    Text("Scanning: \(networkScanner.currentScanTarget)")
                        .font(.system(size: 12))
                        .foregroundColor(ModernColors.textSecondary)

                    Spacer()

                    Text("\(Int(networkScanner.scanProgress * 100))%")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(ModernColors.accent)
                }
            }
        }
        .glassCard()
    }

    // Statistics cards
    private var statisticsCards: some View {
        LazyVGrid(columns: [
            GridItem(.flexible()),
            GridItem(.flexible()),
            GridItem(.flexible()),
            GridItem(.flexible())
        ], spacing: 20) {
            StatCard(
                title: "Devices",
                value: "\(networkScanner.discoveredDevices.count)",
                icon: "network",
                color: ModernColors.accentBlue
            )

            StatCard(
                title: "Critical",
                value: "\(totalCriticalVulns)",
                icon: "exclamationmark.triangle.fill",
                color: ModernColors.statusCritical
            )

            StatCard(
                title: "High",
                value: "\(totalHighVulns)",
                icon: "exclamationmark.circle.fill",
                color: ModernColors.statusHigh
            )

            StatCard(
                title: "CVE Database",
                value: cveDatabase.totalCVEs > 0 ? "\(cveDatabase.totalCVEs / 1000)k" : "Not Downloaded",
                icon: "doc.text.fill",
                color: ModernColors.accent
            )
        }
    }

    // Network map card
    private var networkMapCard: some View {
        VStack(alignment: .leading, spacing: 15) {
            Text("Network Map")
                .modernHeader(size: .medium)

            if networkScanner.discoveredDevices.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "network.slash")
                        .font(.system(size: 60))
                        .foregroundColor(ModernColors.textTertiary)

                    Text("No devices discovered yet")
                        .foregroundColor(ModernColors.textSecondary)

                    Text("Start a network scan to discover devices")
                        .font(.system(size: 12))
                        .foregroundColor(ModernColors.textTertiary)
                }
                .frame(maxWidth: .infinity)
                .padding(40)
            } else {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 15) {
                        ForEach(networkScanner.discoveredDevices) { device in
                            DeviceCard(device: device)
                        }
                    }
                }
            }
        }
        .glassCard()
    }

    // Recent activity card
    private var recentActivityCard: some View {
        VStack(alignment: .leading, spacing: 15) {
            Text("Recent Activity")
                .modernHeader(size: .medium)

            if networkScanner.scanLog.isEmpty {
                Text("No activity yet")
                    .foregroundColor(ModernColors.textSecondary)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding()
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(networkScanner.scanLog.suffix(10).reversed(), id: \.self) { log in
                        Text(log)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(ModernColors.textSecondary)
                    }
                }
            }
        }
        .glassCard()
    }

    // Computed properties
    private var totalCriticalVulns: Int {
        networkScanner.discoveredDevices.reduce(0) { $0 + $1.criticalVulnCount }
    }

    private var totalHighVulns: Int {
        networkScanner.discoveredDevices.reduce(0) { $0 + $1.highVulnCount }
    }

    // Actions
    private func startScan() {
        Task {
            do {
                try SafetyValidator.shared.validateTarget(networkCIDR.components(separatedBy: "/")[0])
                SafetyValidator.shared.logActivity("Network scan started", target: networkCIDR)

                try await networkScanner.scanNetwork(cidr: networkCIDR)

                // After scan, fingerprint services and check CVEs
                await fingerprintAndAnalyze()
            } catch {
                print("Scan error: \(error.localizedDescription)")
            }
        }
    }

    private func quickScan() {
        Task {
            do {
                try await networkScanner.quickScan(cidr: networkCIDR)
                await fingerprintAndAnalyze()
            } catch {
                print("Quick scan error: \(error.localizedDescription)")
            }
        }
    }

    private func fingerprintAndAnalyze() async {
        let fingerprinter = ServiceFingerprinter()

        for device in networkScanner.discoveredDevices {
            for port in device.openPorts {
                if let service = await fingerprinter.fingerprint(ip: device.ipAddress, port: port.port) {
                    // Check CVEs for this service
                    if let version = service.version {
                        let cves = cveDatabase.findCVEs(service: service.name, version: version)
                        // Would add CVEs to device here
                    }
                }
            }
        }
    }
}

// Stat card component
struct StatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 32))
                .foregroundColor(color)

            Text(value)
                .font(.system(size: 28, weight: .bold, design: .rounded))
                .foregroundColor(.white)

            Text(title)
                .font(.system(size: 12))
                .foregroundColor(ModernColors.textSecondary)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .glassCard()
    }
}

// Device card component
struct DeviceCard: View {
    let device: Device

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: device.deviceType.icon)
                    .font(.system(size: 24))
                    .foregroundColor(deviceColor)

                Spacer()

                Circle()
                    .fill(device.isOnline ? Color.green : Color.red)
                    .frame(width: 10, height: 10)
            }

            Text(device.displayName)
                .font(.system(size: 14, weight: .semibold))
                .foregroundColor(.white)
                .lineLimit(1)

            Text(device.ipAddress)
                .font(.system(size: 12))
                .foregroundColor(ModernColors.textSecondary)

            Divider()

            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Ports: \(device.openPorts.count)")
                        .font(.system(size: 10))
                        .foregroundColor(ModernColors.textSecondary)

                    Text("Vulns: \(device.vulnerabilities.count)")
                        .font(.system(size: 10))
                        .foregroundColor(device.vulnerabilities.isEmpty ? ModernColors.statusLow : ModernColors.statusCritical)
                }

                Spacer()

                CircularGauge(
                    value: Double(device.securityScore),
                    color: ModernColors.heatColor(percentage: Double(100 - device.securityScore)),
                    size: 50,
                    lineWidth: 4,
                    showValue: true
                )
            }
        }
        .frame(width: 200)
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color.white.opacity(0.05))
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(deviceColor.opacity(0.3), lineWidth: 1)
                )
        )
    }

    private var deviceColor: Color {
        if device.criticalVulnCount > 0 {
            return ModernColors.statusCritical
        } else if device.highVulnCount > 0 {
            return ModernColors.statusHigh
        } else {
            return ModernColors.statusLow
        }
    }
}

// Settings view
struct SettingsView: View {
    @EnvironmentObject var cveDatabase: CVEDatabase

    var body: some View {
        TabView {
            AIBackendSettingsView()
                .tabItem {
                    Label("AI Backend", systemImage: "cpu")
                }

            CVEDatabaseSettingsView()
                .tabItem {
                    Label("CVE Database", systemImage: "doc.text")
                }
        }
        .frame(width: 600, height: 500)
    }
}

// CVE Database settings
struct CVEDatabaseSettingsView: View {
    @ObservedObject var cveDatabase = CVEDatabase.shared

    var body: some View {
        VStack(spacing: 20) {
            Text("CVE Database")
                .font(.title)

            if cveDatabase.totalCVEs > 0 {
                Text("\(cveDatabase.totalCVEs) CVEs loaded")
                    .foregroundColor(.green)

                if let lastUpdate = cveDatabase.lastUpdate {
                    Text("Last updated: \(lastUpdate.formatted())")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            } else {
                Text("CVE database not downloaded")
                    .foregroundColor(.orange)
            }

            if cveDatabase.isDownloading {
                VStack {
                    ProgressView(value: cveDatabase.downloadProgress)
                        .frame(width: 300)

                    Text("Downloading... \(Int(cveDatabase.downloadProgress * 100))%")
                        .font(.caption)
                }
            } else {
                Button(cveDatabase.totalCVEs > 0 ? "Update Database" : "Download Database (~2GB)") {
                    Task {
                        try? await cveDatabase.downloadNVDDatabase()
                    }
                }
            }

            Spacer()
        }
        .padding()
    }
}

// Placeholder views for other tabs
struct DeviceListView: View {
    var body: some View {
        Text("Device List")
    }
}

struct AttackLogView: View {
    var body: some View {
        Text("Attack Log")
    }
}

struct AIInsightsView: View {
    var body: some View {
        Text("AI Insights")
    }
}

struct VulnerabilitiesView: View {
    var body: some View {
        Text("Vulnerabilities")
    }
}

#Preview {
    DashboardView()
        .environmentObject(NetworkScanner())
        .environmentObject(CVEDatabase.shared)
        .environmentObject(AIAttackOrchestrator())
}
