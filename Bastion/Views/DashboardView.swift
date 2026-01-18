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
    @State private var selectedDevice: Device?
    @State private var showDeviceDetail = false

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
        .sheet(isPresented: $showDeviceDetail) {
            if let device = selectedDevice {
                DeviceDetailView(device: device, isPresented: $showDeviceDetail)
            }
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

    // Network map card - GRID OF DEVICES IN ROWS
    private var networkMapCard: some View {
        VStack(alignment: .leading, spacing: 15) {
            HStack {
                Text("Discovered Devices")
                    .modernHeader(size: .medium)

                Spacer()

                Text("\(networkScanner.discoveredDevices.count) devices")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(ModernColors.accent)
            }

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
                // GRID LAYOUT - 3 columns of devices
                let columns = [
                    GridItem(.flexible(), spacing: 15),
                    GridItem(.flexible(), spacing: 15),
                    GridItem(.flexible(), spacing: 15)
                ]

                LazyVGrid(columns: columns, spacing: 15) {
                    ForEach(networkScanner.discoveredDevices) { device in
                        DeviceCard(device: device)
                            .frame(height: 180)
                            .onTapGesture {
                                selectedDevice = device
                                showDeviceDetail = true
                            }
                            .shadow(color: device.riskLevel.color.opacity(0.3), radius: 10)
                            .overlay(
                                RoundedRectangle(cornerRadius: 12)
                                    .stroke(Color.white.opacity(0.1), lineWidth: 1)
                            )
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

// Device card component - Enhanced for grid display
struct DeviceCard: View {
    let device: Device

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Header with device type and online status
            HStack {
                Image(systemName: device.deviceType.icon)
                    .font(.system(size: 20))
                    .foregroundColor(deviceColor)

                Spacer()

                // Risk level badge
                Text(device.riskLevel.rawValue.uppercased())
                    .font(.system(size: 8, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(
                        RoundedRectangle(cornerRadius: 4)
                            .fill(device.riskLevel.color)
                    )

                Circle()
                    .fill(device.isOnline ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
            }

            // Device name
            Text(device.displayName)
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(.white)
                .lineLimit(1)

            // IP Address
            Text(device.ipAddress)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(ModernColors.textSecondary)

            // OS if detected
            if let os = device.operatingSystem {
                HStack(spacing: 4) {
                    Image(systemName: "desktopcomputer")
                        .font(.system(size: 9))
                    Text(os)
                        .font(.system(size: 9))
                }
                .foregroundColor(ModernColors.textTertiary)
            }

            Divider()
                .background(Color.white.opacity(0.1))

            // Stats row
            HStack(spacing: 12) {
                // Ports
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(device.openPorts.count)")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(.white)
                    Text("Ports")
                        .font(.system(size: 8))
                        .foregroundColor(ModernColors.textTertiary)
                }

                Divider()
                    .frame(height: 30)
                    .background(Color.white.opacity(0.1))

                // Vulnerabilities
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(device.vulnerabilities.count)")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(device.vulnerabilities.isEmpty ? ModernColors.statusLow : ModernColors.statusCritical)
                    Text("Vulns")
                        .font(.system(size: 8))
                        .foregroundColor(ModernColors.textTertiary)
                }

                Spacer()

                // Security score
                ZStack {
                    Circle()
                        .stroke(Color.white.opacity(0.1), lineWidth: 3)
                        .frame(width: 40, height: 40)

                    Circle()
                        .trim(from: 0, to: CGFloat(device.securityScore) / 100.0)
                        .stroke(scoreColor, lineWidth: 3)
                        .frame(width: 40, height: 40)
                        .rotationEffect(.degrees(-90))

                    Text("\(device.securityScore)")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.white)
                }
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color.white.opacity(0.05))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(deviceColor.opacity(0.4), lineWidth: 2)
                )
                .shadow(color: deviceColor.opacity(0.2), radius: 8)
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

    private var scoreColor: Color {
        if device.securityScore >= 80 {
            return .green
        } else if device.securityScore >= 60 {
            return .yellow
        } else if device.securityScore >= 40 {
            return .orange
        } else {
            return .red
        }
    }
}

// SettingsView is defined in SettingsView.swift

// Placeholder views are defined in their own files:
// - DeviceListView.swift
// - AttackLogView.swift
// - AIInsightsView.swift
// - VulnerabilitiesView.swift

#Preview {
    DashboardView()
        .environmentObject(NetworkScanner())
        .environmentObject(CVEDatabase.shared)
        .environmentObject(AIAttackOrchestrator())
}
