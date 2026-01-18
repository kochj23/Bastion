//
//  DeviceDetailView.swift
//  Bastion
//
//  Detailed view showing comprehensive security assessment for a device
//  Shows ALL test results, vulnerabilities, and attack options
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import SwiftUI

struct DeviceDetailView: View {
    let device: Device
    @Binding var isPresented: Bool
    @State private var selectedTab = 0

    var body: some View {
        VStack(spacing: 0) {
            // Header
            deviceHeader

            // Tabs
            TabView(selection: $selectedTab) {
                // Overview tab
                overviewTab
                    .tabItem {
                        Label("Overview", systemImage: "chart.bar.fill")
                    }
                    .tag(0)

                // Ports & Services tab
                portsTab
                    .tabItem {
                        Label("Ports & Services", systemImage: "network")
                    }
                    .tag(1)

                // Vulnerabilities tab
                vulnerabilitiesTab
                    .tabItem {
                        Label("Vulnerabilities", systemImage: "exclamationmark.triangle.fill")
                    }
                    .tag(2)

                // Attack Options tab
                attackTab
                    .tabItem {
                        Label("Attack Options", systemImage: "bolt.fill")
                    }
                    .tag(3)
            }
        }
        .frame(width: 900, height: 700)
        .background(Color.black.opacity(0.95))
    }

    // MARK: - Header

    private var deviceHeader: some View {
        VStack(spacing: 15) {
            HStack {
                Button {
                    isPresented = false
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 24))
                        .foregroundColor(.white.opacity(0.7))
                }

                Spacer()
            }

            HStack(spacing: 20) {
                // Device icon
                Image(systemName: device.deviceType.icon)
                    .font(.system(size: 60))
                    .foregroundColor(device.riskLevel.color)

                VStack(alignment: .leading, spacing: 8) {
                    // Device name
                    Text(device.displayName)
                        .font(.system(size: 32, weight: .bold))
                        .foregroundColor(.white)

                    // IP Address
                    Text(device.ipAddress)
                        .font(.system(size: 18, design: .monospaced))
                        .foregroundColor(.cyan)

                    // OS
                    if let os = device.operatingSystem {
                        HStack(spacing: 8) {
                            Image(systemName: "desktopcomputer")
                            Text(os)
                        }
                        .font(.system(size: 14))
                        .foregroundColor(.white.opacity(0.7))
                    }

                    // Risk level
                    HStack(spacing: 12) {
                        Text("RISK: \(device.riskLevel.rawValue.uppercased())")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.white)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 4)
                            .background(
                                RoundedRectangle(cornerRadius: 6)
                                    .fill(device.riskLevel.color)
                            )

                        Text("Security Score: \(device.securityScore)/100")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(scoreColor)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 4)
                            .background(
                                RoundedRectangle(cornerRadius: 6)
                                    .fill(Color.white.opacity(0.1))
                            )
                    }
                }

                Spacer()

                // Quick stats
                VStack(alignment: .trailing, spacing: 8) {
                    statBadge(icon: "network", value: "\(device.openPorts.count)", label: "Open Ports")
                    statBadge(icon: "gear", value: "\(device.services.count)", label: "Services")
                    statBadge(icon: "exclamationmark.triangle.fill", value: "\(device.vulnerabilities.count)", label: "Vulnerabilities")
                }
            }
        }
        .padding(24)
        .background(
            LinearGradient(
                colors: [device.riskLevel.color.opacity(0.3), Color.black.opacity(0.9)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        )
    }

    private func statBadge(icon: String, value: String, label: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 12))
                .foregroundColor(.white.opacity(0.7))

            VStack(alignment: .trailing, spacing: 2) {
                Text(value)
                    .font(.system(size: 16, weight: .bold))
                    .foregroundColor(.white)
                Text(label)
                    .font(.system(size: 9))
                    .foregroundColor(.white.opacity(0.5))
            }
        }
    }

    // MARK: - Overview Tab

    private var overviewTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Summary section
                VStack(alignment: .leading, spacing: 12) {
                    Text("Device Summary")
                        .font(.system(size: 20, weight: .bold))
                        .foregroundColor(.white)

                    Divider()
                        .background(Color.white.opacity(0.2))

                    summaryRow(label: "Hostname", value: device.hostname ?? "N/A")
                    summaryRow(label: "IP Address", value: device.ipAddress)
                    summaryRow(label: "MAC Address", value: device.macAddress ?? "Unknown")
                    summaryRow(label: "Manufacturer", value: device.manufacturer ?? "Unknown")
                    summaryRow(label: "Device Type", value: device.deviceType.rawValue)
                    summaryRow(label: "Operating System", value: device.operatingSystem ?? "Unknown")
                    summaryRow(label: "Last Scanned", value: device.lastScanned.formatted(date: .abbreviated, time: .shortened))
                }
                .padding()
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(Color.white.opacity(0.05))
                )

                // Security assessment
                VStack(alignment: .leading, spacing: 12) {
                    Text("Security Assessment")
                        .font(.system(size: 20, weight: .bold))
                        .foregroundColor(.white)

                    Divider()
                        .background(Color.white.opacity(0.2))

                    HStack(spacing: 30) {
                        vulnerabilityCountCard(
                            title: "Critical",
                            count: device.criticalVulnCount,
                            color: .red
                        )

                        vulnerabilityCountCard(
                            title: "High",
                            count: device.highVulnCount,
                            color: .orange
                        )

                        vulnerabilityCountCard(
                            title: "Medium",
                            count: device.mediumVulnCount,
                            color: .yellow
                        )

                        vulnerabilityCountCard(
                            title: "Low",
                            count: device.lowVulnCount,
                            color: .blue
                        )
                    }
                }
                .padding()
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(Color.white.opacity(0.05))
                )
            }
            .padding()
        }
    }

    private func summaryRow(label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(.white.opacity(0.7))
                .frame(width: 150, alignment: .leading)

            Text(value)
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(.white)

            Spacer()
        }
    }

    private func vulnerabilityCountCard(title: String, count: Int, color: Color) -> some View {
        VStack(spacing: 8) {
            Text("\(count)")
                .font(.system(size: 36, weight: .bold))
                .foregroundColor(count > 0 ? color : .white.opacity(0.3))

            Text(title)
                .font(.system(size: 12))
                .foregroundColor(.white.opacity(0.6))
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(count > 0 ? color.opacity(0.2) : Color.white.opacity(0.03))
        )
    }

    // MARK: - Ports & Services Tab

    private var portsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Open Ports & Services")
                    .font(.system(size: 20, weight: .bold))
                    .foregroundColor(.white)

                if device.openPorts.isEmpty {
                    Text("No open ports detected")
                        .foregroundColor(.white.opacity(0.5))
                        .frame(maxWidth: .infinity, alignment: .center)
                        .padding(40)
                } else {
                    ForEach(device.openPorts) { port in
                        portCard(port: port)
                    }
                }
            }
            .padding()
        }
    }

    private func portCard(port: OpenPort) -> some View {
        let service = device.services.first(where: { $0.port == port.port })

        return HStack(spacing: 15) {
            // Port number
            Text("\(port.port)")
                .font(.system(size: 20, weight: .bold, design: .monospaced))
                .foregroundColor(.cyan)
                .frame(width: 70)

            VStack(alignment: .leading, spacing: 4) {
                // Service name
                Text(port.service ?? "Unknown Service")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundColor(.white)

                // Version
                if let version = service?.version {
                    Text("Version: \(version)")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.6))
                }

                // Banner
                if let banner = service?.banner {
                    Text(banner)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.white.opacity(0.4))
                        .lineLimit(2)
                }

                // State
                HStack(spacing: 6) {
                    Circle()
                        .fill(port.state == .open ? Color.green : Color.red)
                        .frame(width: 6, height: 6)

                    Text(port.state.rawValue.uppercased())
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(port.state == .open ? .green : .red)
                }
            }

            Spacer()

            // Protocol
            Text(port.portProtocol.rawValue)
                .font(.system(size: 10, weight: .bold))
                .foregroundColor(.white)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(
                    RoundedRectangle(cornerRadius: 4)
                        .fill(Color.white.opacity(0.1))
                )
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color.white.opacity(0.05))
        )
    }

    // MARK: - Vulnerabilities Tab

    private var vulnerabilitiesTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Vulnerabilities")
                    .font(.system(size: 20, weight: .bold))
                    .foregroundColor(.white)

                if device.vulnerabilities.isEmpty {
                    VStack(spacing: 15) {
                        Image(systemName: "checkmark.shield.fill")
                            .font(.system(size: 60))
                            .foregroundColor(.green)

                        Text("No Vulnerabilities Detected")
                            .font(.system(size: 18, weight: .semibold))
                            .foregroundColor(.white)

                        Text("This device appears to be secure based on current tests")
                            .font(.system(size: 13))
                            .foregroundColor(.white.opacity(0.6))
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(40)
                } else {
                    // Group by severity
                    vulnerabilitySection(title: "Critical", vulnerabilities: device.vulnerabilities.filter { $0.severity == .critical }, color: .red)
                    vulnerabilitySection(title: "High", vulnerabilities: device.vulnerabilities.filter { $0.severity == .high }, color: .orange)
                    vulnerabilitySection(title: "Medium", vulnerabilities: device.vulnerabilities.filter { $0.severity == .medium }, color: .yellow)
                    vulnerabilitySection(title: "Low", vulnerabilities: device.vulnerabilities.filter { $0.severity == .low }, color: .blue)
                }
            }
            .padding()
        }
    }

    private func vulnerabilitySection(title: String, vulnerabilities: [Vulnerability], color: Color) -> some View {
        Group {
            if !vulnerabilities.isEmpty {
                VStack(alignment: .leading, spacing: 12) {
                    Text("\(title) (\(vulnerabilities.count))")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(color)

                    ForEach(vulnerabilities) { vuln in
                        vulnerabilityCard(vuln: vuln, color: color)
                    }
                }
            }
        }
    }

    private func vulnerabilityCard(vuln: Vulnerability, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            // Title row
            HStack {
                Circle()
                    .fill(color)
                    .frame(width: 10, height: 10)

                Text(vuln.title)
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(.white)

                Spacer()

                if vuln.exploitAvailable {
                    Text("EXPLOIT AVAILABLE")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(
                            RoundedRectangle(cornerRadius: 4)
                                .fill(Color.red)
                        )
                }
            }

            // CVE ID
            if let cveId = vuln.cveId {
                Text(cveId)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.cyan)
            }

            // Description
            Text(vuln.description)
                .font(.system(size: 12))
                .foregroundColor(.white.opacity(0.8))
                .fixedSize(horizontal: false, vertical: true)

            // Details
            HStack(spacing: 20) {
                if let cvss = vuln.cvssScore {
                    detailLabel(icon: "chart.bar.fill", text: "CVSS: \(String(format: "%.1f", cvss))")
                }

                if let service = vuln.affectedService {
                    detailLabel(icon: "gear", text: service)
                }

                if let version = vuln.affectedVersion {
                    detailLabel(icon: "number", text: version)
                }
            }

            // Remediation if available
            if let remediation = vuln.remediation {
                VStack(alignment: .leading, spacing: 6) {
                    Text("REMEDIATION:")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.green)

                    Text(remediation)
                        .font(.system(size: 11))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(.top, 6)
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color.white.opacity(0.05))
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(color.opacity(0.3), lineWidth: 2)
                )
        )
    }

    private func detailLabel(icon: String, text: String) -> some View {
        HStack(spacing: 4) {
            Image(systemName: icon)
                .font(.system(size: 9))
            Text(text)
                .font(.system(size: 10))
        }
        .foregroundColor(.white.opacity(0.6))
    }

    // MARK: - Attack Tab

    private var attackTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Attack Options")
                    .font(.system(size: 20, weight: .bold))
                    .foregroundColor(.white)

                Text("Select attack methods to test this device")
                    .font(.system(size: 13))
                    .foregroundColor(.white.opacity(0.6))

                // Attack options
                attackOptionCard(
                    title: "Test Default Credentials",
                    description: "Try common usernames and passwords on SSH, FTP, Telnet, databases",
                    icon: "key.fill",
                    color: .orange,
                    severity: "MEDIUM RISK"
                )

                attackOptionCard(
                    title: "Exploit Known CVEs",
                    description: "Attempt to exploit \(device.vulnerabilities.count) known vulnerabilities",
                    icon: "bolt.fill",
                    color: .red,
                    severity: "HIGH RISK"
                )

                attackOptionCard(
                    title: "Web Application Scan",
                    description: "Test for SQL injection, XSS, directory traversal",
                    icon: "network",
                    color: .yellow,
                    severity: "MEDIUM RISK"
                )

                attackOptionCard(
                    title: "Brute Force Attack",
                    description: "Password brute force on detected services (rate-limited)",
                    icon: "lock.fill",
                    color: .red,
                    severity: "HIGH RISK"
                )

                attackOptionCard(
                    title: "AI-Recommended Attack Plan",
                    description: "Let AI analyze device and recommend optimal attack strategy",
                    icon: "brain",
                    color: .purple,
                    severity: "AI-POWERED"
                )

                Spacer()
            }
            .padding()
        }
    }

    private func attackOptionCard(title: String, description: String, icon: String, color: Color, severity: String) -> some View {
        Button {
            // Launch attack
        } label: {
            HStack(spacing: 15) {
                Image(systemName: icon)
                    .font(.system(size: 30))
                    .foregroundColor(color)
                    .frame(width: 50)

                VStack(alignment: .leading, spacing: 6) {
                    Text(title)
                        .font(.system(size: 15, weight: .bold))
                        .foregroundColor(.white)

                    Text(description)
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                        .fixedSize(horizontal: false, vertical: true)

                    Text(severity)
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(color)
                }

                Spacer()

                Image(systemName: "chevron.right")
                    .foregroundColor(.white.opacity(0.5))
            }
            .padding()
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(Color.white.opacity(0.05))
                    .overlay(
                        RoundedRectangle(cornerRadius: 10)
                            .stroke(color.opacity(0.3), lineWidth: 1)
                    )
            )
        }
        .buttonStyle(.plain)
    }

    // MARK: - Helpers

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
