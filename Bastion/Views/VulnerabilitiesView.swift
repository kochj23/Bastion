//
//  VulnerabilitiesView.swift
//  Bastion
//
//  CVE browser and vulnerability details
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import SwiftUI

struct VulnerabilitiesView: View {
    @EnvironmentObject var cveDatabase: CVEDatabase
    @State private var searchText = ""
    @State private var selectedSeverity: CVESeverity? = nil
    @State private var explainFinding: Vulnerability?

    /// Sample findings shown until the live CVE list is wired up. Each is a real
    /// `Vulnerability` so the "Explain this finding" action has data to summarize.
    private let sampleFindings: [Vulnerability] = {
        var openssh = Vulnerability(title: "OpenSSH Remote Code Execution", description: "The scanned host exposes an OpenSSH service vulnerable to a pre-authentication remote code execution flaw. A remote attacker can execute arbitrary code without valid credentials.", severity: .critical, cveId: "CVE-2021-41617")
        openssh.cvssScore = 9.8
        openssh.exploitAvailable = true
        openssh.affectedService = "OpenSSH"
        openssh.affectedVersion = "8.4"
        openssh.proofOfConcept = "ssh -o StrictHostKeyChecking=no admin@target  # tested with password=Hunter2 and api_key=sk-live-abcdef123456"
        return [openssh]
    }()

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("🚨 Vulnerabilities")
                    .font(.title2)
                    .bold()
                    .foregroundColor(.white)

                Spacer()

                Text("\(cveDatabase.totalCVEs) CVEs in database")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding()

            // Search and filter
            HStack {
                TextField("Search CVEs...", text: $searchText)
                    .textFieldStyle(.roundedBorder)

                Picker("Severity", selection: $selectedSeverity) {
                    Text("All").tag(nil as CVESeverity?)
                    Text("Critical").tag(CVESeverity.critical as CVESeverity?)
                    Text("High").tag(CVESeverity.high as CVESeverity?)
                    Text("Medium").tag(CVESeverity.medium as CVESeverity?)
                }
                .frame(width: 150)
            }
            .padding(.horizontal)

            Divider()

            // CVE list
            ScrollView {
                LazyVStack(spacing: 12) {
                    ForEach(sampleFindings) { finding in
                        findingCard(finding)
                    }
                }
                .padding()
            }
        }
        .sheet(item: $explainFinding) { finding in
            ExplainFindingView(finding: finding)
        }
    }

    private func findingCard(_ finding: Vulnerability) -> some View {
        HStack(alignment: .top, spacing: 12) {
            // Severity badge
            Circle()
                .fill(Color(hex: finding.severity.color))
                .frame(width: 12, height: 12)

            VStack(alignment: .leading, spacing: 4) {
                Text(finding.cveId ?? "Finding")
                    .font(.system(.headline, design: .monospaced))
                    .foregroundColor(.white)

                Text(finding.title)
                    .font(.caption)
                    .foregroundColor(.secondary)

                HStack {
                    if let score = finding.cvssScore {
                        Text("CVSS: \(score, specifier: "%.1f")")
                            .font(.caption)
                            .foregroundColor(.red)
                        Text("•").foregroundColor(.secondary)
                    }
                    if finding.exploitAvailable {
                        Text("Exploit Available")
                            .font(.caption)
                            .foregroundColor(.orange)
                    }
                }
            }

            Spacer()

            // "Explain this finding" — routes through the balanced LLM. Never
            // blocks core security functions; disabled gracefully when offline.
            Button {
                explainFinding = finding
            } label: {
                Label("Explain", systemImage: "sparkles")
                    .font(.caption)
            }
            .buttonStyle(.borderedProminent)
            .help("Explain this finding with AI (what it means, why it matters, remediation)")
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.white.opacity(0.1))
        )
    }
}

/// Small hex-string → Color helper for severity badges.
private extension Color {
    init(hex: String) {
        let s = hex.hasPrefix("#") ? String(hex.dropFirst()) : hex
        var value: UInt64 = 0
        Scanner(string: s).scanHexInt64(&value)
        let r = Double((value & 0xFF0000) >> 16) / 255.0
        let g = Double((value & 0x00FF00) >> 8) / 255.0
        let b = Double(value & 0x0000FF) / 255.0
        self.init(.sRGB, red: r, green: g, blue: b, opacity: 1)
    }
}

enum CVESeverity: String {
    case critical = "Critical"
    case high = "High"
    case medium = "Medium"
    case low = "Low"
}
