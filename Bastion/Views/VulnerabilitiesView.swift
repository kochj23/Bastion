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
                    // Placeholder for CVE list
                    ForEach(0..<10, id: \.self) { index in
                        cvePlaceholderCard()
                    }
                }
                .padding()
            }
        }
    }

    private func cvePlaceholderCard() -> some View {
        HStack(alignment: .top, spacing: 12) {
            // Severity badge
            Circle()
                .fill(Color.red)
                .frame(width: 12, height: 12)

            VStack(alignment: .leading, spacing: 4) {
                Text("CVE-2021-41617")
                    .font(.system(.headline, design: .monospaced))
                    .foregroundColor(.white)

                Text("OpenSSH Remote Code Execution")
                    .font(.caption)
                    .foregroundColor(.secondary)

                HStack {
                    Text("CVSS: 9.8")
                        .font(.caption)
                        .foregroundColor(.red)

                    Text("•")
                        .foregroundColor(.secondary)

                    Text("Exploit Available")
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

enum CVESeverity: String {
    case critical = "Critical"
    case high = "High"
    case medium = "Medium"
    case low = "Low"
}
