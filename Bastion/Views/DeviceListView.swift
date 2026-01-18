//
//  DeviceListView.swift
//  Bastion
//
//  Device list with security scores and attack buttons
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import SwiftUI

struct DeviceListView: View {
    @EnvironmentObject var networkScanner: NetworkScanner
    @State private var selectedDevice: Device?
    @State private var sortBy: SortOption = .vulnerability

    enum SortOption {
        case ip, hostname, vulnerability, securityScore
    }

    var sortedDevices: [Device] {
        switch sortBy {
        case .ip:
            return networkScanner.discoveredDevices.sorted { $0.ipAddress < $1.ipAddress }
        case .hostname:
            return networkScanner.discoveredDevices.sorted { ($0.hostname ?? "") < ($1.hostname ?? "") }
        case .vulnerability:
            return networkScanner.discoveredDevices.sorted { $0.vulnerabilities.count > $1.vulnerabilities.count }
        case .securityScore:
            return networkScanner.discoveredDevices.sorted { $0.securityScore < $1.securityScore }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("🌐 Discovered Devices (\(networkScanner.discoveredDevices.count))")
                    .font(.title2)
                    .bold()
                    .foregroundColor(.white)

                Spacer()

                Picker("Sort", selection: $sortBy) {
                    Text("IP").tag(SortOption.ip)
                    Text("Name").tag(SortOption.hostname)
                    Text("Vulnerabilities").tag(SortOption.vulnerability)
                    Text("Score").tag(SortOption.securityScore)
                }
                .pickerStyle(.segmented)
                .frame(width: 300)
            }
            .padding()

            Divider()

            // Device table
            if sortedDevices.isEmpty {
                VStack(spacing: 20) {
                    Image(systemName: "network.slash")
                        .font(.system(size: 60))
                        .foregroundColor(.secondary)
                    Text("No devices discovered")
                        .font(.headline)
                        .foregroundColor(.secondary)
                    Text("Run a network scan to discover devices")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 12) {
                        ForEach(sortedDevices) { device in
                            DeviceRow(device: device, isSelected: selectedDevice?.id == device.id)
                                .onTapGesture {
                                    selectedDevice = device
                                }
                        }
                    }
                    .padding()
                }
            }
        }
    }
}

struct DeviceRow: View {
    let device: Device
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 16) {
            // Risk indicator
            Circle()
                .fill(device.riskLevel.color)
                .frame(width: 20, height: 20)
                .shadow(color: device.riskLevel.color, radius: 5)

            // Device info
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(device.ipAddress)
                        .font(.system(.headline, design: .monospaced))
                        .foregroundColor(.white)

                    if let hostname = device.hostname {
                        Text("(\(hostname))")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                HStack(spacing: 12) {
                    if let os = device.operatingSystem {
                        Label(os, systemImage: "desktopcomputer")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }

                    Label("\(device.openPorts.count) ports", systemImage: "circle.grid.3x3")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Label("\(device.vulnerabilities.count) vulns", systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundColor(device.vulnerabilities.isEmpty ? .green : .red)
                }
            }

            Spacer()

            // Security score
            VStack {
                Text("\(device.securityScore)")
                    .font(.system(.title, design: .rounded))
                    .bold()
                    .foregroundColor(scoreColor(device.securityScore))
                Text("/ 100")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            // Attack button
            Button("🎯 Attack") {
                // Attack this device
            }
            .buttonStyle(.borderedProminent)
            .tint(device.riskLevel.color)
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color.white.opacity(isSelected ? 0.3 : 0.15))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(isSelected ? Color.cyan : Color.white.opacity(0.3), lineWidth: isSelected ? 3 : 1)
                )
        )
    }

    private func scoreColor(_ score: Int) -> Color {
        if score >= 80 { return .green }
        if score >= 60 { return .yellow }
        if score >= 40 { return .orange }
        return .red
    }
}
