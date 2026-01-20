//
//  NetworkSnifferDetector.swift
//  Bastion
//
//  Detects network sniffers and promiscuous mode interfaces
//  Author: Jordan Koch
//  Date: 2025-01-20
//

import Foundation

class NetworkSnifferDetector {
    private let ssh: SSHConnection

    init(ssh: SSHConnection) {
        self.ssh = ssh
    }

    /// Scan for network sniffers
    func scanForSniffers() async -> [NetworkSnifferFinding] {
        var findings: [NetworkSnifferFinding] = []

        print("[NetworkSnifferDetector] Starting network sniffer scan...")

        // Check for promiscuous mode interfaces
        findings.append(contentsOf: await checkPromiscuousMode())

        // Check for running packet capture tools
        findings.append(contentsOf: await checkSnifferProcesses())

        // Check for suspicious network activity
        findings.append(contentsOf: await checkSuspiciousNetworkActivity())

        print("[NetworkSnifferDetector] Found \(findings.count) network sniffer indicators")
        return findings
    }

    /// Check for network interfaces in promiscuous mode
    private func checkPromiscuousMode() async -> [NetworkSnifferFinding] {
        var findings: [NetworkSnifferFinding] = []

        // Method 1: Check with ip link
        if let ipOutput = await ssh.execute("ip link show 2>/dev/null") {
            let lines = ipOutput.components(separatedBy: "\n")
            for line in lines {
                if line.contains("PROMISC") {
                    // Extract interface name
                    let parts = line.components(separatedBy: ":").filter { !$0.isEmpty }
                    if parts.count >= 2 {
                        let interface = parts[1].trimmingCharacters(in: .whitespaces)
                        let finding = NetworkSnifferFinding(
                            interface: interface,
                            isPromiscuous: true,
                            snifferProcess: nil
                        )
                        findings.append(finding)
                        print("[NetworkSnifferDetector] ⚠️ CRITICAL: Interface in promiscuous mode: \(interface)")
                    }
                }
            }
        }

        // Method 2: Check with ifconfig (fallback)
        if let ifconfigOutput = await ssh.execute("ifconfig 2>/dev/null || /sbin/ifconfig 2>/dev/null") {
            let lines = ifconfigOutput.components(separatedBy: "\n")
            var currentInterface: String?

            for line in lines {
                // Interface line (e.g., "eth0: ...")
                if !line.hasPrefix(" ") && !line.hasPrefix("\t") && line.contains(":") {
                    let parts = line.components(separatedBy: ":").filter { !$0.isEmpty }
                    if !parts.isEmpty {
                        currentInterface = parts[0].trimmingCharacters(in: .whitespaces)
                    }
                }

                // Check for PROMISC flag
                if line.uppercased().contains("PROMISC") {
                    if let interface = currentInterface {
                        let finding = NetworkSnifferFinding(
                            interface: interface,
                            isPromiscuous: true,
                            snifferProcess: nil
                        )
                        findings.append(finding)
                        print("[NetworkSnifferDetector] ⚠️ CRITICAL: Interface in promiscuous mode: \(interface)")
                        currentInterface = nil
                    }
                }
            }
        }

        // Method 3: Check /sys/class/net/*/flags
        if let interfaces = await ssh.execute("ls /sys/class/net/ 2>/dev/null") {
            let interfaceList = interfaces.components(separatedBy: "\n")
            for interface in interfaceList {
                if !interface.isEmpty && interface != "lo" {
                    if let flags = await ssh.readFile("/sys/class/net/\(interface)/flags") {
                        // Promiscuous mode is bit 8 (0x100)
                        if let flagValue = Int(flags.trimmingCharacters(in: .whitespacesAndNewlines).dropFirst(2), radix: 16) {
                            if (flagValue & 0x100) != 0 {
                                let finding = NetworkSnifferFinding(
                                    interface: interface,
                                    isPromiscuous: true,
                                    snifferProcess: nil
                                )
                                findings.append(finding)
                                print("[NetworkSnifferDetector] ⚠️ CRITICAL: Interface in promiscuous mode: \(interface)")
                            }
                        }
                    }
                }
            }
        }

        return findings
    }

    /// Check for running packet capture processes
    private func checkSnifferProcesses() async -> [NetworkSnifferFinding] {
        var findings: [NetworkSnifferFinding] = []

        let snifferTools = [
            "tcpdump", "wireshark", "tshark", "ettercap", "dsniff",
            "ngrep", "snort", "suricata", "bro", "zeek", "pcap"
        ]

        for tool in snifferTools {
            if let psOutput = await ssh.execute("ps aux | grep -v grep | grep '\(tool)'") {
                if !psOutput.isEmpty {
                    // Extract process details
                    let lines = psOutput.components(separatedBy: "\n")
                    for line in lines {
                        if !line.isEmpty {
                            let parts = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                            if parts.count >= 11 {
                                let process = parts[10...].joined(separator: " ")
                                let finding = NetworkSnifferFinding(
                                    interface: "unknown",
                                    isPromiscuous: false,
                                    snifferProcess: process
                                )
                                findings.append(finding)
                                print("[NetworkSnifferDetector] ⚠️ Packet capture tool detected: \(tool)")
                            }
                        }
                    }
                }
            }
        }

        return findings
    }

    /// Check for suspicious network activity patterns
    private func checkSuspiciousNetworkActivity() async -> [NetworkSnifferFinding] {
        var findings: [NetworkSnifferFinding] = []

        // Check for processes with raw sockets (used by packet sniffers)
        if let lsofOutput = await ssh.execute("lsof -i -n | grep -i 'raw' 2>/dev/null") {
            if !lsofOutput.isEmpty {
                let lines = lsofOutput.components(separatedBy: "\n")
                for line in lines {
                    if !line.isEmpty {
                        let parts = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                        if parts.count >= 2 {
                            let process = parts[0]
                            let finding = NetworkSnifferFinding(
                                interface: "unknown",
                                isPromiscuous: false,
                                snifferProcess: "Process with raw socket: \(process)"
                            )
                            findings.append(finding)
                            print("[NetworkSnifferDetector] ⚠️ Process with raw socket: \(process)")
                        }
                    }
                }
            }
        }

        // Check for pcap files being written (indicates active capture)
        if let pcapFiles = await ssh.execute("lsof 2>/dev/null | grep -E '\\.pcap|\\.cap' | head -5") {
            if !pcapFiles.isEmpty {
                let finding = NetworkSnifferFinding(
                    interface: "unknown",
                    isPromiscuous: false,
                    snifferProcess: "Active packet capture detected (writing .pcap files)"
                )
                findings.append(finding)
                print("[NetworkSnifferDetector] ⚠️ Active packet capture detected (.pcap files)")
            }
        }

        return findings
    }
}
