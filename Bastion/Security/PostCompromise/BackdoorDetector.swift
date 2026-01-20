//
//  BackdoorDetector.swift
//  Bastion
//
//  Detects backdoor ports and suspicious services
//  Author: Jordan Koch
//  Date: 2025-01-20
//

import Foundation

class BackdoorDetector {
    private let ssh: SSHConnection

    // Known backdoor ports
    private let backdoorPorts: [Int: String] = [
        31337: "Back Orifice/Elite",
        12345: "NetBus",
        54321: "Back Orifice 2000",
        1243: "SubSeven",
        6667: "IRC Bot/Trinity",
        6711: "SubSeven",
        6776: "BackDoor-G, SubSeven",
        9872: "Portal of Doom",
        9873: "Portal of Doom",
        9874: "Portal of Doom",
        9875: "Portal of Doom",
        20034: "NetBus 2 Pro",
        20432: "Shaft DDoS",
        27374: "SubSeven 2.2",
        30100: "NetSphere",
        30303: "Sockets de Troie",
        30999: "Kuang2",
        40421: "Agent 40421",
        40422: "Master Paradise",
        40423: "Master Paradise",
        40426: "Master Paradise",
        65000: "Devil/Stacheldraht"
    ]

    // Suspicious high ports (commonly used by backdoors)
    private let suspiciousPortRanges: [(ClosedRange<Int>, String)] = [
        (30000...40000, "Common backdoor range"),
        (60000...65535, "High ephemeral port range")
    ]

    init(ssh: SSHConnection) {
        self.ssh = ssh
    }

    /// Scan for backdoor ports and suspicious services
    func scanForBackdoors() async -> [BackdoorFinding] {
        var findings: [BackdoorFinding] = []

        print("[BackdoorDetector] Starting backdoor scan...")

        // Get listening ports with netstat
        if let netstatOutput = await ssh.execute("netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null") {
            findings.append(contentsOf: await analyzeListeningPorts(netstatOutput))
        }

        // Check for reverse shells
        findings.append(contentsOf: await checkForReverseShells())

        // Check for web shells
        findings.append(contentsOf: await checkForWebShells())

        print("[BackdoorDetector] Found \(findings.count) potential backdoors")
        return findings
    }

    /// Analyze listening ports for backdoors
    private func analyzeListeningPorts(_ netstatOutput: String) async -> [BackdoorFinding] {
        var findings: [BackdoorFinding] = []

        let lines = netstatOutput.components(separatedBy: "\n")
        for line in lines {
            // Parse netstat/ss output: tcp  0  0 0.0.0.0:31337  0.0.0.0:*  LISTEN  1234/backdoor
            let parts = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
            guard parts.count >= 4 else { continue }

            // Extract port from address:port format
            let addressPort = parts[3]
            if let colonIndex = addressPort.lastIndex(of: ":") {
                let portStr = String(addressPort[addressPort.index(after: colonIndex)...])
                if let port = Int(portStr) {
                    // Check if it's a known backdoor port
                    if let backdoorName = backdoorPorts[port] {
                        let service = parts.count >= 7 ? parts[6] : "unknown"
                        let finding = BackdoorFinding(
                            port: port,
                            service: service,
                            description: "Known backdoor port detected",
                            suspicionReason: "Port \(port) is associated with \(backdoorName)"
                        )
                        findings.append(finding)
                        print("[BackdoorDetector] ⚠️ CRITICAL: Known backdoor port \(port) (\(backdoorName))")
                    }

                    // Check suspicious port ranges
                    for (range, reason) in suspiciousPortRanges {
                        if range.contains(port) {
                            let service = parts.count >= 7 ? parts[6] : "unknown"
                            // Only report if service is not a known legitimate one
                            if !isKnownLegitimateService(service) {
                                let finding = BackdoorFinding(
                                    port: port,
                                    service: service,
                                    description: "Suspicious port in \(reason)",
                                    suspicionReason: "Port \(port) is listening in \(reason) - Service: \(service)"
                                )
                                findings.append(finding)
                                print("[BackdoorDetector] ⚠️ Suspicious port: \(port) - \(service)")
                            }
                        }
                    }

                    // Check for services with suspicious names
                    if parts.count >= 7 {
                        let service = parts[6]
                        if isSuspiciousServiceName(service) {
                            let finding = BackdoorFinding(
                                port: port,
                                service: service,
                                description: "Service with suspicious name",
                                suspicionReason: "Service name '\(service)' is suspicious"
                            )
                            findings.append(finding)
                            print("[BackdoorDetector] ⚠️ Suspicious service name: \(service) on port \(port)")
                        }
                    }
                }
            }
        }

        return findings
    }

    /// Check for reverse shell connections
    private func checkForReverseShells() async -> [BackdoorFinding] {
        var findings: [BackdoorFinding] = []

        // Look for processes with suspicious network connections
        if let netstatOutput = await ssh.execute("netstat -anp 2>/dev/null | grep ESTABLISHED") {
            let lines = netstatOutput.components(separatedBy: "\n")
            for line in lines {
                // Look for shells connected to remote IPs
                if line.contains("/sh") || line.contains("/bash") || line.contains("/nc") {
                    print("[BackdoorDetector] ⚠️ Potential reverse shell detected: \(line)")
                    let finding = BackdoorFinding(
                        port: 0,
                        service: "reverse_shell",
                        description: "Potential reverse shell connection",
                        suspicionReason: line.trimmingCharacters(in: .whitespacesAndNewlines)
                    )
                    findings.append(finding)
                }
            }
        }

        // Check for common reverse shell patterns in processes
        if let psOutput = await ssh.execute("ps aux | grep -E '(bash -i|sh -i|/dev/tcp|nc -e|ncat -e)'") {
            if !psOutput.isEmpty && !psOutput.contains("grep") {
                let finding = BackdoorFinding(
                    port: 0,
                    service: "reverse_shell_process",
                    description: "Reverse shell process detected",
                    suspicionReason: "Process matches reverse shell pattern"
                )
                findings.append(finding)
                print("[BackdoorDetector] ⚠️ CRITICAL: Reverse shell process detected")
            }
        }

        return findings
    }

    /// Check for web shells in common web directories
    private func checkForWebShells() async -> [BackdoorFinding] {
        var findings: [BackdoorFinding] = []

        let webDirs = [
            "/var/www/html",
            "/usr/share/nginx/html",
            "/var/www",
            "/home/*/public_html"
        ]

        let webShellSignatures = [
            "c99.php", "r57.php", "WSO.php", "b374k.php",
            "shell.php", "cmd.php", "backdoor.php"
        ]

        for dir in webDirs {
            for signature in webShellSignatures {
                if await ssh.fileExists("\(dir)/\(signature)") {
                    let finding = BackdoorFinding(
                        port: 80,
                        service: "web_shell",
                        description: "Known web shell detected",
                        suspicionReason: "Found \(signature) in \(dir)"
                    )
                    findings.append(finding)
                    print("[BackdoorDetector] ⚠️ CRITICAL: Web shell detected: \(dir)/\(signature)")
                }
            }

            // Check for PHP files with suspicious functions
            if let phpFiles = await ssh.execute("find \(dir) -name '*.php' -type f 2>/dev/null") {
                let files = phpFiles.components(separatedBy: "\n").prefix(20) // Limit to first 20
                for file in files {
                    if !file.isEmpty {
                        if let content = await ssh.readFile(file) {
                            if content.contains("eval(") || content.contains("base64_decode") ||
                               content.contains("system(") || content.contains("exec(") {
                                let finding = BackdoorFinding(
                                    port: 80,
                                    service: "suspicious_php",
                                    description: "PHP file with suspicious functions",
                                    suspicionReason: "File \(file) contains eval/exec/system functions"
                                )
                                findings.append(finding)
                                print("[BackdoorDetector] ⚠️ Suspicious PHP file: \(file)")
                                break // Only report once per directory
                            }
                        }
                    }
                }
            }
        }

        return findings
    }

    /// Check if service name is known to be legitimate
    private func isKnownLegitimateService(_ service: String) -> Bool {
        let legitimate = ["sshd", "httpd", "nginx", "apache2", "mysqld", "postgres", "redis", "node"]
        return legitimate.contains { service.contains($0) }
    }

    /// Check if service name is suspicious
    private func isSuspiciousServiceName(_ service: String) -> Bool {
        let suspicious = [
            "backdoor", "rootkit", "hide", "hidden", "....", "..  ",
            "update.sh", "cron.sh", "init.sh", "[kworker]", "[events]"
        ]
        return suspicious.contains { service.contains($0) }
    }
}
