//
//  HiddenProcessDetector.swift
//  Bastion
//
//  Detects hidden processes (rootkit technique)
//  Author: Jordan Koch
//  Date: 2025-01-20
//

import Foundation

class HiddenProcessDetector {
    private let ssh: SSHConnection

    init(ssh: SSHConnection) {
        self.ssh = ssh
    }

    /// Scan for hidden processes
    func scanForHiddenProcesses() async -> [HiddenProcessFinding] {
        var findings: [HiddenProcessFinding] = []

        print("[HiddenProcessDetector] Starting hidden process scan...")

        // Method 1: Compare ps output with /proc entries
        findings.append(contentsOf: await compareProcessLists())

        // Method 2: Check for processes using deleted executables
        findings.append(contentsOf: await checkDeletedExecutables())

        // Method 3: Look for processes with suspicious characteristics
        findings.append(contentsOf: await checkSuspiciousProcesses())

        print("[HiddenProcessDetector] Found \(findings.count) hidden/suspicious processes")
        return findings
    }

    /// Compare ps output with /proc directory entries
    private func compareProcessLists() async -> [HiddenProcessFinding] {
        var findings: [HiddenProcessFinding] = []

        // Get PIDs from ps command
        guard let psOutput = await ssh.execute("ps -eo pid --no-headers") else {
            return findings
        }
        let psPids = Set(psOutput.components(separatedBy: "\n")
            .compactMap { Int($0.trimmingCharacters(in: .whitespacesAndNewlines)) })

        // Get PIDs from /proc directory
        guard let procOutput = await ssh.execute("ls -d /proc/[0-9]* 2>/dev/null | sed 's/\\/proc\\///'") else {
            return findings
        }
        let procPids = Set(procOutput.components(separatedBy: "\n")
            .compactMap { Int($0.trimmingCharacters(in: .whitespacesAndNewlines)) })

        // Find discrepancies (PIDs in /proc but not in ps = hidden)
        let hiddenPids = procPids.subtracting(psPids)

        for pid in hiddenPids {
            // Try to get process info from /proc
            if let cmdline = await ssh.readFile("/proc/\(pid)/cmdline") {
                let command = cmdline.replacingOccurrences(of: "\0", with: " ").trimmingCharacters(in: .whitespacesAndNewlines)
                if !command.isEmpty {
                    let finding = HiddenProcessFinding(
                        pid: pid,
                        command: command,
                        hideMethod: "Not visible in ps output (rootkit hiding)"
                    )
                    findings.append(finding)
                    print("[HiddenProcessDetector] ⚠️ CRITICAL: Hidden process detected - PID \(pid): \(command)")
                }
            }
        }

        return findings
    }

    /// Check for processes running deleted executables (indicator of compromise)
    private func checkDeletedExecutables() async -> [HiddenProcessFinding] {
        var findings: [HiddenProcessFinding] = []

        // Find processes using deleted executables
        if let lsofOutput = await ssh.execute("lsof +L1 2>/dev/null | grep '(deleted)' | awk '{print $2, $1, $9}'") {
            let lines = lsofOutput.components(separatedBy: "\n")
            for line in lines {
                if !line.isEmpty {
                    let parts = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                    if parts.count >= 3 {
                        if let pid = Int(parts[0]) {
                            let command = parts[1]
                            let file = parts[2]
                            let finding = HiddenProcessFinding(
                                pid: pid,
                                command: "\(command) (deleted: \(file))",
                                hideMethod: "Process running from deleted executable (common attack persistence)"
                            )
                            findings.append(finding)
                            print("[HiddenProcessDetector] ⚠️ Process using deleted executable: PID \(pid) - \(command)")
                        }
                    }
                }
            }
        }

        return findings
    }

    /// Check for processes with suspicious characteristics
    private func checkSuspiciousProcesses() async -> [HiddenProcessFinding] {
        var findings: [HiddenProcessFinding] = []

        // Check for processes with suspicious names
        let suspiciousPatterns = [
            "[kworker/0:0]", "[events/0]", "[eth0]", "[sshd]", "[httpd]",
            "..  ", "....", "   ", ". ", "     "
        ]

        if let psOutput = await ssh.execute("ps aux") {
            let lines = psOutput.components(separatedBy: "\n")
            for line in lines {
                for pattern in suspiciousPatterns {
                    if line.contains(pattern) {
                        // Extract PID and command
                        let parts = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                        if parts.count >= 11, let pid = Int(parts[1]) {
                            let command = parts[10...].joined(separator: " ")
                            let finding = HiddenProcessFinding(
                                pid: pid,
                                command: command,
                                hideMethod: "Suspicious process name mimicking system process"
                            )
                            findings.append(finding)
                            print("[HiddenProcessDetector] ⚠️ Suspicious process name: \(command)")
                        }
                    }
                }
            }
        }

        // Check for processes listening on ports but not showing in netstat
        findings.append(contentsOf: await checkStealthyListeners())

        return findings
    }

    /// Check for processes listening on ports but hidden from netstat
    private func checkStealthyListeners() async -> [HiddenProcessFinding] {
        var findings: [HiddenProcessFinding] = []

        // Get processes with open network connections directly from /proc
        if let procNetTcp = await ssh.readFile("/proc/net/tcp") {
            // Parse /proc/net/tcp for listening sockets
            let lines = procNetTcp.components(separatedBy: "\n")
            for line in lines.dropFirst() { // Skip header
                if line.contains(": 0A") { // LISTEN state
                    // Extract inode
                    let parts = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                    if parts.count >= 10 {
                        let inode = parts[9]
                        // Find which process owns this inode
                        if let findOutput = await ssh.execute("find /proc/*/fd -lname 'socket:\\[\(inode)\\]' 2>/dev/null | head -1") {
                            if !findOutput.isEmpty {
                                // Extract PID from path like /proc/1234/fd/3
                                let pathParts = findOutput.components(separatedBy: "/")
                                if pathParts.count >= 3, let pid = Int(pathParts[2]) {
                                    // Check if this PID shows up in netstat
                                    if let netstatOutput = await ssh.execute("netstat -tulpn 2>/dev/null | grep '\(pid)/'") {
                                        if netstatOutput.isEmpty {
                                            // Process has listening socket but not in netstat = hidden
                                            if let cmdline = await ssh.readFile("/proc/\(pid)/cmdline") {
                                                let command = cmdline.replacingOccurrences(of: "\0", with: " ")
                                                let finding = HiddenProcessFinding(
                                                    pid: pid,
                                                    command: command,
                                                    hideMethod: "Process listening on network but hidden from netstat (kernel rootkit)"
                                                )
                                                findings.append(finding)
                                                print("[HiddenProcessDetector] ⚠️ CRITICAL: Stealthy listener detected - PID \(pid)")
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return findings
    }
}
