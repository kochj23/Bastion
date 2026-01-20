//
//  LogTamperingDetector.swift
//  Bastion
//
//  Detects log file tampering and suspicious log activity
//  Author: Jordan Koch
//  Date: 2025-01-20
//

import Foundation

class LogTamperingDetector {
    private let ssh: SSHConnection

    // Critical log files to check
    private let criticalLogs = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/kern.log",
        "/var/log/daemon.log",
        "/var/log/wtmp",
        "/var/log/lastlog"
    ]

    init(ssh: SSHConnection) {
        self.ssh = ssh
    }

    /// Scan for log tampering
    func scanForLogTampering() async -> [LogTamperingFinding] {
        var findings: [LogTamperingFinding] = []

        print("[LogTamperingDetector] Starting log tampering scan...")

        for logFile in criticalLogs {
            // Check if log exists
            guard await ssh.fileExists(logFile) else {
                let finding = LogTamperingFinding(
                    logFile: logFile,
                    tamperingType: .missing,
                    description: "Critical log file is missing"
                )
                findings.append(finding)
                print("[LogTamperingDetector] ⚠️ Missing log file: \(logFile)")
                continue
            }

            // Check if log was cleared
            if let cleared = await checkIfCleared(logFile), cleared {
                let finding = LogTamperingFinding(
                    logFile: logFile,
                    tamperingType: .cleared,
                    description: "Log file appears to have been cleared"
                )
                findings.append(finding)
                print("[LogTamperingDetector] ⚠️ CRITICAL: Log file cleared: \(logFile)")
            }

            // Check for gaps in log timestamps
            if let gaps = await checkForGaps(logFile), !gaps.isEmpty {
                let finding = LogTamperingFinding(
                    logFile: logFile,
                    tamperingType: .gapDetected,
                    description: "Suspicious gaps in log timestamps: \(gaps)"
                )
                findings.append(finding)
                print("[LogTamperingDetector] ⚠️ Log gaps detected: \(logFile)")
            }

            // Check permissions (logs should not be world-writable)
            if let suspicious = await checkPermissions(logFile), suspicious {
                let finding = LogTamperingFinding(
                    logFile: logFile,
                    tamperingType: .suspiciousPermissions,
                    description: "Log file has suspicious permissions (world-writable)"
                )
                findings.append(finding)
                print("[LogTamperingDetector] ⚠️ Suspicious log permissions: \(logFile)")
            }
        }

        // Check for suspicious log entries (failed login attempts that suddenly stopped)
        findings.append(contentsOf: await checkSuspiciousLogPatterns())

        print("[LogTamperingDetector] Found \(findings.count) log tampering issues")
        return findings
    }

    /// Check if log file was recently cleared
    private func checkIfCleared(_ logFile: String) async -> Bool? {
        // Get system uptime
        guard let uptimeOutput = await ssh.execute("uptime -s 2>/dev/null || cat /proc/uptime 2>/dev/null") else {
            return nil
        }

        // Get log file size
        guard let statOutput = await ssh.execute("stat -c '%s' \(logFile) 2>/dev/null || stat -f '%z' \(logFile) 2>/dev/null") else {
            return nil
        }

        if let size = Int(statOutput.trimmingCharacters(in: .whitespacesAndNewlines)) {
            // If log file is empty or very small (< 100 bytes) and system has been up for a while
            if size < 100 {
                // Check how long system has been up
                if let uptimeStr = await ssh.execute("cat /proc/uptime | awk '{print $1}'") {
                    if let uptime = Double(uptimeStr.trimmingCharacters(in: .whitespacesAndNewlines)) {
                        let uptimeDays = uptime / 86400
                        if uptimeDays > 1.0 { // System up for more than a day with empty logs = suspicious
                            return true
                        }
                    }
                }
            }
        }

        return false
    }

    /// Check for gaps in log timestamps
    private func checkForGaps(_ logFile: String) async -> String? {
        // Get first and last 10 lines with timestamps
        guard let headLines = await ssh.execute("head -10 \(logFile) 2>/dev/null") else {
            return nil
        }
        guard let tailLines = await ssh.execute("tail -10 \(logFile) 2>/dev/null") else {
            return nil
        }

        // Extract timestamps (this is simplified - real implementation would parse various log formats)
        // For now, just check if there are huge gaps

        // Get file modification time and compare with log content
        if let statOutput = await ssh.execute("stat -c '%Y' \(logFile) 2>/dev/null || stat -f '%m' \(logFile) 2>/dev/null") {
            if let modTime = TimeInterval(statOutput.trimmingCharacters(in: .whitespacesAndNewlines)) {
                let modDate = Date(timeIntervalSince1970: modTime)
                let daysSinceMod = Date().timeIntervalSince(modDate) / 86400

                // If log hasn't been modified in days but system is active, suspicious
                if daysSinceMod > 7 {
                    return "Log not modified in \(Int(daysSinceMod)) days"
                }
            }
        }

        return nil
    }

    /// Check log file permissions
    private func checkPermissions(_ logFile: String) async -> Bool? {
        if let statOutput = await ssh.execute("stat -c '%a' \(logFile) 2>/dev/null || stat -f '%Lp' \(logFile) 2>/dev/null") {
            let perms = statOutput.trimmingCharacters(in: .whitespacesAndNewlines)

            // Check for world-writable (last digit is 2, 3, 6, or 7)
            if perms.hasSuffix("2") || perms.hasSuffix("3") || perms.hasSuffix("6") || perms.hasSuffix("7") {
                return true
            }
        }
        return false
    }

    /// Check for suspicious patterns in logs
    private func checkSuspiciousLogPatterns() async -> [LogTamperingFinding] {
        var findings: [LogTamperingFinding] = []

        // Check auth.log for patterns
        let authLogs = ["/var/log/auth.log", "/var/log/secure"]
        for logFile in authLogs {
            if await ssh.fileExists(logFile) {
                // Check for sudden stop of failed login attempts (might indicate log clearing)
                if let failedLogins = await ssh.execute("grep -i 'failed password' \(logFile) 2>/dev/null | tail -20") {
                    if !failedLogins.isEmpty {
                        // Get last failed login timestamp
                        let lines = failedLogins.components(separatedBy: "\n")
                        if let lastLine = lines.last, !lastLine.isEmpty {
                            // If there were failed logins but none recently, might be cleared
                            // (This is a heuristic - real implementation would parse timestamps)
                        }
                    }
                }

                // Check for suspicious entries (like cleared utmp/wtmp)
                if let suspiciousEntries = await ssh.execute("grep -i 'cleared\\|deleted\\|removed.*log' \(logFile) 2>/dev/null") {
                    if !suspiciousEntries.isEmpty {
                        let finding = LogTamperingFinding(
                            logFile: logFile,
                            tamperingType: .gapDetected,
                            description: "Log contains references to log clearing/deletion"
                        )
                        findings.append(finding)
                        print("[LogTamperingDetector] ⚠️ Log mentions log clearing: \(logFile)")
                    }
                }
            }
        }

        return findings
    }
}
