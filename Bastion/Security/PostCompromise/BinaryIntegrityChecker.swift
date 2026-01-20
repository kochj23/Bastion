//
//  BinaryIntegrityChecker.swift
//  Bastion
//
//  Checks system binaries for tampering and trojanization
//  Author: Jordan Koch
//  Date: 2025-01-20
//

import Foundation

class BinaryIntegrityChecker {
    private let ssh: SSHConnection
    private var detectedDistro: String?

    // Critical system binaries to check
    private let criticalBinaries = [
        "/bin/ls", "/bin/ps", "/bin/netstat", "/bin/login",
        "/bin/su", "/bin/bash", "/bin/sh",
        "/usr/bin/ssh", "/usr/bin/sshd", "/usr/sbin/sshd",
        "/usr/bin/top", "/usr/bin/find", "/usr/bin/passwd",
        "/usr/bin/sudo", "/sbin/ifconfig", "/bin/grep"
    ]

    init(ssh: SSHConnection) {
        self.ssh = ssh
    }

    /// Check binary integrity
    func checkBinaryIntegrity() async -> [BinaryIntegrityFinding] {
        var findings: [BinaryIntegrityFinding] = []

        print("[BinaryIntegrityChecker] Starting binary integrity check...")

        // Detect OS distribution for hash verification
        detectedDistro = await detectDistribution()
        if let distro = detectedDistro {
            print("[BinaryIntegrityChecker] Detected distribution: \(distro)")
        } else {
            print("[BinaryIntegrityChecker] Could not detect distribution - hash verification will be skipped")
        }

        for binary in criticalBinaries {
            guard await ssh.fileExists(binary) else { continue }

            // Check 1: SHA256 hash verification (NEW!)
            if let suspicious = await checkHashIntegrity(binary) {
                findings.append(suspicious)
            }

            // Check 2: Unusual file size (very small or very large binaries are suspicious)
            if let suspicious = await checkFileSize(binary) {
                findings.append(suspicious)
            }

            // Check 3: Check for suspicious strings
            if let suspicious = await checkSuspiciousStrings(binary) {
                findings.append(suspicious)
            }

            // Check 4: Check modification time (recently modified system binaries)
            if let suspicious = await checkModificationTime(binary) {
                findings.append(suspicious)
            }

            // Check 5: Check permissions (SUID/SGID on unusual binaries)
            if let suspicious = await checkPermissions(binary) {
                findings.append(suspicious)
            }
        }

        print("[BinaryIntegrityChecker] Found \(findings.count) binary integrity issues")
        return findings
    }

    /// Detect Linux distribution
    private func detectDistribution() async -> String? {
        if let osRelease = await ssh.readFile("/etc/os-release") {
            return BinaryHashDatabase.shared.detectDistribution(from: osRelease)
        }
        return nil
    }

    /// Check SHA256 hash integrity (NEW!)
    private func checkHashIntegrity(_ binary: String) async -> BinaryIntegrityFinding? {
        // Only check if we detected the distribution
        guard let distro = detectedDistro else { return nil }

        // Check if we have a known-good hash for this binary
        guard BinaryHashDatabase.shared.hasHashData(for: binary) else { return nil }

        // Get the known-good hash
        guard let expectedHash = BinaryHashDatabase.shared.getKnownGoodHash(for: binary, distro: distro) else {
            // We have hash data for this binary, but not for this specific distro
            return nil
        }

        // Calculate SHA256 hash of the binary on remote system
        if let actualHash = await ssh.execute("sha256sum '\(binary)' 2>/dev/null | awk '{print $1}'") {
            let cleanHash = actualHash.trimmingCharacters(in: .whitespacesAndNewlines)

            if cleanHash != expectedHash {
                var finding = BinaryIntegrityFinding(
                    binaryPath: binary,
                    issue: .hashMismatch
                )
                finding.expectedHash = expectedHash
                finding.actualHash = cleanHash
                print("[BinaryIntegrityChecker] ⚠️ CRITICAL: Hash mismatch for \(binary)")
                print("  Expected: \(expectedHash)")
                print("  Actual:   \(cleanHash)")
                return finding
            } else {
                print("[BinaryIntegrityChecker] ✓ Hash verified: \(binary)")
            }
        }

        return nil
    }

    /// Check if file size is unusual
    private func checkFileSize(_ binary: String) async -> BinaryIntegrityFinding? {
        if let statOutput = await ssh.execute("stat -c '%s' \(binary) 2>/dev/null || stat -f '%z' \(binary) 2>/dev/null") {
            if let size = Int(statOutput.trimmingCharacters(in: .whitespacesAndNewlines)) {
                // Very small binaries (< 1KB) are suspicious for system utilities
                if size < 1024 {
                    var finding = BinaryIntegrityFinding(
                        binaryPath: binary,
                        issue: .trojanized
                    )
                    print("[BinaryIntegrityChecker] ⚠️ Suspicious file size: \(binary) (\(size) bytes)")
                    return finding
                }
            }
        }
        return nil
    }

    /// Check for suspicious strings in binary
    private func checkSuspiciousStrings(_ binary: String) async -> BinaryIntegrityFinding? {
        let suspiciousKeywords = ["backdoor", "rootkit", "hide", "sniff", "keylog", "password_capture"]

        if let stringsOutput = await ssh.execute("strings \(binary) 2>/dev/null | grep -iE '(backdoor|rootkit|hide|sniff|keylog)' | head -5") {
            if !stringsOutput.isEmpty {
                var finding = BinaryIntegrityFinding(
                    binaryPath: binary,
                    issue: .trojanized
                )
                print("[BinaryIntegrityChecker] ⚠️ CRITICAL: Trojanized binary: \(binary) contains suspicious strings")
                return finding
            }
        }
        return nil
    }

    /// Check if binary was recently modified
    private func checkModificationTime(_ binary: String) async -> BinaryIntegrityFinding? {
        // Get modification time
        if let statOutput = await ssh.execute("stat -c '%Y' \(binary) 2>/dev/null || stat -f '%m' \(binary) 2>/dev/null") {
            if let modTime = TimeInterval(statOutput.trimmingCharacters(in: .whitespacesAndNewlines)) {
                let modDate = Date(timeIntervalSince1970: modTime)
                let daysSinceModification = Date().timeIntervalSince(modDate) / 86400

                // System binaries modified in the last 30 days are suspicious
                // (unless there was a system update)
                if daysSinceModification < 30 {
                    // Check if there was a recent system update
                    let wasRecentUpdate = await checkRecentSystemUpdate()
                    if !wasRecentUpdate {
                        var finding = BinaryIntegrityFinding(
                            binaryPath: binary,
                            issue: .modifiedTimestamp
                        )
                        print("[BinaryIntegrityChecker] ⚠️ Recently modified binary: \(binary) (modified \(Int(daysSinceModification)) days ago)")
                        return finding
                    }
                }
            }
        }
        return nil
    }

    /// Check file permissions
    private func checkPermissions(_ binary: String) async -> BinaryIntegrityFinding? {
        if let statOutput = await ssh.execute("stat -c '%a' \(binary) 2>/dev/null || stat -f '%Lp' \(binary) 2>/dev/null") {
            let perms = statOutput.trimmingCharacters(in: .whitespacesAndNewlines)

            // Check for world-writable binaries (suspicious)
            if perms.hasSuffix("6") || perms.hasSuffix("7") {
                var finding = BinaryIntegrityFinding(
                    binaryPath: binary,
                    issue: .suspiciousPermissions
                )
                print("[BinaryIntegrityChecker] ⚠️ World-writable system binary: \(binary) (permissions: \(perms))")
                return finding
            }

            // Check for SUID/SGID on unusual binaries
            if perms.hasPrefix("4") || perms.hasPrefix("2") {
                // SUID/SGID is normal for some binaries but suspicious for others
                let normalSuidBinaries = ["/bin/su", "/usr/bin/sudo", "/usr/bin/passwd", "/bin/login"]
                if !normalSuidBinaries.contains(binary) {
                    var finding = BinaryIntegrityFinding(
                        binaryPath: binary,
                        issue: .suspiciousPermissions
                    )
                    print("[BinaryIntegrityChecker] ⚠️ Unusual SUID/SGID binary: \(binary) (permissions: \(perms))")
                    return finding
                }
            }
        }
        return nil
    }

    /// Check if there was a recent system update
    private func checkRecentSystemUpdate() async -> Bool {
        // Check apt/yum/dnf logs for recent updates
        if let aptLog = await ssh.execute("grep -i 'install\\|upgrade' /var/log/apt/history.log 2>/dev/null | tail -5") {
            if !aptLog.isEmpty {
                return true
            }
        }

        if let yumLog = await ssh.execute("grep -i 'Updated\\|Installed' /var/log/yum.log 2>/dev/null | tail -5") {
            if !yumLog.isEmpty {
                return true
            }
        }

        return false
    }
}
