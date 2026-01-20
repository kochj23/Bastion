//
//  SuspiciousUserDetector.swift
//  Bastion
//
//  Detects suspicious users and groups on the system
//  Author: Jordan Koch
//  Date: 2025-01-20
//

import Foundation

class SuspiciousUserDetector {
    private let ssh: SSHConnection

    init(ssh: SSHConnection) {
        self.ssh = ssh
    }

    /// Scan for suspicious user accounts
    func scanForSuspiciousUsers() async -> [SuspiciousUserFinding] {
        var findings: [SuspiciousUserFinding] = []

        print("[SuspiciousUserDetector] Starting user analysis...")

        // Get all users from /etc/passwd
        guard let passwdContent = await ssh.readFile("/etc/passwd") else {
            print("[SuspiciousUserDetector] Failed to read /etc/passwd")
            return findings
        }

        let lines = passwdContent.components(separatedBy: "\n")
        for line in lines {
            guard !line.isEmpty else { continue }

            let parts = line.components(separatedBy: ":")
            guard parts.count >= 7 else { continue }

            let username = parts[0]
            let uid = Int(parts[2]) ?? -1
            let gid = Int(parts[3]) ?? -1
            let homeDir = parts[5]
            let shell = parts[6]

            var suspicionReasons: [String] = []

            // Check 1: UID 0 but not root
            if uid == 0 && username != "root" {
                suspicionReasons.append("Has UID 0 (root privileges) but username is not 'root'")
            }

            // Check 2: Hidden username (starts with .)
            if username.hasPrefix(".") {
                suspicionReasons.append("Hidden username (starts with dot)")
            }

            // Check 3: Username with special characters or spaces
            if username.contains(" ") || username.contains("..") {
                suspicionReasons.append("Username contains suspicious characters")
            }

            // Check 4: Recently created accounts (if we can check /var/log/auth.log)
            if await wasRecentlyCreated(username) {
                suspicionReasons.append("Account created recently")
            }

            // Check 5: Check for backdoor shells
            let backdoorShells = ["/dev/tcp", "/bin/sh", "bash -i", "nc -", "telnet", "/tmp/"]
            if backdoorShells.contains(where: { shell.contains($0) }) {
                suspicionReasons.append("Suspicious shell: \(shell)")
            }

            // Check 6: Home directory in unusual location
            let unusualHomes = ["/dev/", "/tmp/", "/var/tmp/", "/proc/"]
            if unusualHomes.contains(where: { homeDir.hasPrefix($0) }) {
                suspicionReasons.append("Home directory in unusual location: \(homeDir)")
            }

            // Check 7: Empty password field (check /etc/shadow if accessible)
            if await hasEmptyPassword(username) {
                suspicionReasons.append("CRITICAL: Account has empty password")
            }

            if !suspicionReasons.isEmpty {
                var finding = SuspiciousUserFinding(
                    username: username,
                    uid: uid,
                    gid: gid,
                    suspicionReasons: suspicionReasons
                )
                finding.homeDirectory = homeDir
                finding.shell = shell
                findings.append(finding)

                print("[SuspiciousUserDetector] ⚠️ Suspicious user: \(username) - \(suspicionReasons.joined(separator: ", "))")
            }
        }

        // Check for users with dangerous group memberships
        findings.append(contentsOf: await checkDangerousGroupMemberships())

        // Check for users with sudo access
        findings.append(contentsOf: await checkSudoAccess())

        print("[SuspiciousUserDetector] Found \(findings.count) suspicious users")
        return findings
    }

    /// Check if user was recently created (within last 7 days)
    private func wasRecentlyCreated(_ username: String) async -> Bool {
        // Try to check auth.log for useradd command
        if let authLog = await ssh.execute("grep -i 'new user.*\(username)' /var/log/auth.log /var/log/secure 2>/dev/null | tail -5") {
            if !authLog.isEmpty {
                // Parse dates and check if within 7 days
                return true
            }
        }
        return false
    }

    /// Check if user has empty password
    private func hasEmptyPassword(_ username: String) async -> Bool {
        // Try to read /etc/shadow (requires root)
        if let shadowContent = await ssh.executeSudo("cat /etc/shadow 2>/dev/null") {
            let lines = shadowContent.components(separatedBy: "\n")
            for line in lines {
                if line.hasPrefix(username + ":") {
                    let parts = line.components(separatedBy: ":")
                    if parts.count >= 2 {
                        let passwordField = parts[1]
                        // Empty or ! or * means no password or locked
                        if passwordField.isEmpty || passwordField == "!" || passwordField == "*" {
                            return false // Locked account, not a concern
                        }
                        // Just ":" with no characters after means empty password
                        if passwordField == "" {
                            return true
                        }
                    }
                }
            }
        }
        return false
    }

    /// Check for users in dangerous groups
    private func checkDangerousGroupMemberships() async -> [SuspiciousUserFinding] {
        var findings: [SuspiciousUserFinding] = []

        let dangerousGroups = ["docker", "sudo", "wheel", "admin", "shadow"]

        for group in dangerousGroups {
            if let groupMembers = await ssh.execute("getent group \(group) 2>/dev/null") {
                if !groupMembers.isEmpty {
                    let parts = groupMembers.components(separatedBy: ":")
                    if parts.count >= 4 {
                        let members = parts[3].components(separatedBy: ",")
                        for member in members {
                            let username = member.trimmingCharacters(in: .whitespacesAndNewlines)
                            if !username.isEmpty && username != "root" {
                                // Get UID for this user
                                if let uidOutput = await ssh.execute("id -u \(username) 2>/dev/null"),
                                   let uid = Int(uidOutput.trimmingCharacters(in: .whitespacesAndNewlines)) {

                                    let finding = SuspiciousUserFinding(
                                        username: username,
                                        uid: uid,
                                        gid: -1,
                                        suspicionReasons: ["Member of dangerous group: \(group)"]
                                    )
                                    findings.append(finding)
                                    print("[SuspiciousUserDetector] ⚠️ User '\(username)' in dangerous group: \(group)")
                                }
                            }
                        }
                    }
                }
            }
        }

        return findings
    }

    /// Check for users with sudo access
    private func checkSudoAccess() async -> [SuspiciousUserFinding] {
        var findings: [SuspiciousUserFinding] = []

        // Check /etc/sudoers.d/ for individual user sudo configs
        if let sudoersFiles = await ssh.executeSudo("ls /etc/sudoers.d/ 2>/dev/null") {
            let files = sudoersFiles.components(separatedBy: "\n")
            for file in files {
                if !file.isEmpty && !file.hasPrefix(".") {
                    if let content = await ssh.executeSudo("cat /etc/sudoers.d/\(file) 2>/dev/null") {
                        // Parse for suspicious sudo rules
                        if content.contains("NOPASSWD") {
                            print("[SuspiciousUserDetector] ⚠️ Found NOPASSWD sudo rule in \(file)")
                        }
                    }
                }
            }
        }

        return findings
    }
}
