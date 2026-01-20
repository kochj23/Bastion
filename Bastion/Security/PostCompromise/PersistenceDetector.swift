//
//  PersistenceDetector.swift
//  Bastion
//
//  Detects persistence mechanisms used by attackers
//  Author: Jordan Koch
//  Date: 2025-01-20
//

import Foundation

class PersistenceDetector {
    private let ssh: SSHConnection

    init(ssh: SSHConnection) {
        self.ssh = ssh
    }

    /// Scan for persistence mechanisms
    func scanForPersistence() async -> [PersistenceFinding] {
        var findings: [PersistenceFinding] = []

        print("[PersistenceDetector] Starting persistence scan...")

        // Check all common persistence locations
        findings.append(contentsOf: await checkCronJobs())
        findings.append(contentsOf: await checkSystemdServices())
        findings.append(contentsOf: await checkInitScripts())
        findings.append(contentsOf: await checkBashProfile())
        findings.append(contentsOf: await checkSSHKeys())
        findings.append(contentsOf: await checkAtJobs())

        print("[PersistenceDetector] Found \(findings.count) persistence mechanisms")
        return findings
    }

    /// Check cron jobs for suspicious entries
    private func checkCronJobs() async -> [PersistenceFinding] {
        var findings: [PersistenceFinding] = []

        // Check system crontabs
        let cronDirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]
        for dir in cronDirs {
            if let files = await ssh.execute("ls -la \(dir) 2>/dev/null") {
                let lines = files.components(separatedBy: "\n")
                for line in lines {
                    // Look for recently modified files
                    let parts = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                    if parts.count >= 9 {
                        let filename = parts[8]
                        if !filename.hasPrefix(".") && filename != "." && filename != ".." {
                            if let content = await ssh.readFile("\(dir)/\(filename)") {
                                if isSuspiciousCronContent(content) {
                                    var finding = PersistenceFinding(
                                        mechanism: .cron,
                                        location: "\(dir)/\(filename)",
                                        description: "Suspicious cron job detected"
                                    )
                                    finding.content = content
                                    findings.append(finding)
                                    print("[PersistenceDetector] ⚠️ Suspicious cron: \(dir)/\(filename)")
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check user crontabs
        if let crontabList = await ssh.execute("crontab -l 2>/dev/null") {
            if !crontabList.isEmpty && isSuspiciousCronContent(crontabList) {
                var finding = PersistenceFinding(
                    mechanism: .cron,
                    location: "User crontab",
                    description: "Suspicious user crontab entry"
                )
                finding.content = crontabList
                findings.append(finding)
                print("[PersistenceDetector] ⚠️ Suspicious user crontab")
            }
        }

        return findings
    }

    /// Check if cron content is suspicious
    private func isSuspiciousCronContent(_ content: String) -> Bool {
        let suspicious = [
            "curl", "wget", "nc ", "netcat", "/dev/tcp",
            "base64", "python -c", "perl -e", "bash -i",
            "/tmp/", "chmod +x", ".sh", "reverse"
        ]
        return suspicious.contains { content.contains($0) }
    }

    /// Check systemd services and timers
    private func checkSystemdServices() async -> [PersistenceFinding] {
        var findings: [PersistenceFinding] = []

        let systemdDirs = ["/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"]
        for dir in systemdDirs {
            if let services = await ssh.execute("find \(dir) -name '*.service' -o -name '*.timer' 2>/dev/null") {
                let files = services.components(separatedBy: "\n")
                for file in files {
                    if !file.isEmpty {
                        if let content = await ssh.readFile(file) {
                            if isSuspiciousServiceContent(content) {
                                var finding = PersistenceFinding(
                                    mechanism: .systemd,
                                    location: file,
                                    description: "Suspicious systemd service/timer"
                                )
                                finding.content = content
                                findings.append(finding)
                                print("[PersistenceDetector] ⚠️ Suspicious systemd service: \(file)")
                            }
                        }
                    }
                }
            }
        }

        return findings
    }

    /// Check if systemd service content is suspicious
    private func isSuspiciousServiceContent(_ content: String) -> Bool {
        let suspicious = [
            "curl", "wget", "nc ", "netcat", "/dev/tcp",
            "/tmp/", "bash -c", "sh -c", "ExecStart=/tmp",
            "python -c", "perl -e"
        ]
        return suspicious.contains { content.contains($0) }
    }

    /// Check init scripts
    private func checkInitScripts() async -> [PersistenceFinding] {
        var findings: [PersistenceFinding] = []

        let initDirs = ["/etc/init.d", "/etc/rc.d", "/etc/rc.local"]
        for location in initDirs {
            if await ssh.fileExists(location) {
                if let content = await ssh.readFile(location) {
                    if isSuspiciousScriptContent(content) {
                        var finding = PersistenceFinding(
                            mechanism: .initScript,
                            location: location,
                            description: "Suspicious init script"
                        )
                        finding.content = content
                        findings.append(finding)
                        print("[PersistenceDetector] ⚠️ Suspicious init script: \(location)")
                    }
                }
            }
        }

        return findings
    }

    /// Check bash profile and rc files
    private func checkBashProfile() async -> [PersistenceFinding] {
        var findings: [PersistenceFinding] = []

        let profileFiles = [
            "/root/.bashrc", "/root/.bash_profile", "/root/.profile",
            "/home/*/.bashrc", "/home/*/.bash_profile", "/home/*/.profile",
            "/etc/bash.bashrc", "/etc/profile"
        ]

        for pattern in profileFiles {
            if let files = await ssh.execute("ls \(pattern) 2>/dev/null") {
                let fileList = files.components(separatedBy: "\n")
                for file in fileList {
                    if !file.isEmpty {
                        if let content = await ssh.readFile(file) {
                            if isSuspiciousScriptContent(content) {
                                var finding = PersistenceFinding(
                                    mechanism: .bashProfile,
                                    location: file,
                                    description: "Suspicious bash profile modification"
                                )
                                finding.content = content
                                findings.append(finding)
                                print("[PersistenceDetector] ⚠️ Suspicious bash profile: \(file)")
                            }
                        }
                    }
                }
            }
        }

        return findings
    }

    /// Check if script content is suspicious
    private func isSuspiciousScriptContent(_ content: String) -> Bool {
        let suspicious = [
            "curl", "wget", "nc ", "netcat", "/dev/tcp",
            "python -c", "perl -e", "base64", "bash -i",
            "reverse", "backdoor", "/tmp/", "chmod +x .sh"
        ]
        return suspicious.contains { content.contains($0) }
    }

    /// Check SSH authorized_keys for suspicious entries
    private func checkSSHKeys() async -> [PersistenceFinding] {
        var findings: [PersistenceFinding] = []

        let sshKeyPaths = [
            "/root/.ssh/authorized_keys",
            "/home/*/.ssh/authorized_keys"
        ]

        for pattern in sshKeyPaths {
            if let files = await ssh.execute("ls \(pattern) 2>/dev/null") {
                let fileList = files.components(separatedBy: "\n")
                for file in fileList {
                    if !file.isEmpty {
                        if let content = await ssh.readFile(file) {
                            let lines = content.components(separatedBy: "\n")
                            for line in lines {
                                // Check for keys with suspicious options
                                if line.contains("command=") || line.contains("PermitOpen") {
                                    var finding = PersistenceFinding(
                                        mechanism: .sshKey,
                                        location: file,
                                        description: "SSH key with forced command (potential backdoor)"
                                    )
                                    finding.content = line
                                    findings.append(finding)
                                    print("[PersistenceDetector] ⚠️ Suspicious SSH key: \(file)")
                                }
                            }
                        }
                    }
                }
            }
        }

        return findings
    }

    /// Check at jobs
    private func checkAtJobs() async -> [PersistenceFinding] {
        var findings: [PersistenceFinding] = []

        if let atJobs = await ssh.execute("atq 2>/dev/null") {
            if !atJobs.isEmpty {
                let lines = atJobs.components(separatedBy: "\n")
                for line in lines {
                    if !line.isEmpty {
                        let parts = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                        if parts.count >= 1 {
                            let jobId = parts[0]
                            // Read the at job content
                            if let jobContent = await ssh.execute("at -c \(jobId) 2>/dev/null") {
                                if isSuspiciousScriptContent(jobContent) {
                                    var finding = PersistenceFinding(
                                        mechanism: .cron,
                                        location: "at job \(jobId)",
                                        description: "Suspicious at job"
                                    )
                                    finding.content = jobContent
                                    findings.append(finding)
                                    print("[PersistenceDetector] ⚠️ Suspicious at job: \(jobId)")
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
