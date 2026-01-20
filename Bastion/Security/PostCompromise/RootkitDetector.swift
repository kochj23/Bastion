//
//  RootkitDetector.swift
//  Bastion
//
//  Rootkit detection based on chkrootkit and rkhunter signatures
//  Author: Jordan Koch
//  Date: 2025-01-20
//

import Foundation

class RootkitDetector {
    private let ssh: SSHConnection

    // Database of known rootkit signatures (from chkrootkit, rkhunter, etc.)
    private let rootkitSignatures: [RootkitSignature] = [
        // User-space rootkits
        RootkitSignature(name: "55808 Trojan", type: .userland, files: ["/dev/ttya", "/dev/ttyb", "/dev/ptyp", "/dev/ptyq"]),
        RootkitSignature(name: "Adore", type: .kernel, files: ["/dev/.shit"], processes: ["adore"]),
        RootkitSignature(name: "Adore LKM", type: .kernel, files: ["/usr/lib/lib_h.a", "/usr/lib/lib_h.so"], kernelModules: ["adore"]),
        RootkitSignature(name: "Apache Worm", type: .userland, files: ["/usr/bin/mail", "/tmp/.unlock", "/usr/man/.socket"]),
        RootkitSignature(name: "ARK", type: .kernel, files: ["/dev/.ark"], kernelModules: ["ark"]),
        RootkitSignature(name: "Beastkit", type: .userland, files: ["/usr/include/rpm/.../lib", "/usr/lib/locale/.../LC_TIME"]),
        RootkitSignature(name: "cb Rootkit", type: .userland, files: ["/dev/ptyp", "/dev/ptyq"]),
        RootkitSignature(name: "Diamorphine", type: .kernel, kernelModules: ["diamorphine"]),
        RootkitSignature(name: "Enye LKM", type: .kernel, files: ["/etc/rc.d/rc.sysinit"], kernelModules: ["enye"]),
        RootkitSignature(name: "FU Rootkit", type: .kernel, kernelModules: ["fu"]),
        RootkitSignature(name: "Flea Linux", type: .userland, files: ["/usr/bin/linux.bin"]),
        RootkitSignature(name: "Heroin LKM", type: .kernel, kernelModules: ["heroin"]),
        RootkitSignature(name: "Hidrootkit", type: .userland, files: ["/tmp/.../."]),
        RootkitSignature(name: "Showtee", type: .userland, files: ["/usr/bin/.sh"]),
        RootkitSignature(name: "Suckit", type: .kernel, files: ["/sbin/init", "/dev/.SucKIT"], processes: ["suckit"]),
        RootkitSignature(name: "T0rn", type: .userland, files: ["/usr/src/.puta", "/usr/info/libt0rn.so"]),
        RootkitSignature(name: "Volc Rootkit", type: .userland, files: ["/usr/bin/volc"]),
        RootkitSignature(name: "ZK Rootkit", type: .kernel, kernelModules: ["zk"]),
        RootkitSignature(name: "Reptile", type: .kernel, kernelModules: ["reptile"]),
        RootkitSignature(name: "Jynx", type: .userland, files: ["/usr/bin/jynx", "/usr/lib/jynx.so"]),
        RootkitSignature(name: "Linux Rootkit 5", type: .userland, files: ["/usr/bin/lrk5", "/dev/ida/host*"]),
        RootkitSignature(name: "Mood-NT", type: .userland, files: ["/usr/bin/mood-nt"]),
        RootkitSignature(name: "Optickit", type: .userland, files: ["/usr/bin/ovas"]),
        RootkitSignature(name: "RH-Sharpe", type: .userland, files: ["/bin/." + String(repeating: " ", count: 10), "/usr/bin/rpc.istatd"]),
        RootkitSignature(name: "Ramen Worm", type: .userland, files: ["/usr/src/.poop", "/tmp/ramen.tgz"]),
        RootkitSignature(name: "Scalper", type: .userland, files: ["/tmp/.../."]),
        RootkitSignature(name: "Slapper", type: .userland, files: ["/tmp/.unlock", "/tmp/.unlock/.b"]),
        RootkitSignature(name: "TBD", type: .userland, files: ["/dev/xmx", "/dev/ida/.inet"]),
        RootkitSignature(name: "Trojanit", type: .userland, files: ["/dev/xmx", "/sbin/xdev"]),
        RootkitSignature(name: "Zombie Trojan", type: .userland, files: ["/usr/bin/zu"]),
        RootkitSignature(name: "x.c Worm", type: .userland, files: ["/tmp/.w0rm"]),
        RootkitSignature(name: "Zabian", type: .userland, files: ["/tmp/zabian"]),
        RootkitSignature(name: "ChinaZ Backdoor", type: .userland, files: ["/etc/hosts", "/etc/named.conf"], patterns: ["www.chinaz.com"]),

        // Common backdoors
        RootkitSignature(name: "Backdoor.Linux.Mokes", type: .userland, files: ["/tmp/ss", "/tmp/ssw"]),
        RootkitSignature(name: "Mirai Botnet", type: .userland, files: ["/etc/cron.hourly/gcc.sh"], processes: ["mirai"]),
        RootkitSignature(name: "XOR.DDoS", type: .userland, files: ["/usr/bin/bb", "/bin/bb"], processes: ["bb"]),
        RootkitSignature(name: "Linux/Ebury", type: .userland, files: ["/usr/sbin/sshd"], patterns: ["libkeyutils.so.1"]),

        // Cryptocurrency miners (often used as rootkits)
        RootkitSignature(name: "XMRig Miner", type: .userland, processes: ["xmrig", "xmr-stak", "minerd"]),
        RootkitSignature(name: "Cryptominer", type: .userland, files: ["/tmp/kdevtmpfsi", "/tmp/kinsing"]),
    ]

    init(ssh: SSHConnection) {
        self.ssh = ssh
    }

    /// Scan for known rootkits
    func scanForRootkits() async -> [RootkitFinding] {
        var findings: [RootkitFinding] = []

        print("[RootkitDetector] Starting rootkit scan...")

        // Check each rootkit signature
        for signature in rootkitSignatures {
            var detected = false
            var detectedFiles: [String] = []
            var detectedProcesses: [String] = []

            // Check for file signatures
            for file in signature.files {
                if await ssh.fileExists(file) {
                    detected = true
                    detectedFiles.append(file)
                    print("[RootkitDetector] ⚠️ Found rootkit file: \(file) (signature: \(signature.name))")
                }
            }

            // Check for running processes
            for process in signature.processes {
                if let psOutput = await ssh.execute("ps aux | grep -v grep | grep '\(process)'") {
                    if !psOutput.isEmpty {
                        detected = true
                        detectedProcesses.append(process)
                        print("[RootkitDetector] ⚠️ Found rootkit process: \(process) (signature: \(signature.name))")
                    }
                }
            }

            // Check for loaded kernel modules
            for module in signature.kernelModules {
                if let lsmodOutput = await ssh.execute("lsmod | grep '\(module)'") {
                    if !lsmodOutput.isEmpty {
                        detected = true
                        detectedProcesses.append("Kernel module: \(module)")
                        print("[RootkitDetector] ⚠️ Found rootkit kernel module: \(module) (signature: \(signature.name))")
                    }
                }
            }

            // Check for pattern matches
            for pattern in signature.patterns {
                for file in signature.files {
                    if let content = await ssh.readFile(file) {
                        if content.contains(pattern) {
                            detected = true
                            detectedFiles.append("\(file) (contains: \(pattern))")
                            print("[RootkitDetector] ⚠️ Found rootkit pattern '\(pattern)' in \(file)")
                        }
                    }
                }
            }

            if detected {
                var finding = RootkitFinding(
                    name: signature.name,
                    type: signature.type,
                    detectionMethod: "Signature-based detection"
                )
                finding.files = detectedFiles
                finding.processes = detectedProcesses
                findings.append(finding)
            }
        }

        // Additional heuristic checks
        findings.append(contentsOf: await checkForHiddenDirectories())
        findings.append(contentsOf: await checkForSuspiciousStrings())

        print("[RootkitDetector] Scan complete. Found \(findings.count) potential rootkits.")
        return findings
    }

    /// Check for hidden directories (common rootkit hiding technique)
    private func checkForHiddenDirectories() async -> [RootkitFinding] {
        var findings: [RootkitFinding] = []

        let suspiciousPaths = [
            "/dev/shm/.ICE-unix",
            "/dev/.udev",
            "/dev/.static",
            "/dev/.SysV",
            "/tmp/.X11-unix",
            "/tmp/.font-unix",
            "/usr/share/locale/...",
            "/var/tmp/.ICE-unix"
        ]

        for path in suspiciousPaths {
            if await ssh.fileExists(path) {
                // Check if it contains executables
                if let lsOutput = await ssh.execute("find \(path) -type f -executable 2>/dev/null") {
                    if !lsOutput.isEmpty {
                        var finding = RootkitFinding(
                            name: "Hidden Directory with Executables",
                            type: .userland,
                            detectionMethod: "Heuristic analysis"
                        )
                        finding.files = [path]
                        findings.append(finding)
                        print("[RootkitDetector] ⚠️ Found suspicious hidden directory: \(path)")
                    }
                }
            }
        }

        return findings
    }

    /// Check binaries for suspicious strings (backdoor indicators)
    private func checkForSuspiciousStrings() async -> [RootkitFinding] {
        var findings: [RootkitFinding] = []

        // Check sshd for backdoor strings
        if let strings = await ssh.execute("strings /usr/sbin/sshd 2>/dev/null | grep -E '(backdoor|rootkit|hide|sniff|keylog)'") {
            if !strings.isEmpty {
                var finding = RootkitFinding(
                    name: "Trojanized SSHD Binary",
                    type: .userland,
                    detectionMethod: "String analysis"
                )
                finding.files = ["/usr/sbin/sshd"]
                findings.append(finding)
                print("[RootkitDetector] ⚠️ CRITICAL: sshd binary contains suspicious strings")
            }
        }

        return findings
    }
}

// MARK: - Rootkit Signature Database

private struct RootkitSignature {
    let name: String
    let type: RootkitType
    var files: [String] = []
    var processes: [String] = []
    var kernelModules: [String] = []
    var patterns: [String] = [] // String patterns to search for
}
