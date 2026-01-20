//
//  KernelModuleAnalyzer.swift
//  Bastion
//
//  Analyzes kernel modules for rootkits (LKM rootkits)
//  Author: Jordan Koch
//  Date: 2025-01-20
//

import Foundation

class KernelModuleAnalyzer {
    private let ssh: SSHConnection

    // Known malicious kernel modules
    private let knownRootkitModules = [
        "diamorphine", "reptile", "adore", "enye", "heroin", "fu",
        "zk", "ark", "superkit", "knark", "itf", "taskigt",
        "synaptics_i2c", // Fake touchpad driver used by rootkits
        "vmware_vmci", // Sometimes faked
        "vboxguest" // Sometimes faked
    ]

    init(ssh: SSHConnection) {
        self.ssh = ssh
    }

    /// Scan for suspicious kernel modules
    func scanKernelModules() async -> [KernelModuleFinding] {
        var findings: [KernelModuleFinding] = []

        print("[KernelModuleAnalyzer] Starting kernel module analysis...")

        // Get loaded kernel modules
        guard let lsmodOutput = await ssh.execute("lsmod") else {
            print("[KernelModuleAnalyzer] Failed to get kernel modules")
            return findings
        }

        let lines = lsmodOutput.components(separatedBy: "\n").dropFirst() // Skip header
        for line in lines {
            let parts = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
            guard parts.count >= 3 else { continue }

            let moduleName = parts[0]
            var suspicionReasons: [String] = []

            // Check 1: Known rootkit module name
            if knownRootkitModules.contains(moduleName.lowercased()) {
                suspicionReasons.append("Known rootkit module name: \(moduleName)")
            }

            // Check 2: Hidden module (module loaded but no file in /lib/modules)
            if let modulePath = await findModulePath(moduleName) {
                if modulePath.isEmpty {
                    suspicionReasons.append("Module loaded but no source file found (hidden module)")
                }
            }

            // Check 3: Unsigned module (on systems requiring signed modules)
            if await isModuleUnsigned(moduleName) {
                suspicionReasons.append("Kernel module is not signed")
            }

            // Check 4: Module with suspicious strings
            if await moduleHasSuspiciousStrings(moduleName) {
                suspicionReasons.append("Module contains suspicious strings (hide/rootkit/backdoor)")
            }

            if !suspicionReasons.isEmpty {
                let finding = KernelModuleFinding(
                    moduleName: moduleName,
                    suspicionReasons: suspicionReasons,
                    isLoaded: true
                )
                findings.append(finding)
                print("[KernelModuleAnalyzer] ⚠️ Suspicious kernel module: \(moduleName) - \(suspicionReasons.joined(separator: ", "))")
            }
        }

        // Check for discrepancies between lsmod and /proc/modules
        findings.append(contentsOf: await checkModuleDiscrepancies())

        // Check for kernel hooks (ftrace, kprobes abuse)
        findings.append(contentsOf: await checkKernelHooks())

        print("[KernelModuleAnalyzer] Found \(findings.count) suspicious kernel modules")
        return findings
    }

    /// Find kernel module file path
    private func findModulePath(_ moduleName: String) async -> String? {
        if let findOutput = await ssh.execute("find /lib/modules/$(uname -r) -name '\(moduleName).ko*' 2>/dev/null") {
            return findOutput.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return nil
    }

    /// Check if module is unsigned
    private func isModuleUnsigned(_ moduleName: String) async -> Bool {
        if let modinfo = await ssh.execute("modinfo \(moduleName) 2>/dev/null | grep -i 'sig_'") {
            // If sig_id or sig_key is missing, module is unsigned
            return modinfo.isEmpty
        }
        return false
    }

    /// Check if module contains suspicious strings
    private func moduleHasSuspiciousStrings(_ moduleName: String) async -> Bool {
        if let modulePath = await findModulePath(moduleName), !modulePath.isEmpty {
            if let strings = await ssh.execute("strings \(modulePath) 2>/dev/null | grep -iE '(hide|rootkit|backdoor|keylog|sniff)' | head -1") {
                return !strings.isEmpty
            }
        }
        return false
    }

    /// Check for discrepancies between lsmod and /proc/modules
    private func checkModuleDiscrepancies() async -> [KernelModuleFinding] {
        var findings: [KernelModuleFinding] = []

        // Get modules from lsmod
        guard let lsmodOutput = await ssh.execute("lsmod | tail -n +2 | awk '{print $1}'") else {
            return findings
        }
        let lsmodModules = Set(lsmodOutput.components(separatedBy: "\n").filter { !$0.isEmpty })

        // Get modules from /proc/modules
        guard let procOutput = await ssh.readFile("/proc/modules") else {
            return findings
        }
        let procModules = Set(procOutput.components(separatedBy: "\n")
            .filter { !$0.isEmpty }
            .compactMap { $0.components(separatedBy: " ").first })

        // Find discrepancies
        let hiddenFromLsmod = procModules.subtracting(lsmodModules)
        for module in hiddenFromLsmod {
            let finding = KernelModuleFinding(
                moduleName: module,
                suspicionReasons: ["Module in /proc/modules but not visible in lsmod (rootkit hiding)"],
                isLoaded: true
            )
            findings.append(finding)
            print("[KernelModuleAnalyzer] ⚠️ CRITICAL: Hidden kernel module: \(module)")
        }

        return findings
    }

    /// Check for kernel function hooks (common rootkit technique)
    private func checkKernelHooks() async -> [KernelModuleFinding] {
        var findings: [KernelModuleFinding] = []

        // Check for active kprobes (can be abused by rootkits)
        if let kprobes = await ssh.readFile("/sys/kernel/debug/kprobes/list") {
            if !kprobes.isEmpty {
                let lines = kprobes.components(separatedBy: "\n")
                if lines.count > 10 { // Many kprobes can be suspicious
                    let finding = KernelModuleFinding(
                        moduleName: "kprobes",
                        suspicionReasons: ["Unusual number of kprobes active (\(lines.count)) - potential rootkit"],
                        isLoaded: true
                    )
                    findings.append(finding)
                    print("[KernelModuleAnalyzer] ⚠️ High number of kprobes: \(lines.count)")
                }
            }
        }

        // Check for ftrace hooks
        if let ftrace = await ssh.readFile("/sys/kernel/debug/tracing/enabled_functions") {
            if !ftrace.isEmpty {
                let lines = ftrace.components(separatedBy: "\n")
                if lines.count > 20 {
                    let finding = KernelModuleFinding(
                        moduleName: "ftrace",
                        suspicionReasons: ["Unusual number of ftrace hooks (\(lines.count)) - potential rootkit"],
                        isLoaded: true
                    )
                    findings.append(finding)
                    print("[KernelModuleAnalyzer] ⚠️ High number of ftrace hooks: \(lines.count)")
                }
            }
        }

        return findings
    }
}
