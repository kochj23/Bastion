//
//  PostCompromiseModule.swift
//  Bastion
//
//  Main post-compromise assessment module
//  Orchestrates all detection modules and generates comprehensive report
//  Author: Jordan Koch
//  Date: 2025-01-20
//

import Foundation

@MainActor
class PostCompromiseModule: ObservableObject {
    @Published var isScanning = false
    @Published var scanProgress: Double = 0.0
    @Published var currentTask: String = ""
    @Published var report: CompromiseReport?

    /// Run comprehensive post-compromise assessment
    func assessDevice(host: String, username: String, password: String) async -> CompromiseReport {
        isScanning = true
        scanProgress = 0.0
        currentTask = "Establishing SSH connection..."

        // Create SSH connection
        let ssh = SSHConnection(host: host, username: username, password: password)

        // Initialize report
        var report = CompromiseReport(targetIP: host)

        // Run all detection modules
        let totalPhases = 10
        var currentPhase = 0

        // Phase 1: Rootkit Detection
        currentPhase += 1
        scanProgress = Double(currentPhase) / Double(totalPhases)
        currentTask = "Scanning for rootkits..."
        print("\n=== Phase \(currentPhase)/\(totalPhases): Rootkit Detection ===")
        let rootkitDetector = RootkitDetector(ssh: ssh)
        report.rootkits = await rootkitDetector.scanForRootkits()
        addFindingsToReport(&report, from: report.rootkits)

        // Phase 2: Suspicious Users
        currentPhase += 1
        scanProgress = Double(currentPhase) / Double(totalPhases)
        currentTask = "Analyzing user accounts..."
        print("\n=== Phase \(currentPhase)/\(totalPhases): User Analysis ===")
        let userDetector = SuspiciousUserDetector(ssh: ssh)
        report.suspiciousUsers = await userDetector.scanForSuspiciousUsers()
        addFindingsToReport(&report, from: report.suspiciousUsers)

        // Phase 3: Backdoor Detection
        currentPhase += 1
        scanProgress = Double(currentPhase) / Double(totalPhases)
        currentTask = "Scanning for backdoors..."
        print("\n=== Phase \(currentPhase)/\(totalPhases): Backdoor Detection ===")
        let backdoorDetector = BackdoorDetector(ssh: ssh)
        report.backdoors = await backdoorDetector.scanForBackdoors()
        addFindingsToReport(&report, from: report.backdoors)

        // Phase 4: Hidden Processes
        currentPhase += 1
        scanProgress = Double(currentPhase) / Double(totalPhases)
        currentTask = "Detecting hidden processes..."
        print("\n=== Phase \(currentPhase)/\(totalPhases): Hidden Process Detection ===")
        let processDetector = HiddenProcessDetector(ssh: ssh)
        report.hiddenProcesses = await processDetector.scanForHiddenProcesses()
        addFindingsToReport(&report, from: report.hiddenProcesses)

        // Phase 5: Binary Integrity
        currentPhase += 1
        scanProgress = Double(currentPhase) / Double(totalPhases)
        currentTask = "Checking binary integrity..."
        print("\n=== Phase \(currentPhase)/\(totalPhases): Binary Integrity Check ===")
        let binaryChecker = BinaryIntegrityChecker(ssh: ssh)
        report.binaryIntegrityIssues = await binaryChecker.checkBinaryIntegrity()
        addFindingsToReport(&report, from: report.binaryIntegrityIssues)

        // Phase 6: Persistence Mechanisms
        currentPhase += 1
        scanProgress = Double(currentPhase) / Double(totalPhases)
        currentTask = "Searching for persistence mechanisms..."
        print("\n=== Phase \(currentPhase)/\(totalPhases): Persistence Detection ===")
        let persistenceDetector = PersistenceDetector(ssh: ssh)
        report.persistenceMechanisms = await persistenceDetector.scanForPersistence()
        addFindingsToReport(&report, from: report.persistenceMechanisms)

        // Phase 7: Kernel Modules
        currentPhase += 1
        scanProgress = Double(currentPhase) / Double(totalPhases)
        currentTask = "Analyzing kernel modules..."
        print("\n=== Phase \(currentPhase)/\(totalPhases): Kernel Module Analysis ===")
        let kernelAnalyzer = KernelModuleAnalyzer(ssh: ssh)
        report.kernelModuleIssues = await kernelAnalyzer.scanKernelModules()
        addFindingsToReport(&report, from: report.kernelModuleIssues)

        // Phase 8: Log Tampering
        currentPhase += 1
        scanProgress = Double(currentPhase) / Double(totalPhases)
        currentTask = "Checking for log tampering..."
        print("\n=== Phase \(currentPhase)/\(totalPhases): Log Tampering Detection ===")
        let logDetector = LogTamperingDetector(ssh: ssh)
        report.logTamperingIssues = await logDetector.scanForLogTampering()
        addFindingsToReport(&report, from: report.logTamperingIssues)

        // Phase 9: Network Sniffers
        currentPhase += 1
        scanProgress = Double(currentPhase) / Double(totalPhases)
        currentTask = "Detecting network sniffers..."
        print("\n=== Phase \(currentPhase)/\(totalPhases): Network Sniffer Detection ===")
        let snifferDetector = NetworkSnifferDetector(ssh: ssh)
        report.networkSniffers = await snifferDetector.scanForSniffers()
        addFindingsToReport(&report, from: report.networkSniffers)

        // Phase 10: Generate Summary
        currentPhase += 1
        scanProgress = Double(currentPhase) / Double(totalPhases)
        currentTask = "Generating assessment report..."
        print("\n=== Phase \(currentPhase)/\(totalPhases): Report Generation ===")
        report.assessCompromise()
        report.summary = generateSummary(report)
        report.recommendations = generateRecommendations(report)

        // Generate AI-powered analysis (NEW!)
        currentTask = "Generating AI security analysis..."
        print("\n=== AI Analysis Phase ===")
        let aiAnalysis = await AIAttackOrchestrator().analyzeCompromiseReport(report)
        report.summary += "\n\n=== AI SECURITY ANALYSIS ===\n\(aiAnalysis)"

        isScanning = false
        self.report = report

        printSummary(report)

        return report
    }

    // MARK: - Helper Methods

    private func addFindingsToReport(_ report: inout CompromiseReport, from rootkits: [RootkitFinding]) {
        for rootkit in rootkits {
            let finding = CompromiseFinding(
                category: .rootkit,
                severity: .critical,
                title: "Rootkit Detected: \(rootkit.name)",
                description: "\(rootkit.type.rawValue) detected using \(rootkit.detectionMethod)"
            )
            report.findings.append(finding)
        }
    }

    private func addFindingsToReport(_ report: inout CompromiseReport, from users: [SuspiciousUserFinding]) {
        for user in users {
            let severity: VulnerabilitySeverity = user.suspicionReasons.contains { $0.contains("UID 0") || $0.contains("empty password") } ? .critical : .high
            let finding = CompromiseFinding(
                category: .suspiciousUser,
                severity: severity,
                title: "Suspicious User: \(user.username)",
                description: user.suspicionReasons.joined(separator: ", ")
            )
            report.findings.append(finding)
        }
    }

    private func addFindingsToReport(_ report: inout CompromiseReport, from backdoors: [BackdoorFinding]) {
        for backdoor in backdoors {
            let finding = CompromiseFinding(
                category: .backdoor,
                severity: .critical,
                title: "Backdoor Detected: Port \(backdoor.port)",
                description: "\(backdoor.description) - \(backdoor.suspicionReason)"
            )
            report.findings.append(finding)
        }
    }

    private func addFindingsToReport(_ report: inout CompromiseReport, from processes: [HiddenProcessFinding]) {
        for process in processes {
            let finding = CompromiseFinding(
                category: .hiddenProcess,
                severity: .critical,
                title: "Hidden Process: PID \(process.pid)",
                description: "\(process.command) - \(process.hideMethod)"
            )
            report.findings.append(finding)
        }
    }

    private func addFindingsToReport(_ report: inout CompromiseReport, from binaries: [BinaryIntegrityFinding]) {
        for binary in binaries {
            let finding = CompromiseFinding(
                category: .binaryIntegrity,
                severity: .high,
                title: "Binary Integrity Issue: \(binary.binaryPath)",
                description: "\(binary.issue.rawValue)"
            )
            report.findings.append(finding)
        }
    }

    private func addFindingsToReport(_ report: inout CompromiseReport, from persistence: [PersistenceFinding]) {
        for item in persistence {
            let finding = CompromiseFinding(
                category: .persistence,
                severity: .high,
                title: "Persistence Mechanism: \(item.mechanism.rawValue)",
                description: "\(item.description) at \(item.location)"
            )
            report.findings.append(finding)
        }
    }

    private func addFindingsToReport(_ report: inout CompromiseReport, from modules: [KernelModuleFinding]) {
        for module in modules {
            let finding = CompromiseFinding(
                category: .kernelModule,
                severity: .critical,
                title: "Suspicious Kernel Module: \(module.moduleName)",
                description: module.suspicionReasons.joined(separator: ", ")
            )
            report.findings.append(finding)
        }
    }

    private func addFindingsToReport(_ report: inout CompromiseReport, from logs: [LogTamperingFinding]) {
        for log in logs {
            let finding = CompromiseFinding(
                category: .logTampering,
                severity: .high,
                title: "Log Tampering: \(log.logFile)",
                description: "\(log.tamperingType.rawValue) - \(log.description)"
            )
            report.findings.append(finding)
        }
    }

    private func addFindingsToReport(_ report: inout CompromiseReport, from sniffers: [NetworkSnifferFinding]) {
        for sniffer in sniffers {
            let finding = CompromiseFinding(
                category: .networkSniffer,
                severity: .high,
                title: "Network Sniffer Detected",
                description: "Interface \(sniffer.interface) - Promiscuous: \(sniffer.isPromiscuous)"
            )
            report.findings.append(finding)
        }
    }

    private func generateSummary(_ report: CompromiseReport) -> String {
        var summary = ""

        if report.isCompromised {
            summary += "⚠️ COMPROMISE DETECTED (\(report.compromiseConfidence.rawValue))\n\n"
        } else {
            summary += "✓ No signs of compromise detected\n\n"
        }

        summary += "Total Findings: \(report.totalFindings)\n"
        summary += "Critical Issues: \(report.criticalFindings)\n\n"

        if !report.rootkits.isEmpty {
            summary += "🚨 \(report.rootkits.count) rootkit(s) detected\n"
        }
        if !report.backdoors.isEmpty {
            summary += "🚪 \(report.backdoors.count) backdoor(s) detected\n"
        }
        if !report.hiddenProcesses.isEmpty {
            summary += "👻 \(report.hiddenProcesses.count) hidden process(es) detected\n"
        }
        if !report.suspiciousUsers.isEmpty {
            summary += "👤 \(report.suspiciousUsers.count) suspicious user(s) detected\n"
        }
        if !report.persistenceMechanisms.isEmpty {
            summary += "🔗 \(report.persistenceMechanisms.count) persistence mechanism(s) detected\n"
        }

        return summary
    }

    private func generateRecommendations(_ report: CompromiseReport) -> [String] {
        var recommendations: [String] = []

        if report.isCompromised {
            recommendations.append("🚨 IMMEDIATE ACTION REQUIRED - System appears compromised")
            recommendations.append("1. Isolate this device from the network immediately")
            recommendations.append("2. Do NOT log in to any accounts from this device")
            recommendations.append("3. Change all passwords from a KNOWN CLEAN device")

            if !report.rootkits.isEmpty {
                recommendations.append("4. System has rootkits - Complete re-installation recommended")
                recommendations.append("5. Forensic analysis recommended before re-imaging")
            }

            if !report.backdoors.isEmpty {
                recommendations.append("6. Close unauthorized ports: \(report.backdoors.map { "\($0.port)" }.joined(separator: ", "))")
            }

            if !report.persistenceMechanisms.isEmpty {
                recommendations.append("7. Remove persistence mechanisms before reconnecting to network")
            }
        } else {
            recommendations.append("✓ No immediate threats detected")
            recommendations.append("• Continue regular security monitoring")
            recommendations.append("• Keep system updated")
            recommendations.append("• Review user access periodically")
        }

        return recommendations
    }

    private func printSummary(_ report: CompromiseReport) {
        print("\n" + String(repeating: "=", count: 60))
        print("POST-COMPROMISE ASSESSMENT COMPLETE")
        print(String(repeating: "=", count: 60))
        print("\nTarget: \(report.targetIP)")
        print("Scan Date: \(report.scanDate.formatted())")
        print("\nStatus: \(report.compromiseConfidence.rawValue)")
        print("Total Findings: \(report.totalFindings)")
        print("Critical Issues: \(report.criticalFindings)")
        print("\nBreakdown:")
        print("  Rootkits: \(report.rootkits.count)")
        print("  Backdoors: \(report.backdoors.count)")
        print("  Hidden Processes: \(report.hiddenProcesses.count)")
        print("  Suspicious Users: \(report.suspiciousUsers.count)")
        print("  Persistence Mechanisms: \(report.persistenceMechanisms.count)")
        print("  Binary Integrity Issues: \(report.binaryIntegrityIssues.count)")
        print("  Kernel Module Issues: \(report.kernelModuleIssues.count)")
        print("  Log Tampering: \(report.logTamperingIssues.count)")
        print("  Network Sniffers: \(report.networkSniffers.count)")
        print(String(repeating: "=", count: 60) + "\n")
    }
}
