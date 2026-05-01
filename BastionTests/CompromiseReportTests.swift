//
//  CompromiseReportTests.swift
//  BastionTests
//
//  Unit tests for CompromiseReport and all finding types
//  Author: Jordan Koch
//  Date: 2026-05-01
//

import XCTest
@testable import Bastion

final class CompromiseReportTests: XCTestCase {

    // MARK: - CompromiseReport Initialization

    func testReportInit() {
        let report = CompromiseReport(targetIP: "192.168.1.100")

        XCTAssertEqual(report.targetIP, "192.168.1.100")
        XCTAssertFalse(report.isCompromised)
        XCTAssertEqual(report.compromiseConfidence, .none)
        XCTAssertEqual(report.totalFindings, 0)
        XCTAssertEqual(report.criticalFindings, 0)
        XCTAssertTrue(report.rootkits.isEmpty)
        XCTAssertTrue(report.backdoors.isEmpty)
        XCTAssertTrue(report.hiddenProcesses.isEmpty)
        XCTAssertTrue(report.suspiciousUsers.isEmpty)
        XCTAssertTrue(report.persistenceMechanisms.isEmpty)
        XCTAssertTrue(report.binaryIntegrityIssues.isEmpty)
        XCTAssertTrue(report.kernelModuleIssues.isEmpty)
        XCTAssertTrue(report.logTamperingIssues.isEmpty)
        XCTAssertTrue(report.networkSniffers.isEmpty)
    }

    // MARK: - Total Findings Count

    func testTotalFindingsAggregation() {
        var report = CompromiseReport(targetIP: "192.168.1.100")

        report.rootkits = [
            RootkitFinding(name: "rk1", type: .kernel, detectionMethod: "signature")
        ]
        report.backdoors = [
            BackdoorFinding(port: 4444, service: "unknown", description: "Reverse shell", suspicionReason: "Unusual port"),
            BackdoorFinding(port: 5555, service: "unknown", description: "Backdoor", suspicionReason: "Listening")
        ]
        report.hiddenProcesses = [
            HiddenProcessFinding(pid: 999, command: "/usr/bin/evil", hideMethod: "proc_hide")
        ]

        XCTAssertEqual(report.totalFindings, 4) // 1 + 2 + 1
    }

    // MARK: - Compromise Assessment

    func testAssessCompromiseNone() {
        var report = CompromiseReport(targetIP: "192.168.1.100")
        report.assessCompromise()

        XCTAssertEqual(report.compromiseConfidence, .none)
        XCTAssertFalse(report.isCompromised)
    }

    func testAssessCompromiseDefiniteWithRootkits() {
        var report = CompromiseReport(targetIP: "192.168.1.100")
        report.rootkits = [
            RootkitFinding(name: "Jynx", type: .userland, detectionMethod: "LD_PRELOAD check")
        ]
        report.assessCompromise()

        XCTAssertEqual(report.compromiseConfidence, .definite)
        XCTAssertTrue(report.isCompromised)
    }

    func testAssessCompromiseDefiniteWithCriticals() {
        var report = CompromiseReport(targetIP: "192.168.1.100")
        report.findings = [
            CompromiseFinding(category: .backdoor, severity: .critical, title: "A", description: "A"),
            CompromiseFinding(category: .hiddenProcess, severity: .critical, title: "B", description: "B"),
            CompromiseFinding(category: .rootkit, severity: .critical, title: "C", description: "C"),
        ]
        report.assessCompromise()

        XCTAssertEqual(report.compromiseConfidence, .definite)
        XCTAssertTrue(report.isCompromised)
    }

    func testAssessCompromiseLikely() {
        var report = CompromiseReport(targetIP: "192.168.1.100")
        report.findings = [
            CompromiseFinding(category: .backdoor, severity: .critical, title: "A", description: "A"),
        ]
        report.assessCompromise()

        XCTAssertEqual(report.compromiseConfidence, .likely)
        XCTAssertTrue(report.isCompromised)
    }

    func testAssessCompromisePossibleWithHighFindings() {
        var report = CompromiseReport(targetIP: "192.168.1.100")
        report.findings = [
            CompromiseFinding(category: .suspiciousUser, severity: .high, title: "A", description: "A"),
        ]
        report.assessCompromise()

        XCTAssertEqual(report.compromiseConfidence, .possible)
        XCTAssertTrue(report.isCompromised)
    }

    // MARK: - CompromiseConfidence Tests

    func testCompromiseConfidenceRawValues() {
        XCTAssertEqual(CompromiseConfidence.none.rawValue, "No signs of compromise")
        XCTAssertEqual(CompromiseConfidence.possible.rawValue, "Possible compromise")
        XCTAssertEqual(CompromiseConfidence.likely.rawValue, "Likely compromised")
        XCTAssertEqual(CompromiseConfidence.definite.rawValue, "Definitely compromised")
    }

    // MARK: - Finding Type Tests

    func testRootkitFinding() {
        var finding = RootkitFinding(name: "Jynx", type: .userland, detectionMethod: "LD_PRELOAD")
        finding.files = ["/lib/libjynx.so"]
        finding.processes = ["hidden_process"]

        XCTAssertEqual(finding.name, "Jynx")
        XCTAssertEqual(finding.type, .userland)
        XCTAssertEqual(finding.files.count, 1)
        XCTAssertEqual(finding.processes.count, 1)
    }

    func testBackdoorFinding() {
        let finding = BackdoorFinding(port: 4444, service: "unknown", description: "Reverse shell", suspicionReason: "Non-standard port")

        XCTAssertEqual(finding.port, 4444)
        XCTAssertEqual(finding.service, "unknown")
        XCTAssertEqual(finding.suspicionReason, "Non-standard port")
    }

    func testHiddenProcessFinding() {
        let finding = HiddenProcessFinding(pid: 31337, command: "/tmp/.hidden", hideMethod: "proc manipulation")

        XCTAssertEqual(finding.pid, 31337)
        XCTAssertEqual(finding.command, "/tmp/.hidden")
    }

    func testSuspiciousUserFinding() {
        let finding = SuspiciousUserFinding(
            username: "backdoor",
            uid: 0,
            gid: 0,
            suspicionReasons: ["UID 0 (root)", "Non-standard root account"]
        )

        XCTAssertEqual(finding.username, "backdoor")
        XCTAssertEqual(finding.uid, 0)
        XCTAssertEqual(finding.suspicionReasons.count, 2)
    }

    func testPersistenceFinding() {
        var finding = PersistenceFinding(mechanism: .cron, location: "/etc/crontab", description: "Suspicious cron job")
        finding.content = "* * * * * /tmp/.backdoor"

        XCTAssertEqual(finding.mechanism, .cron)
        XCTAssertEqual(finding.location, "/etc/crontab")
        XCTAssertNotNil(finding.content)
    }

    func testBinaryIntegrityFinding() {
        var finding = BinaryIntegrityFinding(binaryPath: "/usr/bin/ls", issue: .hashMismatch)
        finding.expectedHash = "abc123"
        finding.actualHash = "def456"

        XCTAssertEqual(finding.binaryPath, "/usr/bin/ls")
        XCTAssertEqual(finding.issue, .hashMismatch)
        XCTAssertNotEqual(finding.expectedHash, finding.actualHash)
    }

    func testKernelModuleFinding() {
        let finding = KernelModuleFinding(
            moduleName: "rootkit_lkm",
            suspicionReasons: ["Hidden from lsmod", "Hooks sys_call_table"],
            isLoaded: true
        )

        XCTAssertEqual(finding.moduleName, "rootkit_lkm")
        XCTAssertTrue(finding.isLoaded)
        XCTAssertEqual(finding.suspicionReasons.count, 2)
    }

    func testLogTamperingFinding() {
        let finding = LogTamperingFinding(logFile: "/var/log/auth.log", tamperingType: .cleared, description: "Log was cleared")

        XCTAssertEqual(finding.logFile, "/var/log/auth.log")
        XCTAssertEqual(finding.tamperingType, .cleared)
    }

    func testNetworkSnifferFinding() {
        let finding = NetworkSnifferFinding(interface: "eth0", isPromiscuous: true, snifferProcess: "tcpdump")

        XCTAssertEqual(finding.interface, "eth0")
        XCTAssertTrue(finding.isPromiscuous)
        XCTAssertEqual(finding.snifferProcess, "tcpdump")
    }

    // MARK: - Codable Round Trips

    func testCompromiseReportCodable() throws {
        var report = CompromiseReport(targetIP: "10.0.0.5")
        report.isCompromised = true
        report.compromiseConfidence = .definite
        report.rootkits = [RootkitFinding(name: "Test", type: .kernel, detectionMethod: "sig")]
        report.backdoors = [BackdoorFinding(port: 4444, service: "nc", description: "Netcat", suspicionReason: "Suspicious")]

        let data = try JSONEncoder().encode(report)
        let decoded = try JSONDecoder().decode(CompromiseReport.self, from: data)

        XCTAssertEqual(decoded.targetIP, "10.0.0.5")
        XCTAssertTrue(decoded.isCompromised)
        XCTAssertEqual(decoded.compromiseConfidence, .definite)
        XCTAssertEqual(decoded.rootkits.count, 1)
        XCTAssertEqual(decoded.backdoors.count, 1)
    }

    // MARK: - Enum Exhaustiveness

    func testRootkitTypes() {
        let types: [RootkitType] = [.userland, .kernel, .bootkit, .firmware]
        XCTAssertEqual(types.count, 4)
    }

    func testPersistenceMechanisms() {
        let mechanisms: [PersistenceMechanism] = [.cron, .systemd, .initScript, .rcScript, .bashProfile, .sshKey, .kernelModule]
        XCTAssertEqual(mechanisms.count, 7)
    }

    func testIntegrityIssues() {
        let issues: [IntegrityIssue] = [.hashMismatch, .trojanized, .modifiedTimestamp, .suspiciousPermissions]
        XCTAssertEqual(issues.count, 4)
    }

    func testTamperingTypes() {
        let types: [TamperingType] = [.cleared, .missing, .gapDetected, .suspiciousPermissions]
        XCTAssertEqual(types.count, 4)
    }
}
