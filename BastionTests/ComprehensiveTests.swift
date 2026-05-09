//
//  ComprehensiveTests.swift
//  BastionTests
//
//  Comprehensive test suite covering unit, security, integration, functional, and frame tests.
//  Written by Jordan Koch
//  Created: 2026-05-03
//  Copyright © 2026 Jordan Koch. All rights reserved.
//

import XCTest
@testable import Bastion

// MARK: - Unit Tests

final class DeviceUnitTests: XCTestCase {

    // MARK: Test 1
    func testDeviceCreation() {
        let device = Device(ipAddress: "192.168.1.1")
        XCTAssertEqual(device.ipAddress, "192.168.1.1")
        XCTAssertEqual(device.securityScore, 100)
        XCTAssertTrue(device.isOnline)
        XCTAssertEqual(device.deviceType, .unknown)
        XCTAssertTrue(device.openPorts.isEmpty)
        XCTAssertTrue(device.vulnerabilities.isEmpty)
    }

    // MARK: Test 2
    func testDeviceDisplayNameWithHostname() {
        let device = Device(ipAddress: "10.0.0.1", hostname: "router.local")
        XCTAssertEqual(device.displayName, "router.local")
    }

    // MARK: Test 3
    func testDeviceDisplayNameFallsBackToIP() {
        let device = Device(ipAddress: "10.0.0.1")
        XCTAssertEqual(device.displayName, "10.0.0.1")
    }

    // MARK: Test 4
    func testDeviceRiskLevelCritical() {
        var device = Device(ipAddress: "192.168.1.1")
        device.vulnerabilities = [
            Vulnerability(title: "RCE", description: "critical", severity: .critical)
        ]
        XCTAssertEqual(device.riskLevel, .critical)
    }

    // MARK: Test 5
    func testDeviceRiskLevelHigh() {
        var device = Device(ipAddress: "192.168.1.1")
        device.vulnerabilities = [
            Vulnerability(title: "Auth Bypass", description: "high", severity: .high)
        ]
        XCTAssertEqual(device.riskLevel, .high)
    }

    // MARK: Test 6
    func testDeviceRiskLevelMedium() {
        var device = Device(ipAddress: "192.168.1.1")
        device.vulnerabilities = [
            Vulnerability(title: "XSS", description: "medium", severity: .medium)
        ]
        XCTAssertEqual(device.riskLevel, .medium)
    }

    // MARK: Test 7
    func testDeviceRiskLevelLow() {
        let device = Device(ipAddress: "192.168.1.1")
        XCTAssertEqual(device.riskLevel, .low)
    }

    // MARK: Test 8
    func testDeviceSecurityScoreUpdate() {
        var device = Device(ipAddress: "192.168.1.1")
        device.vulnerabilities = [
            Vulnerability(title: "Critical", description: "RCE", severity: .critical),
            Vulnerability(title: "High", description: "Auth bypass", severity: .high),
            Vulnerability(title: "Med", description: "XSS", severity: .medium),
            Vulnerability(title: "Low", description: "Info leak", severity: .low),
        ]
        device.updateSecurityScore()
        // 100 - 20(crit) - 10(high) - 5(med) - 2(low) = 63
        XCTAssertEqual(device.securityScore, 63)
    }

    // MARK: Test 9
    func testDeviceSecurityScoreFloorAtZero() {
        var device = Device(ipAddress: "192.168.1.1")
        device.vulnerabilities = Array(repeating: Vulnerability(title: "RCE", description: "bad", severity: .critical), count: 10)
        device.updateSecurityScore()
        XCTAssertEqual(device.securityScore, 0)
    }

    // MARK: Test 10
    func testDeviceVulnCounts() {
        var device = Device(ipAddress: "192.168.1.1")
        device.vulnerabilities = [
            Vulnerability(title: "C1", description: "", severity: .critical),
            Vulnerability(title: "C2", description: "", severity: .critical),
            Vulnerability(title: "H1", description: "", severity: .high),
            Vulnerability(title: "M1", description: "", severity: .medium),
            Vulnerability(title: "L1", description: "", severity: .low),
            Vulnerability(title: "L2", description: "", severity: .low),
        ]
        XCTAssertEqual(device.criticalVulnCount, 2)
        XCTAssertEqual(device.highVulnCount, 1)
        XCTAssertEqual(device.mediumVulnCount, 1)
        XCTAssertEqual(device.lowVulnCount, 2)
    }
}

final class CVEUnitTests: XCTestCase {

    // MARK: Test 11
    func testCVECreation() {
        let cve = CVE(id: "CVE-2024-1234", description: "Buffer overflow", cvssScore: 9.8)
        XCTAssertEqual(cve.id, "CVE-2024-1234")
        XCTAssertEqual(cve.cvssScore, 9.8)
        XCTAssertEqual(cve.severity, .critical)
        XCTAssertFalse(cve.exploitAvailable)
    }

    // MARK: Test 12
    func testCVESeverityFromScore() {
        XCTAssertEqual(CVE.severityFromScore(10.0), .critical)
        XCTAssertEqual(CVE.severityFromScore(9.0), .critical)
        XCTAssertEqual(CVE.severityFromScore(8.5), .high)
        XCTAssertEqual(CVE.severityFromScore(7.0), .high)
        XCTAssertEqual(CVE.severityFromScore(5.0), .medium)
        XCTAssertEqual(CVE.severityFromScore(4.0), .medium)
        XCTAssertEqual(CVE.severityFromScore(2.0), .low)
        XCTAssertEqual(CVE.severityFromScore(0.0), .informational)
    }

    // MARK: Test 13
    func testVulnerabilitySeverityWeight() {
        XCTAssertEqual(VulnerabilitySeverity.critical.weight, 5)
        XCTAssertEqual(VulnerabilitySeverity.high.weight, 4)
        XCTAssertEqual(VulnerabilitySeverity.medium.weight, 3)
        XCTAssertEqual(VulnerabilitySeverity.low.weight, 2)
        XCTAssertEqual(VulnerabilitySeverity.informational.weight, 1)
    }

    // MARK: Test 14
    func testVulnerabilitySeverityAllCases() {
        XCTAssertEqual(VulnerabilitySeverity.allCases.count, 5)
    }
}

final class PortAndServiceUnitTests: XCTestCase {

    // MARK: Test 15
    func testOpenPortCreation() {
        let port = OpenPort(port: 443, portProtocol: .tcp)
        XCTAssertEqual(port.port, 443)
        XCTAssertEqual(port.portProtocol, .tcp)
        XCTAssertEqual(port.state, .open)
        XCTAssertNil(port.service)
    }

    // MARK: Test 16
    func testServiceInfoDisplayVersion() {
        let service = ServiceInfo(name: "Apache", version: "2.4.51", port: 80)
        XCTAssertEqual(service.displayVersion, "Apache 2.4.51")
    }

    // MARK: Test 17
    func testServiceInfoDisplayVersionWithoutVersion() {
        let service = ServiceInfo(name: "OpenSSH", port: 22)
        XCTAssertEqual(service.displayVersion, "OpenSSH")
    }

    // MARK: Test 18
    func testDeviceTypeIcons() {
        let allTypes: [DeviceType] = [.router, .server, .workstation, .mobile, .iot, .camera, .printer, .nas, .unknown]
        for dt in allTypes {
            XCTAssertFalse(dt.icon.isEmpty, "\(dt) should have an icon")
        }
    }
}

// MARK: - Security Tests

final class BastionSecurityTests: XCTestCase {

    let validator = SafetyValidator.shared

    // MARK: Test 19 - Local IP Validation Private Ranges
    func testIsLocalIPPrivateRanges() {
        XCTAssertTrue(validator.isLocalIP("192.168.1.1"))
        XCTAssertTrue(validator.isLocalIP("192.168.0.100"))
        XCTAssertTrue(validator.isLocalIP("10.0.0.1"))
        XCTAssertTrue(validator.isLocalIP("10.255.255.255"))
        XCTAssertTrue(validator.isLocalIP("172.16.0.1"))
        XCTAssertTrue(validator.isLocalIP("172.31.255.255"))
        XCTAssertTrue(validator.isLocalIP("127.0.0.1"))
    }

    // MARK: Test 20 - Public IP Blocked
    func testIsLocalIPBlocksPublic() {
        XCTAssertFalse(validator.isLocalIP("8.8.8.8"))
        XCTAssertFalse(validator.isLocalIP("1.1.1.1"))
        XCTAssertFalse(validator.isLocalIP("142.250.80.46"))
        XCTAssertFalse(validator.isLocalIP("172.15.0.1"))  // Just outside 172.16.0.0/12
        XCTAssertFalse(validator.isLocalIP("172.32.0.1"))  // Just outside 172.16.0.0/12
    }

    // MARK: Test 21 - Validate Target Throws for Public IP
    func testValidateTargetThrowsForPublicIP() {
        XCTAssertThrowsError(try validator.validateTarget("8.8.8.8")) { error in
            guard let bastionError = error as? BastionError,
                  case .publicIPNotAllowed = bastionError else {
                XCTFail("Expected publicIPNotAllowed error")
                return
            }
        }
    }

    // MARK: Test 22 - Validate Target Allows Local IP
    func testValidateTargetAllowsLocalIP() {
        XCTAssertNoThrow(try validator.validateTarget("192.168.1.100"))
        XCTAssertNoThrow(try validator.validateTarget("10.0.0.5"))
    }

    // MARK: Test 23 - Rate Limiting
    func testRateLimitingBlocks() {
        // Fire 10 requests (max rate), then 11th should fail
        for _ in 0..<10 {
            XCTAssertNoThrow(try validator.checkRateLimit())
        }
        XCTAssertThrowsError(try validator.checkRateLimit()) { error in
            guard let bastionError = error as? BastionError,
                  case .rateLimitExceeded = bastionError else {
                XCTFail("Expected rateLimitExceeded error")
                return
            }
        }
    }

    // MARK: Test 24 - Invalid IP Format
    func testIsLocalIPInvalidFormat() {
        XCTAssertFalse(validator.isLocalIP("not-an-ip"))
        XCTAssertFalse(validator.isLocalIP(""))
        XCTAssertFalse(validator.isLocalIP("192.168.1"))
        XCTAssertFalse(validator.isLocalIP("192.168.1.1.1"))
    }

    // MARK: Test 25 - Bastion Error Descriptions
    func testBastionErrorDescriptions() {
        let errors: [BastionError] = [
            .publicIPNotAllowed("test"),
            .rateLimitExceeded("limit"),
            .unauthorizedTarget,
            .legalNotAccepted,
        ]
        for error in errors {
            XCTAssertNotNil(error.errorDescription)
            XCTAssertFalse(error.errorDescription!.isEmpty)
        }
    }

    // MARK: Test 26 - Audit Logging Does Not Crash
    func testAuditLogging() {
        // Smoke test: ensure logging doesn't crash
        validator.logActivity("Test scan initiated", target: "192.168.1.1")
        validator.logActivity("Test without target")
    }
}

// MARK: - Integration Tests

final class BastionIntegrationTests: XCTestCase {

    // MARK: Test 27 - Attack Result Creation
    func testAttackResultCreation() {
        let result = AttackResult(targetIP: "192.168.1.1", attackType: .portScan, module: "PortScanner")
        XCTAssertEqual(result.targetIP, "192.168.1.1")
        XCTAssertEqual(result.attackType, .portScan)
        XCTAssertEqual(result.module, "PortScanner")
        XCTAssertEqual(result.status, .running)
        XCTAssertFalse(result.vulnerabilityConfirmed)
        XCTAssertFalse(result.exploitSuccessful)
    }

    // MARK: Test 28 - Attack Status Icons
    func testAttackStatusIcons() {
        for status in [AttackStatus.pending, .running, .success, .failed, .blocked, .timeout] {
            XCTAssertFalse(status.icon.isEmpty, "\(status) should have an icon")
        }
    }

    // MARK: Test 29 - Attack Result Log Entry Format
    func testAttackResultLogEntry() {
        var result = AttackResult(targetIP: "192.168.1.1", attackType: .networkScan, module: "Scanner")
        result.details = "Found 5 hosts"
        let log = result.logEntry
        XCTAssertTrue(log.contains("Network Scan"))
        XCTAssertTrue(log.contains("Found 5 hosts"))
    }

    // MARK: Test 30 - Scan Results Init
    func testScanResultsInit() {
        let results = ScanResults()
        XCTAssertTrue(results.devices.isEmpty)
        XCTAssertEqual(results.totalVulnerabilities, 0)
        XCTAssertEqual(results.criticalCount, 0)
        XCTAssertTrue(results.networkCIDR.isEmpty)
    }

    // MARK: Test 31 - Attack Type All Cases
    func testAttackTypeAllCases() {
        XCTAssertTrue(AttackType.allCases.count >= 17)
        for attackType in AttackType.allCases {
            XCTAssertFalse(attackType.icon.isEmpty)
            XCTAssertFalse(attackType.rawValue.isEmpty)
        }
    }

    // MARK: Test 32 - Compromise Report Creation
    func testCompromiseReportCreation() {
        let report = CompromiseReport(targetIP: "192.168.1.50")
        XCTAssertEqual(report.targetIP, "192.168.1.50")
        XCTAssertFalse(report.isCompromised)
        XCTAssertEqual(report.compromiseConfidence, .none)
        XCTAssertEqual(report.totalFindings, 0)
    }

    // MARK: Test 33 - Compromise Assessment Definite
    func testCompromiseAssessmentDefinite() {
        var report = CompromiseReport(targetIP: "192.168.1.50")
        report.rootkits = [
            RootkitFinding(name: "LKM rootkit", type: .kernel, detectionMethod: "signature")
        ]
        report.assessCompromise()
        XCTAssertTrue(report.isCompromised)
        XCTAssertEqual(report.compromiseConfidence, .definite)
    }

    // MARK: Test 34 - Compromise Assessment Likely
    func testCompromiseAssessmentLikely() {
        var report = CompromiseReport(targetIP: "192.168.1.50")
        report.findings = [
            CompromiseFinding(category: .backdoor, severity: .critical, title: "Backdoor", description: ""),
        ]
        report.assessCompromise()
        XCTAssertTrue(report.isCompromised)
        XCTAssertEqual(report.compromiseConfidence, .likely)
    }

    // MARK: Test 35 - Compromise Assessment Possible
    func testCompromiseAssessmentPossible() {
        var report = CompromiseReport(targetIP: "192.168.1.50")
        report.findings = [
            CompromiseFinding(category: .suspiciousUser, severity: .high, title: "Suspicious user", description: ""),
        ]
        report.assessCompromise()
        XCTAssertTrue(report.isCompromised)
        XCTAssertEqual(report.compromiseConfidence, .possible)
    }

    // MARK: Test 36 - Compromise Assessment None
    func testCompromiseAssessmentNone() {
        var report = CompromiseReport(targetIP: "192.168.1.50")
        report.findings = [
            CompromiseFinding(category: .logTampering, severity: .low, title: "Minor", description: ""),
        ]
        report.assessCompromise()
        XCTAssertFalse(report.isCompromised)
        XCTAssertEqual(report.compromiseConfidence, .none)
    }
}

// MARK: - Functional Tests

final class BastionFunctionalTests: XCTestCase {

    // MARK: Test 37 - MITRE Tactic Ordering
    func testMITRETacticOrdering() {
        XCTAssertLessThan(MITRETactic.reconnaissance, MITRETactic.initialAccess)
        XCTAssertLessThan(MITRETactic.initialAccess, MITRETactic.execution)
        XCTAssertLessThan(MITRETactic.execution, MITRETactic.persistence)
        XCTAssertLessThan(MITRETactic.lateralMovement, MITRETactic.exfiltration)
        XCTAssertLessThan(MITRETactic.exfiltration, MITRETactic.impact)
    }

    // MARK: Test 38 - MITRE Tactic All Cases
    func testMITRETacticAllCases() {
        XCTAssertEqual(MITRETactic.allCases.count, 14)
    }

    // MARK: Test 39 - MITRE Report Critical Techniques Filter
    func testMITREReportCriticalTechniques() {
        let techniques = [
            MITRETechnique(id: "T1078", name: "Valid Accounts", tactic: .initialAccess,
                           description: "Default creds", evidence: [], severity: .critical),
            MITRETechnique(id: "T1046", name: "Network Discovery", tactic: .discovery,
                           description: "Port scan", evidence: [], severity: .informational),
        ]
        let report = MITREATTACKReport(techniques: techniques, tactics: [.initialAccess, .discovery],
                                        devicesAnalyzed: 1, scanDate: Date())
        XCTAssertEqual(report.criticalTechniques.count, 1)
        XCTAssertEqual(report.criticalTechniques.first?.id, "T1078")
    }

    // MARK: Test 40 - MITRE Report Techniques By Tactic
    func testMITREReportTechniquesByTactic() {
        let techniques = [
            MITRETechnique(id: "T1", name: "A", tactic: .discovery, description: "", evidence: [], severity: .low),
            MITRETechnique(id: "T2", name: "B", tactic: .discovery, description: "", evidence: [], severity: .low),
            MITRETechnique(id: "T3", name: "C", tactic: .execution, description: "", evidence: [], severity: .high),
        ]
        let report = MITREATTACKReport(techniques: techniques, tactics: [.discovery, .execution],
                                        devicesAnalyzed: 1, scanDate: Date())
        let byTactic = report.techniquesByTactic
        XCTAssertEqual(byTactic[.discovery]?.count, 2)
        XCTAssertEqual(byTactic[.execution]?.count, 1)
    }

    // MARK: Test 41 - Vulnerability Chain Probability Calculation
    func testVulnerabilityChainProbability() {
        let vuln = Vulnerability(title: "test", description: "test vuln", severity: .high)
        var chain = VulnerabilityChain(
            device: Device(ipAddress: "192.168.1.1"),
            steps: [
                ChainStep(vulnerability: vuln, action: "Step 1", successProbability: 80),
                ChainStep(vulnerability: vuln, action: "Step 2", successProbability: 50),
            ],
            impact: "test",
            chainType: .infoToPrivEsc
        )
        chain.calculateTotalProbability()
        // 0.8 * 0.5 = 0.4 => 40%
        XCTAssertEqual(chain.totalSuccessProbability, 40.0, accuracy: 0.01)
    }

    // MARK: Test 42 - Vulnerability Chain Description
    func testVulnerabilityChainDescription() {
        let vuln = Vulnerability(title: "test", description: "test", severity: .medium)
        let chain = VulnerabilityChain(
            device: Device(ipAddress: "192.168.1.1"),
            steps: [
                ChainStep(vulnerability: vuln, action: "A", successProbability: 50),
                ChainStep(vulnerability: vuln, action: "B", successProbability: 50),
                ChainStep(vulnerability: vuln, action: "C", successProbability: 50),
            ],
            impact: "Full compromise",
            chainType: .sqliToRCE
        )
        XCTAssertTrue(chain.description.contains("3-step chain"))
        XCTAssertTrue(chain.description.contains("Full compromise"))
    }

    // MARK: Test 43 - Chain Type All Cases
    func testChainTypeAllCases() {
        XCTAssertEqual(ChainType.allCases.count, 7)
    }

    // MARK: Test 44 - Finding Types Creation
    func testFindingTypesCreation() {
        let rootkit = RootkitFinding(name: "LKM", type: .kernel, detectionMethod: "signature")
        XCTAssertEqual(rootkit.type, .kernel)

        let backdoor = BackdoorFinding(port: 31337, service: "unknown", description: "Backdoor", suspicionReason: "Unusual port")
        XCTAssertEqual(backdoor.port, 31337)

        let hidden = HiddenProcessFinding(pid: 1234, command: "evil", hideMethod: "LD_PRELOAD")
        XCTAssertEqual(hidden.pid, 1234)

        let suspUser = SuspiciousUserFinding(username: "hacker", uid: 0, gid: 0, suspicionReasons: ["uid=0"])
        XCTAssertEqual(suspUser.uid, 0)

        let persist = PersistenceFinding(mechanism: .cron, location: "/etc/crontab", description: "Cron backdoor")
        XCTAssertEqual(persist.mechanism, .cron)

        let integrity = BinaryIntegrityFinding(binaryPath: "/usr/bin/ls", issue: .hashMismatch)
        XCTAssertEqual(integrity.issue, .hashMismatch)

        let kernel = KernelModuleFinding(moduleName: "evil_mod", suspicionReasons: ["unsigned"])
        XCTAssertTrue(kernel.isLoaded)

        let logTamper = LogTamperingFinding(logFile: "/var/log/auth.log", tamperingType: .cleared, description: "Log cleared")
        XCTAssertEqual(logTamper.tamperingType, .cleared)

        let sniffer = NetworkSnifferFinding(interface: "eth0", isPromiscuous: true, snifferProcess: "tcpdump")
        XCTAssertTrue(sniffer.isPromiscuous)
    }

    // MARK: Test 45 - Compromise Confidence Colors
    func testCompromiseConfidenceColors() {
        XCTAssertEqual(CompromiseConfidence.none.color, "#00FF00")
        XCTAssertEqual(CompromiseConfidence.possible.color, "#FFFF00")
        XCTAssertEqual(CompromiseConfidence.likely.color, "#FF9500")
        XCTAssertEqual(CompromiseConfidence.definite.color, "#FF0000")
    }

    // MARK: Test 46 - Compromise Report Total Findings
    func testCompromiseReportTotalFindings() {
        var report = CompromiseReport(targetIP: "192.168.1.1")
        report.rootkits = [RootkitFinding(name: "a", type: .userland, detectionMethod: "m")]
        report.backdoors = [BackdoorFinding(port: 1, service: "x", description: "d", suspicionReason: "r")]
        report.hiddenProcesses = [HiddenProcessFinding(pid: 1, command: "c", hideMethod: "h")]
        XCTAssertEqual(report.totalFindings, 3)
    }

    // MARK: Test 47 - Compromise Report Critical Findings
    func testCompromiseReportCriticalFindings() {
        var report = CompromiseReport(targetIP: "192.168.1.1")
        report.findings = [
            CompromiseFinding(category: .rootkit, severity: .critical, title: "Rootkit", description: ""),
            CompromiseFinding(category: .backdoor, severity: .high, title: "Backdoor", description: ""),
            CompromiseFinding(category: .persistence, severity: .critical, title: "Persist", description: ""),
        ]
        XCTAssertEqual(report.criticalFindings, 2)
    }
}

// MARK: - Frame / Enum Tests

final class BastionFrameTests: XCTestCase {

    // MARK: Test 48 - Risk Level Colors Exist
    func testRiskLevelColorsExist() {
        // Just ensure they don't crash
        _ = RiskLevel.low.color
        _ = RiskLevel.medium.color
        _ = RiskLevel.high.color
        _ = RiskLevel.critical.color
    }

    // MARK: Test 49 - Vulnerability Severity Colors
    func testVulnerabilitySeverityColors() {
        for severity in VulnerabilitySeverity.allCases {
            XCTAssertTrue(severity.color.hasPrefix("#"), "\(severity) color should be hex")
        }
    }

    // MARK: Test 50 - Device Type Values
    func testDeviceTypeValues() {
        let allTypes: [DeviceType] = [.router, .server, .workstation, .mobile, .iot, .camera, .printer, .nas, .unknown]
        XCTAssertEqual(allTypes.count, 9)
        for dt in allTypes {
            XCTAssertFalse(dt.rawValue.isEmpty)
        }
    }

    // MARK: Test 51 - Port Protocol Values
    func testPortProtocolValues() {
        XCTAssertEqual(PortProtocol.tcp.rawValue, "TCP")
        XCTAssertEqual(PortProtocol.udp.rawValue, "UDP")
    }

    // MARK: Test 52 - Port State Values
    func testPortStateValues() {
        XCTAssertEqual(PortState.open.rawValue, "Open")
        XCTAssertEqual(PortState.closed.rawValue, "Closed")
        XCTAssertEqual(PortState.filtered.rawValue, "Filtered")
    }

    // MARK: Test 53 - Rootkit Type Values
    func testRootkitTypeValues() {
        XCTAssertEqual(RootkitType.userland.rawValue, "Userland Rootkit")
        XCTAssertEqual(RootkitType.kernel.rawValue, "Kernel Rootkit (LKM)")
        XCTAssertEqual(RootkitType.bootkit.rawValue, "Bootkit")
        XCTAssertEqual(RootkitType.firmware.rawValue, "Firmware Rootkit")
    }

    // MARK: Test 54 - Persistence Mechanism Values
    func testPersistenceMechanismValues() {
        let allMechanisms: [PersistenceMechanism] = [.cron, .systemd, .initScript, .rcScript, .bashProfile, .sshKey, .kernelModule]
        XCTAssertEqual(allMechanisms.count, 7)
        XCTAssertEqual(PersistenceMechanism.cron.rawValue, "Cron Job")
        XCTAssertEqual(PersistenceMechanism.sshKey.rawValue, "SSH Authorized Key")
    }

    // MARK: Test 55 - Integrity Issue Values
    func testIntegrityIssueValues() {
        XCTAssertEqual(IntegrityIssue.hashMismatch.rawValue, "Hash Mismatch")
        XCTAssertEqual(IntegrityIssue.trojanized.rawValue, "Trojanized Binary")
        XCTAssertEqual(IntegrityIssue.modifiedTimestamp.rawValue, "Modified Timestamp")
        XCTAssertEqual(IntegrityIssue.suspiciousPermissions.rawValue, "Suspicious Permissions")
    }

    // MARK: Test 56 - Tampering Type Values
    func testTamperingTypeValues() {
        XCTAssertEqual(TamperingType.cleared.rawValue, "Log Cleared")
        XCTAssertEqual(TamperingType.missing.rawValue, "Log Missing")
        XCTAssertEqual(TamperingType.gapDetected.rawValue, "Gaps Detected")
        XCTAssertEqual(TamperingType.suspiciousPermissions.rawValue, "Suspicious Permissions")
    }

    // MARK: Test 57 - Compromise Category Values
    func testCompromiseCategoryValues() {
        XCTAssertEqual(CompromiseCategory.rootkit.rawValue, "Rootkit")
        XCTAssertEqual(CompromiseCategory.backdoor.rawValue, "Backdoor")
        XCTAssertEqual(CompromiseCategory.hiddenProcess.rawValue, "Hidden Process")
        XCTAssertEqual(CompromiseCategory.suspiciousUser.rawValue, "Suspicious User")
        XCTAssertEqual(CompromiseCategory.persistence.rawValue, "Persistence Mechanism")
        XCTAssertEqual(CompromiseCategory.binaryIntegrity.rawValue, "Binary Integrity")
        XCTAssertEqual(CompromiseCategory.kernelModule.rawValue, "Kernel Module")
        XCTAssertEqual(CompromiseCategory.logTampering.rawValue, "Log Tampering")
        XCTAssertEqual(CompromiseCategory.networkSniffer.rawValue, "Network Sniffer")
    }

    // MARK: Test 58 - Device Codable Round Trip
    func testDeviceCodableRoundTrip() throws {
        var device = Device(ipAddress: "192.168.1.10", hostname: "server.local", macAddress: "AA:BB:CC:DD:EE:FF")
        device.deviceType = .server
        device.operatingSystem = "Ubuntu 22.04"
        device.openPorts = [OpenPort(port: 22), OpenPort(port: 80)]
        device.services = [ServiceInfo(name: "OpenSSH", version: "8.9", port: 22)]

        let data = try JSONEncoder().encode(device)
        let decoded = try JSONDecoder().decode(Device.self, from: data)
        XCTAssertEqual(decoded.ipAddress, "192.168.1.10")
        XCTAssertEqual(decoded.hostname, "server.local")
        XCTAssertEqual(decoded.deviceType, .server)
        XCTAssertEqual(decoded.openPorts.count, 2)
    }

    // MARK: Test 59 - CVE Codable Round Trip
    func testCVECodableRoundTrip() throws {
        var cve = CVE(id: "CVE-2024-5678", description: "SQL injection in web panel", cvssScore: 8.1)
        cve.exploitAvailable = true
        cve.cweId = "CWE-89"
        cve.affectedProducts = ["WebPanel v1.0"]

        let data = try JSONEncoder().encode(cve)
        let decoded = try JSONDecoder().decode(CVE.self, from: data)
        XCTAssertEqual(decoded.id, "CVE-2024-5678")
        XCTAssertEqual(decoded.cvssScore, 8.1)
        XCTAssertTrue(decoded.exploitAvailable)
        XCTAssertEqual(decoded.cweId, "CWE-89")
    }

    // MARK: Test 60 - Vulnerability Chain Single Step 100%
    func testVulnerabilityChainSingleStep100() {
        let vuln = Vulnerability(title: "t", description: "d", severity: .critical)
        var chain = VulnerabilityChain(
            device: Device(ipAddress: "192.168.1.1"),
            steps: [ChainStep(vulnerability: vuln, action: "Go", successProbability: 100)],
            impact: "Full",
            chainType: .customChain
        )
        chain.calculateTotalProbability()
        XCTAssertEqual(chain.totalSuccessProbability, 100.0, accuracy: 0.01)
    }
}
