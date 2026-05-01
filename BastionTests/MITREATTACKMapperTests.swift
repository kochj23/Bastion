//
//  MITREATTACKMapperTests.swift
//  BastionTests
//
//  Functional tests for MITRE ATT&CK mapping logic
//  Author: Jordan Koch
//  Date: 2026-05-01
//

import XCTest
@testable import Bastion

@MainActor
final class MITREATTACKMapperTests: XCTestCase {

    var mapper: MITREATTACKMapper!

    override func setUp() {
        super.setUp()
        mapper = MITREATTACKMapper()
    }

    // MARK: - Network Service Discovery Mapping

    func testOpenPortsMappedToT1046() {
        var device = Device(ipAddress: "192.168.1.10")
        device.openPorts = [OpenPort(port: 22), OpenPort(port: 80)]

        let report = mapper.mapToATTACK(devices: [device], attackResults: [])

        let t1046 = report.techniques.filter { $0.id == "T1046" }
        XCTAssertFalse(t1046.isEmpty, "Open ports should map to T1046 Network Service Discovery")
        XCTAssertTrue(report.tactics.contains(.discovery))
    }

    // MARK: - SSH Mapping

    func testSSHMappedToT1021004() {
        var device = Device(ipAddress: "192.168.1.10")
        device.openPorts = [OpenPort(port: 22)]

        let report = mapper.mapToATTACK(devices: [device], attackResults: [])

        let sshTechniques = report.techniques.filter { $0.id == "T1021.004" }
        XCTAssertFalse(sshTechniques.isEmpty, "SSH should map to T1021.004")
        XCTAssertTrue(report.tactics.contains(.lateralMovement))
    }

    // MARK: - SMB Mapping

    func testSMBMappedToT1021002() {
        var device = Device(ipAddress: "192.168.1.10")
        device.openPorts = [OpenPort(port: 445)]

        let report = mapper.mapToATTACK(devices: [device], attackResults: [])

        let smbTechniques = report.techniques.filter { $0.id == "T1021.002" }
        XCTAssertFalse(smbTechniques.isEmpty, "SMB should map to T1021.002")
    }

    // MARK: - Default Credentials Mapping

    func testDefaultCredentialsMappedToT1078() {
        var device = Device(ipAddress: "192.168.1.10")
        device.vulnerabilities = [
            Vulnerability(title: "Default admin password", description: "Default credentials", severity: .critical)
        ]

        let report = mapper.mapToATTACK(devices: [device], attackResults: [])

        let credsTechniques = report.techniques.filter { $0.id == "T1078" }
        XCTAssertFalse(credsTechniques.isEmpty, "Default creds should map to T1078 Valid Accounts")
        XCTAssertTrue(report.tactics.contains(.initialAccess))
    }

    // MARK: - RCE Mapping

    func testRCEMappedToT1059() {
        var device = Device(ipAddress: "192.168.1.10")
        device.vulnerabilities = [
            Vulnerability(title: "RCE", description: "Remote code execution via injection", severity: .critical)
        ]

        let report = mapper.mapToATTACK(devices: [device], attackResults: [])

        let rceTechniques = report.techniques.filter { $0.id == "T1059" }
        XCTAssertFalse(rceTechniques.isEmpty, "RCE should map to T1059")
        XCTAssertTrue(report.tactics.contains(.execution))
    }

    // MARK: - Privilege Escalation Mapping

    func testPrivEscMappedToT1068() {
        var device = Device(ipAddress: "192.168.1.10")
        device.vulnerabilities = [
            Vulnerability(title: "PrivEsc", description: "Local privilege escalation", severity: .high)
        ]

        let report = mapper.mapToATTACK(devices: [device], attackResults: [])

        let privEscTechniques = report.techniques.filter { $0.id == "T1068" }
        XCTAssertFalse(privEscTechniques.isEmpty, "PrivEsc should map to T1068")
        XCTAssertTrue(report.tactics.contains(.privilegeEscalation))
    }

    // MARK: - Attack Result Mapping

    func testBruteForceAttackMappedToT1110() {
        let attack = AttackResult(targetIP: "192.168.1.10", attackType: .sshBruteForce, module: "SSHModule")

        let report = mapper.mapToATTACK(devices: [], attackResults: [attack])

        let bruteTechniques = report.techniques.filter { $0.id == "T1110" }
        XCTAssertFalse(bruteTechniques.isEmpty, "Brute force should map to T1110")
        XCTAssertTrue(report.tactics.contains(.credentialAccess))
    }

    func testSQLiAttackMappedToT1190() {
        let attack = AttackResult(targetIP: "192.168.1.10", attackType: .sqlInjection, module: "WebModule")

        let report = mapper.mapToATTACK(devices: [], attackResults: [attack])

        let sqliTechniques = report.techniques.filter { $0.id == "T1190" }
        XCTAssertFalse(sqliTechniques.isEmpty, "SQLi should map to T1190")
    }

    func testSMBExploitMappedToT1210() {
        let attack = AttackResult(targetIP: "192.168.1.10", attackType: .smbExploit, module: "SMBModule")

        let report = mapper.mapToATTACK(devices: [], attackResults: [attack])

        let smbTechniques = report.techniques.filter { $0.id == "T1210" }
        XCTAssertFalse(smbTechniques.isEmpty, "SMB exploit should map to T1210")
    }

    // MARK: - Report Computed Properties

    func testCriticalTechniquesFilter() {
        var device = Device(ipAddress: "192.168.1.10")
        device.vulnerabilities = [
            Vulnerability(title: "Default creds", description: "Default credentials found", severity: .critical),
            Vulnerability(title: "RCE", description: "Remote code execution possible", severity: .critical),
        ]
        device.openPorts = [OpenPort(port: 22)]

        let report = mapper.mapToATTACK(devices: [device], attackResults: [])

        XCTAssertFalse(report.criticalTechniques.isEmpty, "Should identify critical techniques")
    }

    func testTechniquesByTactic() {
        var device = Device(ipAddress: "192.168.1.10")
        device.openPorts = [OpenPort(port: 22), OpenPort(port: 445)]

        let report = mapper.mapToATTACK(devices: [device], attackResults: [])
        let byTactic = report.techniquesByTactic

        XCTAssertNotNil(byTactic[.lateralMovement], "Should group techniques by tactic")
    }

    // MARK: - Multiple Devices

    func testMultipleDevicesMapping() {
        var device1 = Device(ipAddress: "192.168.1.10")
        device1.openPorts = [OpenPort(port: 22)]

        var device2 = Device(ipAddress: "192.168.1.20")
        device2.openPorts = [OpenPort(port: 445), OpenPort(port: 3389)]

        let report = mapper.mapToATTACK(devices: [device1, device2], attackResults: [])

        XCTAssertEqual(report.devicesAnalyzed, 2)
        XCTAssertTrue(report.techniques.count >= 3, "Multiple devices should produce multiple techniques")
    }

    // MARK: - Navigator JSON Export

    func testNavigatorJSONExport() {
        var device = Device(ipAddress: "192.168.1.10")
        device.openPorts = [OpenPort(port: 22)]

        let report = mapper.mapToATTACK(devices: [device], attackResults: [])
        let json = mapper.exportNavigatorJSON(report: report)

        XCTAssertTrue(json.contains("enterprise-attack"))
        XCTAssertTrue(json.contains("techniqueID"))
        XCTAssertTrue(json.contains("Bastion"))
    }

    // MARK: - MITRETactic Order

    func testTacticOrdering() {
        XCTAssertTrue(MITRETactic.reconnaissance < MITRETactic.initialAccess)
        XCTAssertTrue(MITRETactic.initialAccess < MITRETactic.execution)
        XCTAssertTrue(MITRETactic.execution < MITRETactic.persistence)
        XCTAssertTrue(MITRETactic.exfiltration < MITRETactic.impact)
    }

    func testTacticAllCases() {
        XCTAssertEqual(MITRETactic.allCases.count, 14)
    }

    // MARK: - Empty Inputs

    func testEmptyDevicesAndAttacks() {
        let report = mapper.mapToATTACK(devices: [], attackResults: [])

        XCTAssertTrue(report.techniques.isEmpty)
        XCTAssertTrue(report.tactics.isEmpty)
        XCTAssertEqual(report.devicesAnalyzed, 0)
    }
}
