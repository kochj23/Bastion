//
//  AttackResultTests.swift
//  BastionTests
//
//  Unit tests for AttackResult, AttackStatus, ScanResults, and AttackType
//  Author: Jordan Koch
//  Date: 2026-05-01
//

import XCTest
@testable import Bastion

final class AttackResultTests: XCTestCase {

    // MARK: - AttackResult Initialization

    func testAttackResultInit() {
        let result = AttackResult(targetIP: "192.168.1.50", attackType: .sshBruteForce, module: "SSHModule")

        XCTAssertEqual(result.targetIP, "192.168.1.50")
        XCTAssertEqual(result.attackType, .sshBruteForce)
        XCTAssertEqual(result.module, "SSHModule")
        XCTAssertEqual(result.status, .running)
        XCTAssertEqual(result.duration, 0)
        XCTAssertTrue(result.details.isEmpty)
        XCTAssertTrue(result.evidence.isEmpty)
        XCTAssertFalse(result.vulnerabilityConfirmed)
        XCTAssertFalse(result.exploitSuccessful)
    }

    func testAttackResultLogEntry() {
        var result = AttackResult(targetIP: "192.168.1.50", attackType: .sqlInjection, module: "WebModule")
        result.details = "Found injection point in login form"

        let logEntry = result.logEntry
        XCTAssertTrue(logEntry.contains("SQL Injection"))
        XCTAssertTrue(logEntry.contains("Found injection point"))
    }

    // MARK: - AttackResult Codable

    func testAttackResultCodable() throws {
        var result = AttackResult(targetIP: "10.0.0.5", attackType: .cveExploit, module: "CVEModule")
        result.status = .success
        result.details = "CVE-2021-44228 confirmed"
        result.vulnerabilityConfirmed = true
        result.exploitSuccessful = true

        let data = try JSONEncoder().encode(result)
        let decoded = try JSONDecoder().decode(AttackResult.self, from: data)

        XCTAssertEqual(decoded.targetIP, "10.0.0.5")
        XCTAssertEqual(decoded.attackType, .cveExploit)
        XCTAssertEqual(decoded.status, .success)
        XCTAssertTrue(decoded.vulnerabilityConfirmed)
        XCTAssertTrue(decoded.exploitSuccessful)
    }

    // MARK: - AttackStatus Tests

    func testAttackStatusIcons() {
        XCTAssertFalse(AttackStatus.pending.icon.isEmpty)
        XCTAssertFalse(AttackStatus.running.icon.isEmpty)
        XCTAssertFalse(AttackStatus.success.icon.isEmpty)
        XCTAssertFalse(AttackStatus.failed.icon.isEmpty)
        XCTAssertFalse(AttackStatus.blocked.icon.isEmpty)
        XCTAssertFalse(AttackStatus.timeout.icon.isEmpty)
    }

    func testAttackStatusRawValues() {
        XCTAssertEqual(AttackStatus.pending.rawValue, "Pending")
        XCTAssertEqual(AttackStatus.running.rawValue, "Running")
        XCTAssertEqual(AttackStatus.success.rawValue, "Success")
        XCTAssertEqual(AttackStatus.failed.rawValue, "Failed")
        XCTAssertEqual(AttackStatus.blocked.rawValue, "Blocked")
        XCTAssertEqual(AttackStatus.timeout.rawValue, "Timeout")
    }

    // MARK: - AttackType Tests

    func testAttackTypeAllCases() {
        XCTAssertTrue(AttackType.allCases.count >= 16)
    }

    func testAttackTypeIcons() {
        for attackType in AttackType.allCases {
            XCTAssertFalse(attackType.icon.isEmpty, "AttackType.\(attackType.rawValue) should have an icon")
        }
    }

    func testAttackTypeCodable() throws {
        let type = AttackType.smbExploit
        let data = try JSONEncoder().encode(type)
        let decoded = try JSONDecoder().decode(AttackType.self, from: data)

        XCTAssertEqual(decoded, .smbExploit)
    }

    // MARK: - ScanResults Tests

    func testScanResultsInit() {
        let results = ScanResults()

        XCTAssertTrue(results.devices.isEmpty)
        XCTAssertEqual(results.totalVulnerabilities, 0)
        XCTAssertEqual(results.criticalCount, 0)
        XCTAssertEqual(results.highCount, 0)
        XCTAssertEqual(results.mediumCount, 0)
        XCTAssertEqual(results.lowCount, 0)
        XCTAssertTrue(results.networkCIDR.isEmpty)
        XCTAssertTrue(results.attackResults.isEmpty)
    }

    func testScanResultsCodable() throws {
        var results = ScanResults()
        results.networkCIDR = "192.168.1.0/24"
        results.totalVulnerabilities = 5
        results.criticalCount = 1
        results.highCount = 2

        let data = try JSONEncoder().encode(results)
        let decoded = try JSONDecoder().decode(ScanResults.self, from: data)

        XCTAssertEqual(decoded.networkCIDR, "192.168.1.0/24")
        XCTAssertEqual(decoded.totalVulnerabilities, 5)
        XCTAssertEqual(decoded.criticalCount, 1)
        XCTAssertEqual(decoded.highCount, 2)
    }
}
