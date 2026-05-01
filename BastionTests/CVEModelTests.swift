//
//  CVEModelTests.swift
//  BastionTests
//
//  Unit tests for CVE, Vulnerability, and VulnerabilitySeverity models
//  Author: Jordan Koch
//  Date: 2026-05-01
//

import XCTest
@testable import Bastion

final class CVEModelTests: XCTestCase {

    // MARK: - CVE Initialization

    func testCVEInitBasic() {
        let cve = CVE(id: "CVE-2024-1234", description: "Test vulnerability", cvssScore: 7.5)

        XCTAssertEqual(cve.id, "CVE-2024-1234")
        XCTAssertEqual(cve.description, "Test vulnerability")
        XCTAssertEqual(cve.cvssScore, 7.5)
        XCTAssertNil(cve.cvssVector)
        XCTAssertTrue(cve.affectedProducts.isEmpty)
        XCTAssertTrue(cve.references.isEmpty)
        XCTAssertFalse(cve.exploitAvailable)
        XCTAssertNil(cve.cweId)
    }

    // MARK: - Severity From Score

    func testSeverityCriticalScore() {
        XCTAssertEqual(CVE.severityFromScore(10.0), .critical)
        XCTAssertEqual(CVE.severityFromScore(9.0), .critical)
        XCTAssertEqual(CVE.severityFromScore(9.5), .critical)
    }

    func testSeverityHighScore() {
        XCTAssertEqual(CVE.severityFromScore(8.9), .high)
        XCTAssertEqual(CVE.severityFromScore(7.0), .high)
        XCTAssertEqual(CVE.severityFromScore(7.5), .high)
    }

    func testSeverityMediumScore() {
        XCTAssertEqual(CVE.severityFromScore(6.9), .medium)
        XCTAssertEqual(CVE.severityFromScore(4.0), .medium)
        XCTAssertEqual(CVE.severityFromScore(5.5), .medium)
    }

    func testSeverityLowScore() {
        XCTAssertEqual(CVE.severityFromScore(3.9), .low)
        XCTAssertEqual(CVE.severityFromScore(0.1), .low)
        XCTAssertEqual(CVE.severityFromScore(1.0), .low)
    }

    func testSeverityInformationalScore() {
        XCTAssertEqual(CVE.severityFromScore(0.0), .informational)
        XCTAssertEqual(CVE.severityFromScore(-1.0), .informational)
    }

    func testCVESeverityAutoSet() {
        let criticalCVE = CVE(id: "CVE-2024-0001", description: "Critical", cvssScore: 10.0)
        XCTAssertEqual(criticalCVE.severity, .critical)

        let highCVE = CVE(id: "CVE-2024-0002", description: "High", cvssScore: 8.0)
        XCTAssertEqual(highCVE.severity, .high)

        let mediumCVE = CVE(id: "CVE-2024-0003", description: "Medium", cvssScore: 5.0)
        XCTAssertEqual(mediumCVE.severity, .medium)
    }

    // MARK: - CVE Codable

    func testCVECodableRoundTrip() throws {
        var cve = CVE(id: "CVE-2021-44228", description: "Log4Shell", cvssScore: 10.0)
        cve.cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        cve.affectedProducts = ["log4j-core"]
        cve.exploitAvailable = true
        cve.cweId = "CWE-502"

        let data = try JSONEncoder().encode(cve)
        let decoded = try JSONDecoder().decode(CVE.self, from: data)

        XCTAssertEqual(decoded.id, "CVE-2021-44228")
        XCTAssertEqual(decoded.cvssScore, 10.0)
        XCTAssertEqual(decoded.cvssVector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        XCTAssertTrue(decoded.exploitAvailable)
        XCTAssertEqual(decoded.cweId, "CWE-502")
        XCTAssertEqual(decoded.affectedProducts, ["log4j-core"])
    }

    // MARK: - Vulnerability Tests

    func testVulnerabilityInit() {
        let vuln = Vulnerability(title: "SQL Injection", description: "Input not sanitized", severity: .high, cveId: "CVE-2024-5678")

        XCTAssertEqual(vuln.title, "SQL Injection")
        XCTAssertEqual(vuln.description, "Input not sanitized")
        XCTAssertEqual(vuln.severity, .high)
        XCTAssertEqual(vuln.cveId, "CVE-2024-5678")
        XCTAssertNil(vuln.cvssScore)
        XCTAssertFalse(vuln.exploitAvailable)
        XCTAssertNil(vuln.proofOfConcept)
        XCTAssertNil(vuln.remediation)
    }

    func testVulnerabilityInitWithoutCVE() {
        let vuln = Vulnerability(title: "Weak Auth", description: "Default password", severity: .critical)

        XCTAssertNil(vuln.cveId)
    }

    func testVulnerabilityCodable() throws {
        let vuln = Vulnerability(title: "XSS", description: "Reflected XSS", severity: .medium, cveId: "CVE-2024-9999")

        let data = try JSONEncoder().encode(vuln)
        let decoded = try JSONDecoder().decode(Vulnerability.self, from: data)

        XCTAssertEqual(decoded.title, "XSS")
        XCTAssertEqual(decoded.severity, .medium)
        XCTAssertEqual(decoded.cveId, "CVE-2024-9999")
    }

    // MARK: - VulnerabilitySeverity Tests

    func testSeverityWeight() {
        XCTAssertEqual(VulnerabilitySeverity.critical.weight, 5)
        XCTAssertEqual(VulnerabilitySeverity.high.weight, 4)
        XCTAssertEqual(VulnerabilitySeverity.medium.weight, 3)
        XCTAssertEqual(VulnerabilitySeverity.low.weight, 2)
        XCTAssertEqual(VulnerabilitySeverity.informational.weight, 1)
    }

    func testSeverityAllCases() {
        XCTAssertEqual(VulnerabilitySeverity.allCases.count, 5)
    }

    func testSeverityColors() {
        XCTAssertFalse(VulnerabilitySeverity.critical.color.isEmpty)
        XCTAssertFalse(VulnerabilitySeverity.high.color.isEmpty)
        XCTAssertFalse(VulnerabilitySeverity.medium.color.isEmpty)
        XCTAssertFalse(VulnerabilitySeverity.low.color.isEmpty)
        XCTAssertFalse(VulnerabilitySeverity.informational.color.isEmpty)
    }

    func testSeverityRawValues() {
        XCTAssertEqual(VulnerabilitySeverity.critical.rawValue, "Critical")
        XCTAssertEqual(VulnerabilitySeverity.high.rawValue, "High")
        XCTAssertEqual(VulnerabilitySeverity.medium.rawValue, "Medium")
        XCTAssertEqual(VulnerabilitySeverity.low.rawValue, "Low")
        XCTAssertEqual(VulnerabilitySeverity.informational.rawValue, "Info")
    }
}
