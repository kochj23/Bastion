//
//  DeviceModelTests.swift
//  BastionTests
//
//  Unit tests for Device, OpenPort, ServiceInfo, and related models
//  Author: Jordan Koch
//  Date: 2026-05-01
//

import XCTest
@testable import Bastion

final class DeviceModelTests: XCTestCase {

    // MARK: - Device Initialization

    func testDeviceInitWithIPOnly() {
        let device = Device(ipAddress: "192.168.1.10")

        XCTAssertEqual(device.ipAddress, "192.168.1.10")
        XCTAssertNil(device.hostname)
        XCTAssertNil(device.macAddress)
        XCTAssertNil(device.manufacturer)
        XCTAssertNil(device.operatingSystem)
        XCTAssertEqual(device.deviceType, .unknown)
        XCTAssertTrue(device.openPorts.isEmpty)
        XCTAssertTrue(device.services.isEmpty)
        XCTAssertTrue(device.vulnerabilities.isEmpty)
        XCTAssertEqual(device.securityScore, 100)
        XCTAssertTrue(device.isOnline)
    }

    func testDeviceInitWithHostname() {
        let device = Device(ipAddress: "10.0.0.1", hostname: "gateway.local")

        XCTAssertEqual(device.ipAddress, "10.0.0.1")
        XCTAssertEqual(device.hostname, "gateway.local")
    }

    func testDeviceInitWithMAC() {
        let testMAC = "test-mac-address"
        let device = Device(ipAddress: "192.168.1.50", macAddress: testMAC)

        XCTAssertEqual(device.macAddress, testMAC)
    }

    // MARK: - Display Name

    func testDisplayNameUsesHostnameWhenAvailable() {
        let device = Device(ipAddress: "192.168.1.10", hostname: "server.local")

        XCTAssertEqual(device.displayName, "server.local")
    }

    func testDisplayNameFallsBackToIP() {
        let device = Device(ipAddress: "192.168.1.10")

        XCTAssertEqual(device.displayName, "192.168.1.10")
    }

    // MARK: - Vulnerability Counting

    func testVulnerabilityCountsEmpty() {
        let device = Device(ipAddress: "192.168.1.1")

        XCTAssertEqual(device.criticalVulnCount, 0)
        XCTAssertEqual(device.highVulnCount, 0)
        XCTAssertEqual(device.mediumVulnCount, 0)
        XCTAssertEqual(device.lowVulnCount, 0)
    }

    func testVulnerabilityCountsMixed() {
        var device = Device(ipAddress: "192.168.1.1")
        device.vulnerabilities = [
            Vulnerability(title: "Critical RCE", description: "Remote code execution", severity: .critical),
            Vulnerability(title: "High SQLi", description: "SQL injection", severity: .high),
            Vulnerability(title: "High XSS", description: "Cross-site scripting", severity: .high),
            Vulnerability(title: "Medium Info", description: "Info disclosure", severity: .medium),
            Vulnerability(title: "Low Header", description: "Missing header", severity: .low),
            Vulnerability(title: "Low Cookie", description: "Cookie issue", severity: .low),
            Vulnerability(title: "Low Config", description: "Config issue", severity: .low),
        ]

        XCTAssertEqual(device.criticalVulnCount, 1)
        XCTAssertEqual(device.highVulnCount, 2)
        XCTAssertEqual(device.mediumVulnCount, 1)
        XCTAssertEqual(device.lowVulnCount, 3)
    }

    // MARK: - Risk Level

    func testRiskLevelCritical() {
        var device = Device(ipAddress: "192.168.1.1")
        device.vulnerabilities = [
            Vulnerability(title: "RCE", description: "Remote code execution", severity: .critical)
        ]

        XCTAssertEqual(device.riskLevel, .critical)
    }

    func testRiskLevelHigh() {
        var device = Device(ipAddress: "192.168.1.1")
        device.vulnerabilities = [
            Vulnerability(title: "SQLi", description: "SQL injection", severity: .high)
        ]

        XCTAssertEqual(device.riskLevel, .high)
    }

    func testRiskLevelMedium() {
        var device = Device(ipAddress: "192.168.1.1")
        device.vulnerabilities = [
            Vulnerability(title: "Info", description: "Info disclosure", severity: .medium)
        ]

        XCTAssertEqual(device.riskLevel, .medium)
    }

    func testRiskLevelLowWhenNoVulns() {
        let device = Device(ipAddress: "192.168.1.1")

        XCTAssertEqual(device.riskLevel, .low)
    }

    // MARK: - Security Score

    func testSecurityScorePerfectWhenClean() {
        var device = Device(ipAddress: "192.168.1.1")
        device.updateSecurityScore()

        XCTAssertEqual(device.securityScore, 100)
    }

    func testSecurityScoreDeductsCritical() {
        var device = Device(ipAddress: "192.168.1.1")
        device.vulnerabilities = [
            Vulnerability(title: "RCE", description: "RCE", severity: .critical)
        ]
        device.updateSecurityScore()

        XCTAssertEqual(device.securityScore, 80) // 100 - 20
    }

    func testSecurityScoreDeductsHigh() {
        var device = Device(ipAddress: "192.168.1.1")
        device.vulnerabilities = [
            Vulnerability(title: "SQLi", description: "SQLi", severity: .high)
        ]
        device.updateSecurityScore()

        XCTAssertEqual(device.securityScore, 90) // 100 - 10
    }

    func testSecurityScoreFloorAtZero() {
        var device = Device(ipAddress: "192.168.1.1")
        // Add enough criticals to exceed 100 deduction (6 * 20 = 120)
        device.vulnerabilities = (0..<6).map { _ in
            Vulnerability(title: "RCE", description: "RCE", severity: .critical)
        }
        device.updateSecurityScore()

        XCTAssertEqual(device.securityScore, 0)
    }

    func testSecurityScoreMixedDeductions() {
        var device = Device(ipAddress: "192.168.1.1")
        device.vulnerabilities = [
            Vulnerability(title: "A", description: "A", severity: .critical),  // -20
            Vulnerability(title: "B", description: "B", severity: .high),      // -10
            Vulnerability(title: "C", description: "C", severity: .medium),    // -5
            Vulnerability(title: "D", description: "D", severity: .low),       // -2
        ]
        device.updateSecurityScore()

        XCTAssertEqual(device.securityScore, 63) // 100 - 20 - 10 - 5 - 2
    }

    // MARK: - Codable Conformance

    func testDeviceCodableRoundTrip() throws {
        var device = Device(ipAddress: "192.168.1.100", hostname: "server.local")
        device.operatingSystem = "Linux"
        device.deviceType = .server
        device.openPorts = [OpenPort(port: 22), OpenPort(port: 80)]

        let encoder = JSONEncoder()
        let data = try encoder.encode(device)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(Device.self, from: data)

        XCTAssertEqual(decoded.ipAddress, "192.168.1.100")
        XCTAssertEqual(decoded.hostname, "server.local")
        XCTAssertEqual(decoded.operatingSystem, "Linux")
        XCTAssertEqual(decoded.deviceType, .server)
        XCTAssertEqual(decoded.openPorts.count, 2)
    }

    // MARK: - OpenPort Tests

    func testOpenPortInit() {
        let port = OpenPort(port: 443)

        XCTAssertEqual(port.port, 443)
        XCTAssertEqual(port.portProtocol, .tcp)
        XCTAssertEqual(port.state, .open)
        XCTAssertNil(port.service)
        XCTAssertNil(port.version)
    }

    func testOpenPortUDPProtocol() {
        let port = OpenPort(port: 53, portProtocol: .udp)

        XCTAssertEqual(port.portProtocol, .udp)
    }

    // MARK: - ServiceInfo Tests

    func testServiceInfoInit() {
        let service = ServiceInfo(name: "SSH", version: "8.9p1", port: 22)

        XCTAssertEqual(service.name, "SSH")
        XCTAssertEqual(service.version, "8.9p1")
        XCTAssertEqual(service.port, 22)
        XCTAssertNil(service.banner)
        XCTAssertTrue(service.cpes.isEmpty)
    }

    func testServiceInfoDisplayVersionWithVersion() {
        let service = ServiceInfo(name: "Apache", version: "2.4.52", port: 80)

        XCTAssertEqual(service.displayVersion, "Apache 2.4.52")
    }

    func testServiceInfoDisplayVersionWithoutVersion() {
        let service = ServiceInfo(name: "SSH", port: 22)

        XCTAssertEqual(service.displayVersion, "SSH")
    }

    // MARK: - DeviceType Tests

    func testDeviceTypeIcons() {
        XCTAssertEqual(DeviceType.router.icon, "wifi.router")
        XCTAssertEqual(DeviceType.server.icon, "server.rack")
        XCTAssertEqual(DeviceType.workstation.icon, "desktopcomputer")
        XCTAssertEqual(DeviceType.unknown.icon, "questionmark.circle")
    }

    // MARK: - RiskLevel Tests

    func testRiskLevelRawValues() {
        XCTAssertEqual(RiskLevel.low.rawValue, "Low")
        XCTAssertEqual(RiskLevel.medium.rawValue, "Medium")
        XCTAssertEqual(RiskLevel.high.rawValue, "High")
        XCTAssertEqual(RiskLevel.critical.rawValue, "Critical")
    }
}
