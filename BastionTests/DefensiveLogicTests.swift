//
//  DefensiveLogicTests.swift
//  BastionTests
//
//  Coverage for previously-untested deterministic defensive logic:
//  IPv6 local-network enforcement, CIDR input validation, banner->OS
//  fingerprint heuristics, and MITRE ATT&CK Navigator severity scoring.
//
//  These tests exercise ONLY pure parsing/scoring/validation code paths.
//  No exploit execution, no real network scanning, no credential attacks.
//
//  Author: Jordan Koch
//  Date: 2026-08-18
//

import XCTest
@testable import Bastion

// MARK: - SafetyValidator IPv6 Enforcement
//
// Existing SafetyValidatorTests only cover IPv4 (RFC 1918). The IPv6
// private-range path (isLocalIPv6) was entirely untested.

final class SafetyValidatorIPv6Tests: XCTestCase {

    let validator = SafetyValidator.shared

    func testIPv6LoopbackIsLocal() {
        XCTAssertTrue(validator.isLocalIP("::1"))
    }

    func testIPv6LinkLocalIsLocal() {
        // fe80::/10 link-local, including uppercase (normalized internally)
        XCTAssertTrue(validator.isLocalIP("fe80::1"))
        XCTAssertTrue(validator.isLocalIP("FE80::abcd:1234"))
    }

    func testIPv6UniqueLocalIsLocal() {
        // fc00::/7 (fc.. and fd.. prefixes)
        XCTAssertTrue(validator.isLocalIP("fd00::1"))
        XCTAssertTrue(validator.isLocalIP("fc00::1"))
    }

    func testIPv6PublicIsBlocked() {
        // Public / global-unicast IPv6 must NOT be treated as local.
        XCTAssertFalse(validator.isLocalIP("2001:4860:4860::8888")) // Google DNS
        XCTAssertFalse(validator.isLocalIP("2606:4700:4700::1111")) // Cloudflare DNS
    }

    func testValidateTargetAcceptsLocalIPv6() {
        XCTAssertNoThrow(try validator.validateTarget("::1"))
        XCTAssertNoThrow(try validator.validateTarget("fe80::1"))
        XCTAssertNoThrow(try validator.validateTarget("fd12:3456::abcd"))
    }

    func testValidateTargetRejectsPublicIPv6() {
        XCTAssertThrowsError(try validator.validateTarget("2001:4860:4860::8888")) { error in
            guard case BastionError.publicIPNotAllowed? = error as? BastionError else {
                XCTFail("Expected publicIPNotAllowed for public IPv6")
                return
            }
        }
    }
}

// MARK: - NetworkScanner CIDR Input Validation
//
// parseCIDR is private, but structurally-invalid CIDR strings are rejected
// (NetworkError.invalidCIDR) before any scanning begins. These tests only
// use inputs that THROW during parsing, so no hosts are ever contacted.

@MainActor
final class NetworkScannerCIDRValidationTests: XCTestCase {

    func testMissingMaskThrows() async {
        let scanner = NetworkScanner()
        do {
            try await scanner.scanNetwork(cidr: "192.168.1.0")
            XCTFail("Expected invalidCIDR for missing mask")
        } catch NetworkError.invalidCIDR {
            // expected
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
        XCTAssertTrue(scanner.discoveredDevices.isEmpty)
    }

    func testNonNumericMaskThrows() async {
        let scanner = NetworkScanner()
        do {
            try await scanner.scanNetwork(cidr: "192.168.1.0/xx")
            XCTFail("Expected invalidCIDR for non-numeric mask")
        } catch NetworkError.invalidCIDR {
            // expected
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testTooFewOctetsThrows() async {
        let scanner = NetworkScanner()
        do {
            try await scanner.scanNetwork(cidr: "192.168.1/24")
            XCTFail("Expected invalidCIDR for 3-octet base")
        } catch NetworkError.invalidCIDR {
            // expected
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testEmptyStringThrows() async {
        let scanner = NetworkScanner()
        do {
            try await scanner.scanNetwork(cidr: "")
            XCTFail("Expected invalidCIDR for empty string")
        } catch NetworkError.invalidCIDR {
            // expected
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testInvalidCIDRErrorMessageIsDescriptive() {
        // The user-facing error should guide the user to the correct format.
        let message = NetworkError.invalidCIDR.errorDescription
        XCTAssertNotNil(message)
        XCTAssertTrue(message?.contains("192.168.1.0/24") ?? false,
                      "invalidCIDR message should show the expected format")
    }
}

// MARK: - ServiceFingerprinter OS Heuristics
//
// detectOS maps SSH banner substrings to an operating-system label. Pure
// string inspection of an in-memory Device; no sockets are opened.

@MainActor
final class ServiceFingerprinterOSTests: XCTestCase {

    var fingerprinter: ServiceFingerprinter!

    override func setUp() {
        super.setUp()
        fingerprinter = ServiceFingerprinter()
    }

    private func device(sshBanner: String?) -> Device {
        var device = Device(ipAddress: "192.168.1.20")
        var port = OpenPort(port: 22)
        port.service = sshBanner
        device.openPorts = [port]
        return device
    }

    func testUbuntuBannerDetected() async {
        let os = await fingerprinter.detectOS(device: device(sshBanner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"))
        XCTAssertEqual(os, "Ubuntu Linux")
    }

    func testDebianBannerDetected() async {
        let os = await fingerprinter.detectOS(device: device(sshBanner: "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"))
        XCTAssertEqual(os, "Debian Linux")
    }

    func testRaspberryPiBannerDetected() async {
        let os = await fingerprinter.detectOS(device: device(sshBanner: "SSH-2.0-OpenSSH_7.9 raspberry pi node"))
        XCTAssertEqual(os, "Raspberry Pi OS")
    }

    func testUnknownSSHBannerReturnsNil() async {
        let os = await fingerprinter.detectOS(device: device(sshBanner: "SSH-2.0-OpenSSH_9.0"))
        XCTAssertNil(os)
    }

    func testNoSSHServiceReturnsNil() async {
        var device = Device(ipAddress: "192.168.1.21")
        device.openPorts = [OpenPort(port: 80), OpenPort(port: 443)]
        let os = await fingerprinter.detectOS(device: device)
        XCTAssertNil(os)
    }

    func testNoOpenPortsReturnsNil() async {
        let os = await fingerprinter.detectOS(device: Device(ipAddress: "192.168.1.22"))
        XCTAssertNil(os)
    }
}

// MARK: - MITRE ATT&CK Navigator Severity Scoring
//
// exportNavigatorJSON assigns a heatmap score per technique severity
// (critical=100, high=75, medium=50, else=25). This scoring was untested.

@MainActor
final class MITRENavigatorScoreTests: XCTestCase {

    var mapper: MITREATTACKMapper!

    override func setUp() {
        super.setUp()
        mapper = MITREATTACKMapper()
    }

    func testCriticalTechniqueScores100() {
        var device = Device(ipAddress: "192.168.1.30")
        device.vulnerabilities = [
            Vulnerability(title: "Default Credentials Found",
                          description: "admin/admin accepted",
                          severity: .critical)
        ]
        let report = mapper.mapToATTACK(devices: [device], attackResults: [])
        let json = mapper.exportNavigatorJSON(report: report)

        XCTAssertTrue(json.contains("\"techniqueID\": \"T1078\""),
                      "Default credentials should map to T1078 Valid Accounts")
        XCTAssertTrue(json.contains("\"score\": 100"),
                      "Critical technique should score 100 in Navigator JSON")
    }

    func testHighTechniqueScores75() {
        var device = Device(ipAddress: "192.168.1.31")
        device.openPorts = [OpenPort(port: 445)] // SMB -> T1021.002 (high)
        let report = mapper.mapToATTACK(devices: [device], attackResults: [])
        let json = mapper.exportNavigatorJSON(report: report)

        XCTAssertTrue(json.contains("\"techniqueID\": \"T1021.002\""))
        XCTAssertTrue(json.contains("\"score\": 75"),
                      "High technique should score 75")
    }

    func testMediumAndInformationalScores() {
        var device = Device(ipAddress: "192.168.1.32")
        device.openPorts = [OpenPort(port: 22)] // SSH -> T1021.004 (medium) + T1046 (info)
        let report = mapper.mapToATTACK(devices: [device], attackResults: [])
        let json = mapper.exportNavigatorJSON(report: report)

        XCTAssertTrue(json.contains("\"score\": 50"),
                      "Medium SSH technique should score 50")
        XCTAssertTrue(json.contains("\"score\": 25"),
                      "Informational discovery technique should score 25")
    }

    func testNavigatorJSONIsWellFormed() {
        var device = Device(ipAddress: "192.168.1.33")
        device.openPorts = [OpenPort(port: 22), OpenPort(port: 445)]
        let report = mapper.mapToATTACK(devices: [device], attackResults: [])
        let json = mapper.exportNavigatorJSON(report: report)

        guard let data = json.data(using: .utf8) else {
            XCTFail("JSON string not UTF-8 encodable")
            return
        }
        XCTAssertNoThrow(try JSONSerialization.jsonObject(with: data),
                         "exportNavigatorJSON must emit parseable JSON")
        XCTAssertTrue(json.contains("\"domain\": \"enterprise-attack\""))
    }

    func testEmptyInputProducesNoTechniques() {
        let report = mapper.mapToATTACK(devices: [], attackResults: [])
        XCTAssertTrue(report.techniques.isEmpty)
        XCTAssertEqual(report.devicesAnalyzed, 0)
    }
}
