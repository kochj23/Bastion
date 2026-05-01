//
//  SafetyValidatorTests.swift
//  BastionTests
//
//  Security tests for SafetyValidator: IP validation, rate limiting, RFC 1918 enforcement
//  Author: Jordan Koch
//  Date: 2026-05-01
//

import XCTest
@testable import Bastion

final class SafetyValidatorTests: XCTestCase {

    let validator = SafetyValidator.shared

    // MARK: - Local IP Validation (RFC 1918)

    func testPrivateClass192168() {
        XCTAssertTrue(validator.isLocalIP("192.168.0.1"))
        XCTAssertTrue(validator.isLocalIP("192.168.1.1"))
        XCTAssertTrue(validator.isLocalIP("192.168.1.254"))
        XCTAssertTrue(validator.isLocalIP("192.168.255.255"))
        XCTAssertTrue(validator.isLocalIP("192.168.0.0"))
    }

    func testPrivateClass10() {
        XCTAssertTrue(validator.isLocalIP("10.0.0.1"))
        XCTAssertTrue(validator.isLocalIP("10.10.10.10"))
        XCTAssertTrue(validator.isLocalIP("10.255.255.254"))
    }

    func testPrivateClass172() {
        XCTAssertTrue(validator.isLocalIP("172.16.0.1"))
        XCTAssertTrue(validator.isLocalIP("172.20.5.10"))
        XCTAssertTrue(validator.isLocalIP("172.31.255.254"))
    }

    func testPrivateClass172Boundaries() {
        // 172.15.x.x is NOT private
        XCTAssertFalse(validator.isLocalIP("172.15.0.1"))
        // 172.32.x.x is NOT private
        XCTAssertFalse(validator.isLocalIP("172.32.0.1"))
    }

    func testLocalhost() {
        XCTAssertTrue(validator.isLocalIP("127.0.0.1"))
        XCTAssertTrue(validator.isLocalIP("127.0.0.0"))
        XCTAssertTrue(validator.isLocalIP("127.255.255.255"))
    }

    // MARK: - Public IP Blocking (CRITICAL SECURITY)

    func testBlocksPublicIPs() {
        XCTAssertFalse(validator.isLocalIP("8.8.8.8"))
        XCTAssertFalse(validator.isLocalIP("1.1.1.1"))
        XCTAssertFalse(validator.isLocalIP("142.250.80.46"))
        XCTAssertFalse(validator.isLocalIP("151.101.1.140"))
        XCTAssertFalse(validator.isLocalIP("216.58.214.206"))
    }

    func testBlocksPublicIPBoundaries() {
        // Just outside private ranges
        XCTAssertFalse(validator.isLocalIP("192.167.1.1"))
        XCTAssertFalse(validator.isLocalIP("192.169.1.1"))
        XCTAssertFalse(validator.isLocalIP("11.0.0.1"))
        XCTAssertFalse(validator.isLocalIP("9.0.0.1"))
    }

    // MARK: - Invalid IP Handling

    func testInvalidIPFormats() {
        XCTAssertFalse(validator.isLocalIP(""))
        XCTAssertFalse(validator.isLocalIP("invalid"))
        XCTAssertFalse(validator.isLocalIP("192.168.1"))
        XCTAssertFalse(validator.isLocalIP("192.168.1.1.1"))
        XCTAssertFalse(validator.isLocalIP("abc.def.ghi.jkl"))
    }

    // MARK: - validateTarget Throws for Public IPs

    func testValidateTargetAcceptsLocalIP() {
        XCTAssertNoThrow(try validator.validateTarget("192.168.1.1"))
        XCTAssertNoThrow(try validator.validateTarget("10.0.0.1"))
        XCTAssertNoThrow(try validator.validateTarget("172.16.0.1"))
    }

    func testValidateTargetRejectsPublicIP() {
        XCTAssertThrowsError(try validator.validateTarget("8.8.8.8")) { error in
            guard let bastionError = error as? BastionError else {
                XCTFail("Expected BastionError")
                return
            }
            if case .publicIPNotAllowed(let message) = bastionError {
                XCTAssertTrue(message.contains("ILLEGAL"), "Should mention illegal operation")
                XCTAssertTrue(message.contains("8.8.8.8"), "Should include the blocked IP")
            } else {
                XCTFail("Expected publicIPNotAllowed error")
            }
        }
    }

    func testValidateTargetRejectsGoogleDNS() {
        XCTAssertThrowsError(try validator.validateTarget("8.8.4.4"))
    }

    func testValidateTargetRejectsCloudflare() {
        XCTAssertThrowsError(try validator.validateTarget("1.1.1.1"))
    }

    // MARK: - Rate Limiting

    func testRateLimitAllowsNormalTraffic() {
        // Should not throw for reasonable number of requests
        for _ in 0..<5 {
            XCTAssertNoThrow(try validator.checkRateLimit())
        }
    }

    // MARK: - BastionError Tests

    func testBastionErrorDescriptions() {
        let publicError = BastionError.publicIPNotAllowed("Test message")
        XCTAssertEqual(publicError.errorDescription, "Test message")

        let rateError = BastionError.rateLimitExceeded("Rate limited")
        XCTAssertEqual(rateError.errorDescription, "Rate limited")

        let authError = BastionError.unauthorizedTarget
        XCTAssertNotNil(authError.errorDescription)

        let legalError = BastionError.legalNotAccepted
        XCTAssertNotNil(legalError.errorDescription)
    }
}
