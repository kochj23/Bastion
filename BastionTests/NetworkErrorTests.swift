//
//  NetworkErrorTests.swift
//  BastionTests
//
//  Tests for network error types and CVE database error handling
//  Author: Jordan Koch
//  Date: 2026-05-01
//

import XCTest
@testable import Bastion

final class NetworkErrorTests: XCTestCase {

    // MARK: - NetworkError Tests

    func testInvalidCIDRError() {
        let error = NetworkError.invalidCIDR
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("CIDR"))
    }

    func testScanFailedError() {
        let error = NetworkError.scanFailed
        XCTAssertNotNil(error.errorDescription)
    }

    func testTimeoutError() {
        let error = NetworkError.timeoutError
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("timeout"))
    }

    // MARK: - CVEDatabaseError Tests

    func testCVEInvalidURLError() {
        let error = CVEDatabaseError.invalidURL
        XCTAssertNotNil(error.errorDescription)
    }

    func testCVEDownloadFailedError() {
        let error = CVEDatabaseError.downloadFailed("HTTP 404")
        XCTAssertNotNil(error.errorDescription)
    }

    func testCVEParseError() {
        let error = CVEDatabaseError.parseError
        XCTAssertNotNil(error.errorDescription)
    }

    func testCVEDecompressError() {
        let error = CVEDatabaseError.decompressError
        XCTAssertNotNil(error.errorDescription)
    }

    // MARK: - CVEMetadata Tests

    func testCVEMetadataCodable() throws {
        let metadata = CVEMetadata(totalCVEs: 250000, lastUpdate: Date())

        let data = try JSONEncoder().encode(metadata)
        let decoded = try JSONDecoder().decode(CVEMetadata.self, from: data)

        XCTAssertEqual(decoded.totalCVEs, 250000)
        XCTAssertNotNil(decoded.lastUpdate)
    }
}
