//
//  LateralMovementTests.swift
//  BastionTests
//
//  Tests for lateral movement data models and trust relationships
//  Author: Jordan Koch
//  Date: 2026-05-01
//

import XCTest
@testable import Bastion

final class LateralMovementTests: XCTestCase {

    // MARK: - TrustType Tests

    func testTrustTypeAllCases() {
        XCTAssertEqual(TrustType.allCases.count, 8)
    }

    func testTrustTypeRawValues() {
        XCTAssertEqual(TrustType.sshKeyReuse.rawValue, "SSH Key Reuse")
        XCTAssertEqual(TrustType.sharedCredentials.rawValue, "Shared Credentials")
        XCTAssertEqual(TrustType.noSegmentation.rawValue, "No Network Segmentation")
        XCTAssertEqual(TrustType.sameDomain.rawValue, "Same AD Domain")
    }

    // MARK: - MovementPath Tests

    func testMovementPathIsMultiHop() {
        let device1 = Device(ipAddress: "192.168.1.10")
        let device2 = Device(ipAddress: "192.168.1.20")
        let device3 = Device(ipAddress: "192.168.1.30")

        let trust = TrustRelationship(
            sourceDevice: device1, targetDevice: device2,
            trustType: .sshKeyReuse, confidence: 60,
            description: "SSH key shared"
        )

        let multiHopPath = MovementPath(
            steps: [
                MovementStep(device: device1, action: "Compromise"),
                MovementStep(device: device2, action: "Pivot"),
                MovementStep(device: device3, action: "Final target")
            ],
            trustBasis: trust,
            totalProbability: 40.0,
            description: "Multi-hop path"
        )

        XCTAssertTrue(multiHopPath.isMultiHop)
        XCTAssertEqual(multiHopPath.steps.count, 3)
    }

    func testMovementPathSingleHop() {
        let device1 = Device(ipAddress: "192.168.1.10")
        let device2 = Device(ipAddress: "192.168.1.20")

        let trust = TrustRelationship(
            sourceDevice: device1, targetDevice: device2,
            trustType: .noSegmentation, confidence: 90,
            description: "Same subnet"
        )

        let singleHopPath = MovementPath(
            steps: [
                MovementStep(device: device1, action: "Compromise"),
                MovementStep(device: device2, action: "Access target")
            ],
            trustBasis: trust,
            totalProbability: 80.0,
            description: "Single hop"
        )

        XCTAssertFalse(singleHopPath.isMultiHop)
    }

    func testMovementPathTargetDevice() {
        let device1 = Device(ipAddress: "192.168.1.10")
        let device2 = Device(ipAddress: "192.168.1.20")

        let trust = TrustRelationship(
            sourceDevice: device1, targetDevice: device2,
            trustType: .sshKeyReuse, confidence: 50,
            description: "Test"
        )

        let path = MovementPath(
            steps: [
                MovementStep(device: device1, action: "Start"),
                MovementStep(device: device2, action: "End")
            ],
            trustBasis: trust,
            totalProbability: 50.0,
            description: "Test path"
        )

        XCTAssertEqual(path.targetDevice?.ipAddress, "192.168.1.20")
    }

    // MARK: - LateralMovementMap Tests

    func testCriticalPathsFilter() {
        let device1 = Device(ipAddress: "192.168.1.10")
        let device2 = Device(ipAddress: "192.168.1.20")

        let trust = TrustRelationship(
            sourceDevice: device1, targetDevice: device2,
            trustType: .noSegmentation, confidence: 90,
            description: "No segmentation"
        )

        let criticalPath = MovementPath(
            steps: [MovementStep(device: device1, action: "A"), MovementStep(device: device2, action: "B")],
            trustBasis: trust,
            totalProbability: 80.0,
            description: "Critical"
        )

        let lowPath = MovementPath(
            steps: [MovementStep(device: device1, action: "C"), MovementStep(device: device2, action: "D")],
            trustBasis: trust,
            totalProbability: 30.0,
            description: "Low"
        )

        let map = LateralMovementMap(paths: [criticalPath, lowPath], trustRelationships: [trust])

        XCTAssertEqual(map.criticalPaths.count, 1)
        XCTAssertEqual(map.criticalPaths.first?.totalProbability, 80.0)
    }

    func testMultiHopPathsFilter() {
        let d1 = Device(ipAddress: "192.168.1.10")
        let d2 = Device(ipAddress: "192.168.1.20")
        let d3 = Device(ipAddress: "192.168.1.30")

        let trust = TrustRelationship(sourceDevice: d1, targetDevice: d2, trustType: .sshKeyReuse, confidence: 60, description: "Test")

        let twoHop = MovementPath(
            steps: [MovementStep(device: d1, action: "A"), MovementStep(device: d2, action: "B")],
            trustBasis: trust, totalProbability: 50.0, description: "Two hop"
        )

        let threeHop = MovementPath(
            steps: [
                MovementStep(device: d1, action: "A"),
                MovementStep(device: d2, action: "B"),
                MovementStep(device: d3, action: "C")
            ],
            trustBasis: trust, totalProbability: 30.0, description: "Three hop"
        )

        let map = LateralMovementMap(paths: [twoHop, threeHop], trustRelationships: [trust])

        XCTAssertEqual(map.multiHopPaths.count, 1)
    }

    // MARK: - TrustRelationship Tests

    func testTrustRelationshipProperties() {
        let source = Device(ipAddress: "192.168.1.10")
        let target = Device(ipAddress: "192.168.1.20")

        let trust = TrustRelationship(
            sourceDevice: source,
            targetDevice: target,
            trustType: .sharedCredentials,
            confidence: 70,
            description: "Same device type with shared admin password"
        )

        XCTAssertEqual(trust.sourceDevice.ipAddress, "192.168.1.10")
        XCTAssertEqual(trust.targetDevice.ipAddress, "192.168.1.20")
        XCTAssertEqual(trust.trustType, .sharedCredentials)
        XCTAssertEqual(trust.confidence, 70)
    }
}
