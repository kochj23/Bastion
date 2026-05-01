//
//  AIBackendTests.swift
//  BastionTests
//
//  Tests for AI backend configuration, error handling, and enum completeness
//  Author: Jordan Koch
//  Date: 2026-05-01
//

import XCTest
@testable import Bastion

final class AIBackendTests: XCTestCase {

    // MARK: - AIBackend Enum

    func testAllBackendCases() {
        let allCases = AIBackend.allCases
        XCTAssertEqual(allCases.count, 6)
        XCTAssertTrue(allCases.contains(.ollama))
        XCTAssertTrue(allCases.contains(.mlx))
        XCTAssertTrue(allCases.contains(.tinyLLM))
        XCTAssertTrue(allCases.contains(.tinyChat))
        XCTAssertTrue(allCases.contains(.openWebUI))
        XCTAssertTrue(allCases.contains(.auto))
    }

    func testBackendIcons() {
        for backend in AIBackend.allCases {
            XCTAssertFalse(backend.icon.isEmpty, "\(backend.rawValue) should have an icon")
        }
    }

    func testBackendDescriptions() {
        for backend in AIBackend.allCases {
            XCTAssertFalse(backend.description.isEmpty, "\(backend.rawValue) should have a description")
        }
    }

    func testBackendAttribution() {
        XCTAssertNotNil(AIBackend.tinyLLM.attribution)
        XCTAssertNotNil(AIBackend.tinyChat.attribution)
        XCTAssertNotNil(AIBackend.openWebUI.attribution)
        XCTAssertNil(AIBackend.ollama.attribution)
        XCTAssertNil(AIBackend.mlx.attribution)
        XCTAssertNil(AIBackend.auto.attribution)
    }

    func testBackendCodable() throws {
        let backend = AIBackend.ollama
        let data = try JSONEncoder().encode(backend)
        let decoded = try JSONDecoder().decode(AIBackend.self, from: data)
        XCTAssertEqual(decoded, .ollama)
    }

    func testBackendRawValues() {
        XCTAssertEqual(AIBackend.ollama.rawValue, "Ollama")
        XCTAssertEqual(AIBackend.mlx.rawValue, "MLX Toolkit")
        XCTAssertEqual(AIBackend.tinyLLM.rawValue, "TinyLLM")
        XCTAssertEqual(AIBackend.tinyChat.rawValue, "TinyChat")
        XCTAssertEqual(AIBackend.openWebUI.rawValue, "OpenWebUI")
        XCTAssertEqual(AIBackend.auto.rawValue, "Auto (Prefer Ollama)")
    }

    // MARK: - AIBackendError Tests

    func testNoBackendAvailableError() {
        let error = AIBackendError.noBackendAvailable
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("No AI backend"))
    }

    func testInvalidConfigurationError() {
        let error = AIBackendError.invalidConfiguration
        XCTAssertNotNil(error.errorDescription)
    }

    func testInvalidStateError() {
        let error = AIBackendError.invalidState
        XCTAssertNotNil(error.errorDescription)
    }

    func testMLXScriptNotConfiguredError() {
        let error = AIBackendError.mlxScriptNotConfigured
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("MLX"))
    }

    func testMLXExecutionFailedError() {
        let error = AIBackendError.mlxExecutionFailed("Python crashed")
        XCTAssertNotNil(error.errorDescription)
        XCTAssertTrue(error.errorDescription!.contains("Python crashed"))
    }

    func testEmbeddingsNotSupportedError() {
        let error = AIBackendError.embeddingsNotSupported
        XCTAssertNotNil(error.errorDescription)
    }

    // MARK: - AttackPlan Model Tests

    func testAttackPlanConstruction() {
        let device = Device(ipAddress: "192.168.1.10")
        let target = PriorityTarget(
            device: device,
            reason: "Most vulnerable",
            attackSequence: ["port_scan", "default_creds"],
            successProbability: 85,
            timeToCompromise: "30 seconds",
            pivotOpportunities: ["SSH key reuse"]
        )

        let chain = AttackChain(
            description: "Pi to NAS",
            steps: ["exploit_pi", "extract_keys", "access_nas"]
        )

        let plan = AttackPlan(
            priorityTargets: [target],
            attackChains: [chain],
            overallStrategy: "Start with IoT"
        )

        XCTAssertEqual(plan.priorityTargets.count, 1)
        XCTAssertEqual(plan.attackChains.count, 1)
        XCTAssertEqual(plan.overallStrategy, "Start with IoT")
        XCTAssertEqual(plan.priorityTargets[0].successProbability, 85)
        XCTAssertEqual(plan.attackChains[0].steps.count, 3)
    }

    // MARK: - PostExploitationPlan Tests

    func testPostExploitationPlan() {
        let plan = PostExploitationPlan(
            recommendations: ["Check /etc/shadow", "Enumerate local network"],
            lateralMovementTargets: ["192.168.1.20 via SSH"],
            privilegeEscalationPaths: ["SUID binary abuse"],
            persistenceMechanisms: ["Cron job backdoor"]
        )

        XCTAssertEqual(plan.recommendations.count, 2)
        XCTAssertEqual(plan.lateralMovementTargets.count, 1)
        XCTAssertEqual(plan.privilegeEscalationPaths.count, 1)
        XCTAssertEqual(plan.persistenceMechanisms.count, 1)
    }

    // MARK: - AttackRecommendation Tests

    func testAttackRecommendation() {
        let rec = AttackRecommendation(
            name: "SSH Default Credentials",
            type: .credentialAttack,
            successProbability: 40,
            impact: "Shell access",
            stealth: "Low detection",
            reasoning: "Default pi/raspberry password"
        )

        XCTAssertEqual(rec.name, "SSH Default Credentials")
        XCTAssertEqual(rec.type, .credentialAttack)
        XCTAssertEqual(rec.successProbability, 40)
        XCTAssertNotNil(rec.id)
    }
}
