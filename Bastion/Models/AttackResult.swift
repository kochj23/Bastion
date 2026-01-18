//
//  AttackResult.swift
//  Bastion
//
//  Attack execution result tracking
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import Foundation

struct AttackResult: Identifiable, Codable {
    let id: UUID
    let timestamp: Date
    let targetIP: String
    let attackType: AttackType
    let module: String
    var status: AttackStatus
    var duration: TimeInterval
    var details: String
    var evidence: [String] // Screenshots, command outputs, etc.
    var vulnerabilityConfirmed: Bool
    var exploitSuccessful: Bool

    init(targetIP: String, attackType: AttackType, module: String) {
        self.id = UUID()
        self.timestamp = Date()
        self.targetIP = targetIP
        self.attackType = attackType
        self.module = module
        self.status = .running
        self.duration = 0
        self.details = ""
        self.evidence = []
        self.vulnerabilityConfirmed = false
        self.exploitSuccessful = false
    }

    var logEntry: String {
        let timeStr = timestamp.formatted(date: .omitted, time: .standard)
        let statusIcon = status.icon
        return "[\(timeStr)] \(statusIcon) \(attackType.rawValue): \(details)"
    }
}

// AttackType enum moved to AIAttackOrchestrator.swift to avoid duplication

enum AttackStatus: String, Codable {
    case pending = "Pending"
    case running = "Running"
    case success = "Success"
    case failed = "Failed"
    case blocked = "Blocked"
    case timeout = "Timeout"

    var icon: String {
        switch self {
        case .pending: return "⏳"
        case .running: return "🔄"
        case .success: return "✓"
        case .failed: return "✗"
        case .blocked: return "🚫"
        case .timeout: return "⏱"
        }
    }
}

// AttackPlan and AttackRecommendation moved to AIAttackOrchestrator.swift to avoid duplication
// RiskLevel moved to Device.swift

struct ScanResults: Codable {
    var devices: [Device]
    var totalVulnerabilities: Int
    var criticalCount: Int
    var highCount: Int
    var mediumCount: Int
    var lowCount: Int
    var scanDate: Date
    var networkCIDR: String
    var attackResults: [AttackResult]

    init() {
        self.devices = []
        self.totalVulnerabilities = 0
        self.criticalCount = 0
        self.highCount = 0
        self.mediumCount = 0
        self.lowCount = 0
        self.scanDate = Date()
        self.networkCIDR = ""
        self.attackResults = []
    }
}
