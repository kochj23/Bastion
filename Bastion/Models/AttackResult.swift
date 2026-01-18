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

enum AttackType: String, Codable, CaseIterable {
    case networkScan = "Network Scan"
    case portScan = "Port Scan"
    case serviceFingerprint = "Service Detection"
    case sshBruteForce = "SSH Brute Force"
    case defaultCredentials = "Default Credentials Test"
    case sqlInjection = "SQL Injection"
    case xss = "Cross-Site Scripting"
    case directoryTraversal = "Directory Traversal"
    case smbExploit = "SMB Exploit"
    case cveExploit = "CVE Exploit"
    case webVulnScan = "Web Vulnerability Scan"
    case passwordSpray = "Password Spray"
    case apiTest = "API Security Test"

    var icon: String {
        switch self {
        case .networkScan: return "🔍"
        case .portScan: return "🎯"
        case .serviceFingerprint: return "🔎"
        case .sshBruteForce: return "🔐"
        case .defaultCredentials: return "🔑"
        case .sqlInjection: return "💉"
        case .xss: return "⚠️"
        case .directoryTraversal: return "📁"
        case .smbExploit: return "💾"
        case .cveExploit: return "💣"
        case .webVulnScan: return "🌐"
        case .passwordSpray: return "💧"
        case .apiTest: return "🔗"
        }
    }
}

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

struct AttackPlan: Identifiable {
    let id: UUID
    var targetDevice: Device
    var recommendedAttacks: [AttackRecommendation]
    var aiAnalysis: String
    var priorityScore: Int // 0-100
    var estimatedDuration: TimeInterval

    init(targetDevice: Device) {
        self.id = UUID()
        self.targetDevice = targetDevice
        self.recommendedAttacks = []
        self.aiAnalysis = ""
        self.priorityScore = 0
        self.estimatedDuration = 0
    }
}

struct AttackRecommendation: Identifiable {
    let id: UUID
    let attackType: AttackType
    let reason: String
    let successProbability: Double // 0.0 - 1.0
    let riskLevel: RiskLevel
    let estimatedDuration: TimeInterval
    var payload: String?

    init(attackType: AttackType, reason: String, successProbability: Double) {
        self.id = UUID()
        self.attackType = attackType
        self.reason = reason
        self.successProbability = successProbability
        self.riskLevel = successProbability > 0.7 ? .high : (successProbability > 0.4 ? .medium : .low)
        self.estimatedDuration = 60 // Default 1 minute
        self.payload = nil
    }
}

enum RiskLevel: String {
    case low = "Low"
    case medium = "Medium"
    case high = "High"
    case critical = "Critical"
}

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
