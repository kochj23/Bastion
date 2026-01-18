//
//  CVE.swift
//  Bastion
//
//  CVE (Common Vulnerabilities and Exposures) model
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import Foundation

struct CVE: Identifiable, Codable {
    let id: String // CVE-2024-1234
    let description: String
    var publishedDate: Date
    var lastModifiedDate: Date
    let cvssScore: Double
    var cvssVector: String?
    var severity: VulnerabilitySeverity
    var affectedProducts: [String]
    var references: [String]
    var exploitAvailable: Bool
    var cweId: String? // CWE-79 (XSS), etc.

    init(id: String, description: String, cvssScore: Double) {
        self.id = id
        self.description = description
        self.publishedDate = Date()
        self.lastModifiedDate = Date()
        self.cvssScore = cvssScore
        self.cvssVector = nil
        self.severity = CVE.severityFromScore(cvssScore)
        self.affectedProducts = []
        self.references = []
        self.exploitAvailable = false
        self.cweId = nil
    }

    static func severityFromScore(_ score: Double) -> VulnerabilitySeverity {
        switch score {
        case 9.0...10.0: return .critical
        case 7.0..<9.0: return .high
        case 4.0..<7.0: return .medium
        case 0.1..<4.0: return .low
        default: return .informational
        }
    }
}

struct Vulnerability: Identifiable, Codable {
    let id: UUID
    let cveId: String?
    let title: String
    let description: String
    let severity: VulnerabilitySeverity
    var cvssScore: Double?
    var exploitAvailable: Bool
    var proofOfConcept: String?
    var remediation: String?
    var affectedService: String?
    var affectedVersion: String?
    var discovered: Date

    init(title: String, description: String, severity: VulnerabilitySeverity, cveId: String? = nil) {
        self.id = UUID()
        self.cveId = cveId
        self.title = title
        self.description = description
        self.severity = severity
        self.cvssScore = nil
        self.exploitAvailable = false
        self.proofOfConcept = nil
        self.remediation = nil
        self.affectedService = nil
        self.affectedVersion = nil
        self.discovered = Date()
    }
}

enum VulnerabilitySeverity: String, Codable, CaseIterable {
    case critical = "Critical"
    case high = "High"
    case medium = "Medium"
    case low = "Low"
    case informational = "Info"

    var color: String {
        switch self {
        case .critical: return "#FF3B30" // Red
        case .high: return "#FF9500" // Orange
        case .medium: return "#FFCC00" // Yellow
        case .low: return "#007AFF" // Blue
        case .informational: return "#8E8E93" // Gray
        }
    }

    var weight: Int {
        switch self {
        case .critical: return 5
        case .high: return 4
        case .medium: return 3
        case .low: return 2
        case .informational: return 1
        }
    }
}
