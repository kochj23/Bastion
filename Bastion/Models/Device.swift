//
//  Device.swift
//  Bastion
//
//  Network device model with vulnerability tracking
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import Foundation
import SwiftUI

enum RiskLevel: String, Codable {
    case low = "Low"
    case medium = "Medium"
    case high = "High"
    case critical = "Critical"

    var color: Color {
        switch self {
        case .low: return .green
        case .medium: return .yellow
        case .high: return .orange
        case .critical: return .red
        }
    }
}

struct Device: Identifiable, Codable {
    let id: UUID
    let ipAddress: String
    var hostname: String?
    var macAddress: String?
    var manufacturer: String?
    var deviceType: DeviceType
    var operatingSystem: String?
    var openPorts: [OpenPort]
    var services: [ServiceInfo]
    var vulnerabilities: [Vulnerability]
    var securityScore: Int // 0-100 (100 = secure, 0 = critically vulnerable)
    var lastScanned: Date
    var isOnline: Bool

    init(ipAddress: String, hostname: String? = nil, macAddress: String? = nil) {
        self.id = UUID()
        self.ipAddress = ipAddress
        self.hostname = hostname
        self.macAddress = macAddress
        self.manufacturer = nil
        self.deviceType = .unknown
        self.operatingSystem = nil
        self.openPorts = []
        self.services = []
        self.vulnerabilities = []
        self.securityScore = 100
        self.lastScanned = Date()
        self.isOnline = true
    }

    var displayName: String {
        hostname ?? ipAddress
    }

    var criticalVulnCount: Int {
        vulnerabilities.filter { $0.severity == .critical }.count
    }

    var highVulnCount: Int {
        vulnerabilities.filter { $0.severity == .high }.count
    }

    var mediumVulnCount: Int {
        vulnerabilities.filter { $0.severity == .medium }.count
    }

    var lowVulnCount: Int {
        vulnerabilities.filter { $0.severity == .low }.count
    }

    var riskLevel: RiskLevel {
        if criticalVulnCount > 0 {
            return .critical
        } else if highVulnCount > 0 {
            return .high
        } else if mediumVulnCount > 0 {
            return .medium
        } else {
            return .low
        }
    }

    mutating func updateSecurityScore() {
        var score = 100
        score -= criticalVulnCount * 20
        score -= highVulnCount * 10
        score -= mediumVulnCount * 5
        score -= lowVulnCount * 2
        securityScore = max(0, score)
    }
}

enum DeviceType: String, Codable {
    case router = "Router"
    case server = "Server"
    case workstation = "Workstation"
    case mobile = "Mobile Device"
    case iot = "IoT Device"
    case camera = "Camera"
    case printer = "Printer"
    case nas = "Network Storage"
    case unknown = "Unknown"

    var icon: String {
        switch self {
        case .router: return "wifi.router"
        case .server: return "server.rack"
        case .workstation: return "desktopcomputer"
        case .mobile: return "iphone"
        case .iot: return "sensors"
        case .camera: return "camera"
        case .printer: return "printer"
        case .nas: return "externaldrive"
        case .unknown: return "questionmark.circle"
        }
    }
}

struct OpenPort: Identifiable, Codable {
    let id: UUID
    let port: Int
    let portProtocol: PortProtocol
    var state: PortState
    var service: String?
    var version: String?

    init(port: Int, portProtocol: PortProtocol = .tcp) {
        self.id = UUID()
        self.port = port
        self.portProtocol = portProtocol
        self.state = .open
        self.service = nil
        self.version = nil
    }
}

enum PortProtocol: String, Codable {
    case tcp = "TCP"
    case udp = "UDP"
}

enum PortState: String, Codable {
    case open = "Open"
    case closed = "Closed"
    case filtered = "Filtered"
}

struct ServiceInfo: Identifiable, Codable {
    let id: UUID
    var name: String
    var version: String?
    var banner: String?
    let port: Int
    var cpes: [String] // Common Platform Enumeration identifiers

    init(name: String, version: String? = nil, port: Int) {
        self.id = UUID()
        self.name = name
        self.version = version
        self.banner = nil
        self.port = port
        self.cpes = []
    }

    var displayVersion: String {
        if let version = version {
            return "\(name) \(version)"
        }
        return name
    }
}
