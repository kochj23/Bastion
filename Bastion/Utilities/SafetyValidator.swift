//
//  SafetyValidator.swift
//  Bastion
//
//  Safety features and local network enforcement
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import Foundation
import SwiftUI

class SafetyValidator {
    static let shared = SafetyValidator()

    private init() {}

    // CRITICAL: Validate target is local network only
    func validateTarget(_ ipAddress: String) throws {
        guard isLocalIP(ipAddress) else {
            throw BastionError.publicIPNotAllowed(
                "🚨 ILLEGAL OPERATION BLOCKED\n\n" +
                "Bastion only scans LOCAL networks.\n" +
                "Scanning internet IPs is ILLEGAL without authorization.\n\n" +
                "Target: \(ipAddress) is NOT a local IP.\n\n" +
                "Allowed ranges:\n" +
                "• 192.168.0.0/16 (192.168.x.x)\n" +
                "• 10.0.0.0/8 (10.x.x.x)\n" +
                "• 172.16.0.0/12 (172.16-31.x.x)\n\n" +
                "Unauthorized network scanning may violate:\n" +
                "• Computer Fraud and Abuse Act (USA)\n" +
                "• Computer Misuse Act (UK)\n" +
                "Maximum penalties: $250,000 fine + 20 years imprisonment"
            )
        }
    }

    // Check if IP is in private range
    func isLocalIP(_ ip: String) -> Bool {
        let octets = ip.split(separator: ".").compactMap { Int($0) }
        guard octets.count == 4 else { return false }

        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return true
        }

        // 10.0.0.0/8
        if octets[0] == 10 {
            return true
        }

        // 172.16.0.0/12 (172.16 - 172.31)
        if octets[0] == 172 && (16...31).contains(octets[1]) {
            return true
        }

        // Localhost
        if octets[0] == 127 {
            return true
        }

        return false
    }

    // Rate limiting to prevent DoS
    private var requestTimestamps: [Date] = []
    private let maxRequestsPerSecond = 10

    func checkRateLimit() throws {
        let now = Date()
        let oneSecondAgo = now.addingTimeInterval(-1)

        // Remove old timestamps
        requestTimestamps.removeAll { $0 < oneSecondAgo }

        guard requestTimestamps.count < maxRequestsPerSecond else {
            throw BastionError.rateLimitExceeded(
                "Rate limit exceeded. Maximum \(maxRequestsPerSecond) requests per second."
            )
        }

        requestTimestamps.append(now)
    }

    // Show legal warning on first launch
    @MainActor
    func showLegalWarningIfNeeded() async -> Bool {
        let hasAccepted = UserDefaults.standard.bool(forKey: "BastionLegalAccepted")

        if hasAccepted {
            return true
        }

        // Would show alert dialog here
        // For now, return true if accepted
        return await showLegalWarningDialog()
    }

    @MainActor
    private func showLegalWarningDialog() async -> Bool {
        return await withCheckedContinuation { continuation in
            let alert = NSAlert()
            alert.messageText = "⚠️ LEGAL NOTICE - WHITE HAT SECURITY TOOL"
            alert.informativeText = """
            Bastion is a WHITE HAT security testing tool for YOUR OWN network.

            UNAUTHORIZED NETWORK SCANNING IS ILLEGAL

            By using Bastion, you confirm:
            ✓ You own or have explicit written permission to test this network
            ✓ You will use this tool for defensive security purposes only
            ✓ You understand unauthorized access/scanning may violate:
              • Computer Fraud and Abuse Act (CFAA) - USA
              • Computer Misuse Act - UK
              • Similar laws in your jurisdiction

            Maximum penalties: $250,000 fine + 20 years imprisonment (USA)

            This tool is designed for:
            ✓ Testing YOUR home network security
            ✓ Assessing YOUR office network (with permission)
            ✓ Security research in authorized lab environments
            ✓ Penetration testing with signed engagement contracts

            DO NOT use on networks you don't own/control.

            Bastion enforces local IP scanning only (192.168.x.x, 10.x.x.x, 172.16-31.x.x).
            All activities are logged for audit purposes.
            """

            alert.addButton(withTitle: "I Understand and Accept")
            alert.addButton(withTitle: "Quit")
            alert.alertStyle = .critical

            let response = alert.runModal()

            if response == .alertFirstButtonReturn {
                UserDefaults.standard.set(true, forKey: "BastionLegalAccepted")
                UserDefaults.standard.set(Date(), forKey: "BastionLegalAcceptedDate")
                continuation.resume(returning: true)
            } else {
                continuation.resume(returning: false)
            }
        }
    }

    // Confirm attack execution
    @MainActor
    func confirmAttack(target: Device, attackTypes: [AttackType]) async -> Bool {
        return await withCheckedContinuation { continuation in
            let alert = NSAlert()
            alert.messageText = "🎯 CONFIRM SECURITY TEST"
            alert.informativeText = """
            You are about to execute security tests against:

            IP: \(target.ipAddress)
            Hostname: \(target.hostname ?? "Unknown")
            Services: \(target.services.map { $0.name }.joined(separator: ", "))
            Tests: \(attackTypes.map { $0.rawValue }.joined(separator: ", "))

            These tests may:
            • Generate network traffic
            • Trigger security alerts
            • Temporarily slow the target
            • Appear in system logs

            Are you sure this is YOUR network and you have authorization?
            """

            alert.addButton(withTitle: "Yes, I Own This Network")
            alert.addButton(withTitle: "Cancel")
            alert.alertStyle = .warning

            let response = alert.runModal()
            continuation.resume(returning: response == .alertFirstButtonReturn)
        }
    }

    // Audit logging
    func logActivity(_ action: String, target: String? = nil) {
        let timestamp = Date().formatted(date: .abbreviated, time: .standard)
        let logEntry = "[\(timestamp)] \(action)" + (target != nil ? " - Target: \(target!)" : "")

        // Append to audit log file
        let logPath = getAuditLogPath()
        if let data = (logEntry + "\n").data(using: .utf8) {
            if FileManager.default.fileExists(atPath: logPath.path) {
                if let fileHandle = try? FileHandle(forWritingTo: logPath) {
                    fileHandle.seekToEndOfFile()
                    fileHandle.write(data)
                    fileHandle.closeFile()
                }
            } else {
                try? data.write(to: logPath)
            }
        }

        print(logEntry) // Also print to console
    }

    private func getAuditLogPath() -> URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let bastionDir = appSupport.appendingPathComponent("Bastion", isDirectory: true)
        try? FileManager.default.createDirectory(at: bastionDir, withIntermediateDirectories: true)
        return bastionDir.appendingPathComponent("audit.log")
    }
}

enum BastionError: LocalizedError {
    case publicIPNotAllowed(String)
    case rateLimitExceeded(String)
    case unauthorizedTarget
    case legalNotAccepted

    var errorDescription: String? {
        switch self {
        case .publicIPNotAllowed(let message):
            return message
        case .rateLimitExceeded(let message):
            return message
        case .unauthorizedTarget:
            return "Unauthorized target - local networks only"
        case .legalNotAccepted:
            return "You must accept the legal terms to use Bastion"
        }
    }
}
