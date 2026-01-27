//
//  TimelineReconstructor.swift
//  Bastion
//
//  Forensic timeline reconstruction from compromise assessment
//  Rebuilds attacker activity sequence from evidence
//  Author: Jordan Koch
//  Date: 2026-01-20
//

import Foundation

@MainActor
class TimelineReconstructor: ObservableObject {
    @Published var timeline: [TimelineEvent] = []
    @Published var attackNarrative: String = ""
    @Published var isAnalyzing = false

    private let aiBackend = AIBackendManager.shared

    // MARK: - Timeline Reconstruction

    /// Reconstruct attack timeline from compromise report
    func reconstructTimeline(report: CompromiseReport, device: Device) async -> AttackTimeline {
        isAnalyzing = true
        defer { isAnalyzing = false }

        print("📅 TIMELINE: Reconstructing attack sequence for \(report.targetIP)...")

        var events: [TimelineEvent] = []

        // Phase 1: Initial Reconnaissance (estimated)
        if report.totalFindings > 0 {
            events.append(TimelineEvent(
                timestamp: estimateReconTime(report: report),
                phase: .reconnaissance,
                action: "Attacker performed network reconnaissance",
                evidence: ["Multiple vulnerabilities exploited", "Systematic compromise pattern"],
                confidence: .possible,
                attackerAction: "Network scanning and vulnerability assessment"
            ))
        }

        // Phase 2: Initial Access
        events.append(contentsOf: reconstructInitialAccess(report: report))

        // Phase 3: Privilege Escalation
        events.append(contentsOf: reconstructPrivilegeEscalation(report: report))

        // Phase 4: Persistence
        events.append(contentsOf: reconstructPersistence(report: report))

        // Phase 5: Defense Evasion
        events.append(contentsOf: reconstructDefenseEvasion(report: report))

        // Phase 6: Collection & Exfiltration
        events.append(contentsOf: reconstructCollectionPhase(report: report))

        // Sort by timestamp
        events.sort { $0.timestamp < $1.timestamp }

        // Generate narrative
        let narrative = await generateNarrative(events: events, report: report)

        let attackTimeline = AttackTimeline(
            events: events,
            narrative: narrative,
            attackDuration: estimateAttackDuration(events: events),
            sophisticationLevel: assessSophistication(report: report)
        )

        await MainActor.run {
            self.timeline = events
            self.attackNarrative = narrative
        }

        return attackTimeline
    }

    // MARK: - Phase Reconstruction

    private func reconstructInitialAccess(report: CompromiseReport) -> [TimelineEvent] {
        var events: [TimelineEvent] = []

        // Check for suspicious users (likely initial access point)
        if !report.suspiciousUsers.isEmpty {
            for user in report.suspiciousUsers {
                let timestamp = Date().addingTimeInterval(-86400 * 7) // Estimate 1 week ago

                events.append(TimelineEvent(
                    timestamp: timestamp,
                    phase: .initialAccess,
                    action: "Suspicious user account created: \(user.username)",
                    evidence: user.suspicionReasons,
                    confidence: .likely,
                    attackerAction: "Created backdoor user account for persistent access"
                ))
            }
        }

        // Check for backdoors (initial access mechanism)
        if !report.backdoors.isEmpty {
            for backdoor in report.backdoors.prefix(3) {
                events.append(TimelineEvent(
                    timestamp: Date().addingTimeInterval(-86400 * 5), // Estimate 5 days ago
                    phase: .initialAccess,
                    action: "Backdoor service established on port \(backdoor.port)",
                    evidence: ["Port: \(backdoor.port)", "Service: \(backdoor.service)", backdoor.suspicionReason],
                    confidence: .likely,
                    attackerAction: "Installed network backdoor for remote access"
                ))
            }
        }

        return events
    }

    private func reconstructPrivilegeEscalation(report: CompromiseReport) -> [TimelineEvent] {
        var events: [TimelineEvent] = []

        // Rootkit = privilege escalation successful
        if !report.rootkits.isEmpty {
            for rootkit in report.rootkits {
                events.append(TimelineEvent(
                    timestamp: Date().addingTimeInterval(-86400 * 3), // Estimate 3 days ago
                    phase: .privilegeEscalation,
                    action: "Rootkit installed: \(rootkit.name) (\(rootkit.type.rawValue))",
                    evidence: ["Rootkit: \(rootkit.name)", "Type: \(rootkit.type.rawValue)"],
                    confidence: .definite,
                    attackerAction: "Escalated to root privileges and installed rootkit"
                ))
            }
        }

        // Suspicious users with UID 0 = privilege escalation
        let rootUsers = report.suspiciousUsers.filter { $0.uid == 0 || $0.username == "root" }
        if !rootUsers.isEmpty {
            events.append(TimelineEvent(
                timestamp: Date().addingTimeInterval(-86400 * 4),
                phase: .privilegeEscalation,
                action: "Attacker gained root/admin privileges",
                evidence: ["Modified root account or created UID 0 user"],
                confidence: .likely,
                attackerAction: "Privilege escalation to administrator"
            ))
        }

        return events
    }

    private func reconstructPersistence(report: CompromiseReport) -> [TimelineEvent] {
        var events: [TimelineEvent] = []

        // Persistence mechanisms
        for mechanism in report.persistenceMechanisms {
            events.append(TimelineEvent(
                timestamp: Date().addingTimeInterval(-86400 * 2),
                phase: .persistence,
                action: "Persistence mechanism: \(mechanism.mechanism.rawValue)",
                evidence: ["Location: \(mechanism.location)", "Details: \(mechanism.description)"],
                confidence: .likely,
                attackerAction: "Installed persistence to survive reboots"
            ))
        }

        return events
    }

    private func reconstructDefenseEvasion(report: CompromiseReport) -> [TimelineEvent] {
        var events: [TimelineEvent] = []

        // Log tampering = defense evasion
        if !report.logTamperingIssues.isEmpty {
            for logIssue in report.logTamperingIssues {
                events.append(TimelineEvent(
                    timestamp: Date().addingTimeInterval(-86400),
                    phase: .defenseEvasion,
                    action: "Log tampering: \(logIssue.tamperingType.rawValue)",
                    evidence: ["Log file: \(logIssue.logFile)", "Tampering: \(logIssue.tamperingType.rawValue)"],
                    confidence: .likely,
                    attackerAction: "Covered tracks by tampering with system logs"
                ))
            }
        }

        // Binary modifications = defense evasion
        if !report.binaryIntegrityIssues.isEmpty {
            for binaryIssue in report.binaryIntegrityIssues.prefix(5) {
                events.append(TimelineEvent(
                    timestamp: Date().addingTimeInterval(-86400 * 2),
                    phase: .defenseEvasion,
                    action: "Binary trojanized: \(binaryIssue.binaryPath)",
                    evidence: ["Binary: \(binaryIssue.binaryPath)", "Issue: \(binaryIssue.issue.rawValue)"],
                    confidence: .definite,
                    attackerAction: "Replaced system binaries with trojanized versions"
                ))
            }
        }

        return events
    }

    private func reconstructCollectionPhase(report: CompromiseReport) -> [TimelineEvent] {
        var events: [TimelineEvent] = []

        // Network sniffers = collection phase
        if !report.networkSniffers.isEmpty {
            for sniffer in report.networkSniffers {
                events.append(TimelineEvent(
                    timestamp: Date().addingTimeInterval(-86400),
                    phase: .collection,
                    action: "Network sniffer active on \(sniffer.interface)",
                    evidence: ["Interface: \(sniffer.interface)", "Promiscuous: \(sniffer.isPromiscuous)"],
                    confidence: .definite,
                    attackerAction: "Deployed network sniffer to capture credentials"
                ))
            }
        }

        return events
    }

    // MARK: - Narrative Generation

    private func generateNarrative(events: [TimelineEvent], report: CompromiseReport) async -> String {
        guard aiBackend.activeBackend != nil else {
            return generateBasicNarrative(events: events, report: report)
        }

        let prompt = """
        Reconstruct the attack narrative from these forensic findings.

        TARGET: \(report.targetIP)
        COMPROMISE STATUS: \(report.compromiseConfidence.rawValue)
        TOTAL FINDINGS: \(report.totalFindings)

        TIMELINE EVENTS (\(events.count)):
        \(events.map { "[\(formatTimestamp($0.timestamp))] \($0.phase.rawValue): \($0.action)" }.joined(separator: "\n"))

        Write a coherent attack narrative that:
        1. Tells the story chronologically
        2. Explains attacker motivations
        3. Identifies attacker skill level
        4. Explains what data was likely compromised
        5. Recommends incident response steps

        Write as a security analyst briefing executive leadership.
        """

        do {
            let narrative = try await aiBackend.generate(
                prompt: prompt,
                systemPrompt: "You are a forensic analyst reconstructing a cybersecurity incident. Write clear, executive-level briefings.",
                temperature: 0.6,
                maxTokens: 1000
            )

            return narrative
        } catch {
            return generateBasicNarrative(events: events, report: report)
        }
    }

    private func generateBasicNarrative(events: [TimelineEvent], report: CompromiseReport) -> String {
        var narrative = "ATTACK TIMELINE RECONSTRUCTION\n"
        narrative += "================================\n\n"

        narrative += "Target: \(report.targetIP)\n"
        narrative += "Status: \(report.compromiseConfidence.rawValue)\n"
        narrative += "Timeline Events: \(events.count)\n\n"

        narrative += "ATTACK SEQUENCE:\n\n"

        for (index, event) in events.enumerated() {
            narrative += "\(index + 1). [\(formatTimestamp(event.timestamp))] \(event.action)\n"
            narrative += "   Phase: \(event.phase.rawValue)\n"
            narrative += "   Confidence: \(event.confidence.rawValue)\n\n"
        }

        return narrative
    }

    // MARK: - Helpers

    private func estimateReconTime(report: CompromiseReport) -> Date {
        // Estimate reconnaissance happened 2 weeks before first compromise
        return Date().addingTimeInterval(-86400 * 14)
    }

    private func estimateAttackDuration(events: [TimelineEvent]) -> TimeInterval {
        guard let first = events.first?.timestamp,
              let last = events.last?.timestamp else {
            return 0
        }

        return last.timeIntervalSince(first)
    }

    private func assessSophistication(report: CompromiseReport) -> SophisticationLevel {
        var score = 0

        // Rootkits = sophisticated
        if !report.rootkits.isEmpty {
            score += 3
        }

        // Kernel modules = very sophisticated
        if !report.kernelModuleIssues.isEmpty {
            score += 2
        }

        // Log tampering = moderate sophistication
        if !report.logTamperingIssues.isEmpty {
            score += 2
        }

        // Binary trojanization = sophisticated
        if report.binaryIntegrityIssues.count > 5 {
            score += 3
        }

        // Multiple persistence = planned attack
        if report.persistenceMechanisms.count > 3 {
            score += 2
        }

        if score >= 8 {
            return .apt
        } else if score >= 5 {
            return .advanced
        } else if score >= 3 {
            return .intermediate
        } else {
            return .scriptKiddie
        }
    }

    private func formatTimestamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }
}

// MARK: - Data Models

struct AttackTimeline {
    let events: [TimelineEvent]
    let narrative: String
    let attackDuration: TimeInterval // In seconds
    let sophisticationLevel: SophisticationLevel

    var durationDescription: String {
        let days = Int(attackDuration / 86400)
        let hours = Int((attackDuration.truncatingRemainder(dividingBy: 86400)) / 3600)

        if days > 0 {
            return "\(days) days, \(hours) hours"
        } else if hours > 0 {
            return "\(hours) hours"
        } else {
            return "< 1 hour"
        }
    }
}

struct TimelineEvent: Identifiable {
    let id = UUID()
    let timestamp: Date
    let phase: AttackPhase
    let action: String
    let evidence: [String]
    let confidence: CompromiseConfidence
    let attackerAction: String
}

enum AttackPhase: String, Codable, CaseIterable {
    case reconnaissance = "Reconnaissance"
    case initialAccess = "Initial Access"
    case execution = "Execution"
    case persistence = "Persistence"
    case privilegeEscalation = "Privilege Escalation"
    case defenseEvasion = "Defense Evasion"
    case credentialAccess = "Credential Access"
    case discovery = "Discovery"
    case lateralMovement = "Lateral Movement"
    case collection = "Collection"
    case exfiltration = "Exfiltration"
    case impact = "Impact"
}

enum SophisticationLevel: String {
    case scriptKiddie = "Script Kiddie"
    case intermediate = "Intermediate"
    case advanced = "Advanced Attacker"
    case apt = "APT / Nation State"

    var description: String {
        switch self {
        case .scriptKiddie:
            return "Low sophistication - using automated tools and public exploits"
        case .intermediate:
            return "Moderate sophistication - custom scripts and multiple techniques"
        case .advanced:
            return "High sophistication - custom malware, anti-forensics, multiple persistence"
        case .apt:
            return "Nation-state / APT level - rootkits, kernel modules, advanced evasion"
        }
    }
}
