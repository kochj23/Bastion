//
//  MITREATTACKMapper.swift
//  Bastion
//
//  Maps findings to MITRE ATT&CK framework techniques
//  Provides industry-standard threat modeling and reporting
//  Author: Jordan Koch
//  Date: 2026-01-20
//

import Foundation

@MainActor
class MITREATTACKMapper: ObservableObject {
    @Published var techniqueMapping: [String: [MITRETechnique]] = [:]
    @Published var tacticsDetected: Set<MITRETactic> = []

    // MARK: - Main Mapping Function

    /// Map all vulnerabilities and findings to MITRE ATT&CK techniques
    func mapToATTACK(devices: [Device], attackResults: [AttackResult]) -> MITREATTACKReport {
        print("🎯 MITRE ATT&CK: Mapping findings to framework...")

        var techniques: [MITRETechnique] = []
        var tactics: Set<MITRETactic> = []

        // Map device vulnerabilities
        for device in devices {
            // Network service scanning = T1046
            if !device.openPorts.isEmpty {
                let technique = MITRETechnique(
                    id: "T1046",
                    name: "Network Service Discovery",
                    tactic: .discovery,
                    description: "Discovered \(device.openPorts.count) open ports on \(device.ipAddress)",
                    evidence: device.openPorts.map { "Port \($0.port): \($0.service ?? "unknown")" },
                    severity: .informational
                )
                techniques.append(technique)
                tactics.insert(.discovery)
            }

            // SSH service = T1021.004 (Remote Services: SSH)
            if device.openPorts.contains(where: { $0.port == 22 }) {
                let technique = MITRETechnique(
                    id: "T1021.004",
                    name: "Remote Services: SSH",
                    tactic: .lateralMovement,
                    description: "SSH service exposed on \(device.ipAddress) - potential lateral movement vector",
                    evidence: ["Port 22 open", "SSH accessible"],
                    severity: .medium
                )
                techniques.append(technique)
                tactics.insert(.lateralMovement)
            }

            // SMB service = T1021.002 (Remote Services: SMB/Windows Admin Shares)
            if device.openPorts.contains(where: { $0.port == 445 }) {
                let technique = MITRETechnique(
                    id: "T1021.002",
                    name: "Remote Services: SMB/Windows Admin Shares",
                    tactic: .lateralMovement,
                    description: "SMB service exposed on \(device.ipAddress)",
                    evidence: ["Port 445 open"],
                    severity: .high
                )
                techniques.append(technique)
                tactics.insert(.lateralMovement)
            }

            // Default credentials = T1078 (Valid Accounts)
            if device.vulnerabilities.contains(where: { $0.title.lowercased().contains("default") }) {
                let technique = MITRETechnique(
                    id: "T1078",
                    name: "Valid Accounts",
                    tactic: .initialAccess,
                    description: "Default credentials detected on \(device.ipAddress)",
                    evidence: ["Potential default credential vulnerability"],
                    severity: .critical
                )
                techniques.append(technique)
                tactics.insert(.initialAccess)
            }

            // RCE vulnerabilities = T1059 (Command and Scripting Interpreter)
            let rceVulns = device.vulnerabilities.filter {
                $0.description.lowercased().contains("remote code execution") ||
                $0.description.lowercased().contains("command injection")
            }
            if !rceVulns.isEmpty {
                let technique = MITRETechnique(
                    id: "T1059",
                    name: "Command and Scripting Interpreter",
                    tactic: .execution,
                    description: "\(rceVulns.count) RCE vulnerabilities on \(device.ipAddress)",
                    evidence: rceVulns.map { $0.cveId ?? $0.title },
                    severity: .critical
                )
                techniques.append(technique)
                tactics.insert(.execution)
            }

            // Privilege escalation = T1068 (Exploitation for Privilege Escalation)
            let privEsc = device.vulnerabilities.filter {
                $0.description.lowercased().contains("privilege escalation")
            }
            if !privEsc.isEmpty {
                let technique = MITRETechnique(
                    id: "T1068",
                    name: "Exploitation for Privilege Escalation",
                    tactic: .privilegeEscalation,
                    description: "\(privEsc.count) privilege escalation paths on \(device.ipAddress)",
                    evidence: privEsc.map { $0.cveId ?? $0.title },
                    severity: .high
                )
                techniques.append(technique)
                tactics.insert(.privilegeEscalation)
            }
        }

        // Map attack results
        for attack in attackResults {
            let mappedTechniques = mapAttackToTechnique(attack: attack)
            techniques.append(contentsOf: mappedTechniques)
            for technique in mappedTechniques {
                tactics.insert(technique.tactic)
            }
        }

        self.tacticsDetected = tactics

        return MITREATTACKReport(
            techniques: techniques,
            tactics: Array(tactics).sorted { $0.order < $1.order },
            devicesAnalyzed: devices.count,
            scanDate: Date()
        )
    }

    // MARK: - Attack to Technique Mapping

    private func mapAttackToTechnique(attack: AttackResult) -> [MITRETechnique] {
        var techniques: [MITRETechnique] = []

        switch attack.attackType {
        case .networkScan, .portScan:
            techniques.append(MITRETechnique(
                id: "T1046",
                name: "Network Service Discovery",
                tactic: .discovery,
                description: "Network scanning performed",
                evidence: [attack.details],
                severity: .informational
            ))

        case .sshBruteForce, .defaultCredentials:
            techniques.append(MITRETechnique(
                id: "T1110",
                name: "Brute Force",
                tactic: .credentialAccess,
                description: "Credential brute force attempted",
                evidence: attack.evidence,
                severity: .medium
            ))

        case .sqlInjection:
            techniques.append(MITRETechnique(
                id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: .initialAccess,
                description: "SQL injection vulnerability tested",
                evidence: attack.evidence,
                severity: .high
            ))

        case .xss, .directoryTraversal:
            techniques.append(MITRETechnique(
                id: "T1190",
                name: "Exploit Public-Facing Application",
                tactic: .initialAccess,
                description: "Web application vulnerability tested",
                evidence: attack.evidence,
                severity: .medium
            ))

        case .smbExploit:
            techniques.append(MITRETechnique(
                id: "T1210",
                name: "Exploitation of Remote Services",
                tactic: .lateralMovement,
                description: "SMB vulnerability tested",
                evidence: attack.evidence,
                severity: .critical
            ))

        default:
            break
        }

        return techniques
    }

    // MARK: - Report Generation

    /// Generate MITRE ATT&CK Navigator JSON (for heatmap visualization)
    func exportNavigatorJSON(report: MITREATTACKReport) -> String {
        var json = """
        {
            "name": "Bastion Security Assessment",
            "version": "4.5",
            "domain": "enterprise-attack",
            "description": "Generated by Bastion on \(report.scanDate.formatted())",
            "techniques": [
        """

        for (index, technique) in report.techniques.enumerated() {
            let comma = index < report.techniques.count - 1 ? "," : ""
            json += """
                {
                    "techniqueID": "\(technique.id)",
                    "tactic": "\(technique.tactic.rawValue)",
                    "score": \(technique.severity == .critical ? 100 : technique.severity == .high ? 75 : technique.severity == .medium ? 50 : 25),
                    "comment": "\(technique.description.replacingOccurrences(of: "\"", with: "'"))"
                }\(comma)
            """
        }

        json += """
            ],
            "gradient": {
                "colors": ["#ffffff", "#ff0000"],
                "minValue": 0,
                "maxValue": 100
            }
        }
        """

        return json
    }
}

// MARK: - Data Models

struct MITREATTACKReport {
    let techniques: [MITRETechnique]
    let tactics: [MITRETactic]
    let devicesAnalyzed: Int
    let scanDate: Date

    var criticalTechniques: [MITRETechnique] {
        techniques.filter { $0.severity == .critical }
    }

    var techniquesByTactic: [MITRETactic: [MITRETechnique]] {
        Dictionary(grouping: techniques, by: { $0.tactic })
    }
}

struct MITRETechnique: Identifiable {
    let id: String // e.g., "T1046"
    let name: String
    let tactic: MITRETactic
    let description: String
    let evidence: [String]
    let severity: VulnerabilitySeverity
}

enum MITRETactic: String, CaseIterable, Comparable {
    case reconnaissance = "Reconnaissance"
    case resourceDevelopment = "Resource Development"
    case initialAccess = "Initial Access"
    case execution = "Execution"
    case persistence = "Persistence"
    case privilegeEscalation = "Privilege Escalation"
    case defenseEvasion = "Defense Evasion"
    case credentialAccess = "Credential Access"
    case discovery = "Discovery"
    case lateralMovement = "Lateral Movement"
    case collection = "Collection"
    case commandAndControl = "Command and Control"
    case exfiltration = "Exfiltration"
    case impact = "Impact"

    var order: Int {
        switch self {
        case .reconnaissance: return 1
        case .resourceDevelopment: return 2
        case .initialAccess: return 3
        case .execution: return 4
        case .persistence: return 5
        case .privilegeEscalation: return 6
        case .defenseEvasion: return 7
        case .credentialAccess: return 8
        case .discovery: return 9
        case .lateralMovement: return 10
        case .collection: return 11
        case .commandAndControl: return 12
        case .exfiltration: return 13
        case .impact: return 14
        }
    }

    static func < (lhs: MITRETactic, rhs: MITRETactic) -> Bool {
        lhs.order < rhs.order
    }
}
