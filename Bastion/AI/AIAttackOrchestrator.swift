//
//  AIAttackOrchestrator.swift
//  Bastion
//
//  THE BRAIN: AI-powered attack orchestration and exploit selection
//  This is what makes Bastion worth $5,000 - no competitor has this
//  Author: Jordan Koch
//  Date: 2025-01-17
//
//  "Unleash intelligent, relentless security testing" - Bastion
//

import Foundation
import SwiftUI

/// AI-powered attack orchestrator - The intelligent brain of Bastion
@MainActor
class AIAttackOrchestrator: ObservableObject {
    @Published var attackPlan: AttackPlan?
    @Published var isOrchestrating = false
    @Published var confidenceScores: [String: Double] = [:] // IP -> success probability
    @Published var attackRecommendations: [AttackRecommendation] = []

    private let aiBackend = AIBackendManager.shared

    // MARK: - THE KILLER FEATURE: AI Attack Strategy

    /// Analyze entire network and create intelligent attack plan
    /// This is what makes Bastion enterprise-grade
    func orchestrateAttacks(devices: [Device], cveDatabase: CVEDatabase) async -> AttackPlan {
        guard aiBackend.activeBackend != nil else {
            return generateBasicAttackPlan(devices: devices)
        }

        isOrchestrating = true
        defer { isOrchestrating = false }

        print("🧠 AI ORCHESTRATOR: Analyzing \(devices.count) devices...")

        // Build comprehensive threat landscape
        let threatLandscape = buildThreatLandscape(devices: devices, cveDB: cveDatabase)

        let prompt = """
        You are an elite penetration tester analyzing a network. Your goal: Find EVERY vulnerability.

        NETWORK THREAT LANDSCAPE:
        \(threatLandscape)

        Create an aggressive, intelligent attack plan:

        1. Rank devices by exploitability (1=most vulnerable)
        2. For each device, recommend attack sequence
        3. Predict success probability (0-100%) for each attack
        4. Identify attack chains (compromise Device A to pivot to Device B)
        5. Estimate time to compromise each device

        Think like an attacker: What's the fastest path to root on each device?

        Respond in JSON:
        {
            "priorityTargets": [
                {
                    "ip": "192.168.1.10",
                    "reason": "Most vulnerable - default creds + 3 RCE CVEs",
                    "attackSequence": ["default_creds", "cve-2021-41617", "privilege_escalation"],
                    "successProbability": 95,
                    "timeToCompromise": "60 seconds",
                    "pivotOpportunities": ["Can access internal network from here"]
                }
            ],
            "attackChains": [
                {
                    "description": "Compromise Raspberry Pi → Pivot to NAS via SSH key reuse",
                    "steps": ["exploit_pi", "extract_ssh_keys", "access_nas"]
                }
            ],
            "overallStrategy": "Start with IoT devices (easiest), escalate to servers, use captured credentials for lateral movement"
        }
        """

        do {
            let response = try await aiBackend.generate(
                prompt: prompt,
                systemPrompt: "You are an expert penetration tester and exploit developer. Be aggressive and thorough in finding vulnerabilities.",
                temperature: 0.6,
                maxTokens: 1500
            )

            print("🧠 AI ORCHESTRATOR: Strategy generated")

            if let plan = parseAttackPlan(response, devices: devices) {
                await MainActor.run {
                    self.attackPlan = plan
                }
                return plan
            }
        } catch {
            print("❌ AI ORCHESTRATOR ERROR: \(error)")
        }

        return generateBasicAttackPlan(devices: devices)
    }

    // MARK: - AI Exploit Selection for Single Target

    /// AI selects best exploits for a specific device
    func selectExploits(for device: Device, cves: [CVE]) async -> [AttackRecommendation] {
        guard aiBackend.activeBackend != nil else {
            return generateBasicRecommendations(device: device, cves: cves)
        }

        let context = """
        TARGET: \(device.ip) (\(device.hostname ?? "unknown"))
        OS: \(device.osGuess ?? "unknown")

        SERVICES:
        \(device.openPorts.map { "\($0.port): \($0.service ?? "unknown") \($0.version ?? "")" }.joined(separator: "\n"))

        KNOWN CVEs (\(cves.count)):
        \(cves.prefix(10).map { "- \($0.id): \($0.description.prefix(100))... CVSS: \($0.cvssScore)" }.joined(separator: "\n"))
        """

        let prompt = """
        Select the BEST exploits to compromise this device.

        \(context)

        Consider:
        1. Which CVE is most likely to succeed?
        2. Which has public exploit code?
        3. What's the easiest initial access vector?
        4. Can we chain exploits for full compromise?

        Rank exploits by:
        - Success probability (technical feasibility)
        - Impact (what access we get)
        - Stealth (how noisy is the exploit)

        Respond in JSON with top 5 exploits:
        {
            "exploits": [
                {
                    "name": "SSH Default Credentials",
                    "type": "credential_attack",
                    "successProbability": 85,
                    "impact": "full_shell_access",
                    "stealth": "low_detection",
                    "reasoning": "Raspberry Pi fingerprint suggests default pi/raspberry"
                }
            ]
        }
        """

        do {
            let response = try await aiBackend.generate(
                prompt: prompt,
                systemPrompt: "You are a professional penetration tester selecting optimal exploits.",
                temperature: 0.4,
                maxTokens: 800
            )

            if let recommendations = parseExploitRecommendations(response, device: device) {
                await MainActor.run {
                    self.attackRecommendations = recommendations
                }
                return recommendations
            }
        } catch {
            print("❌ Exploit selection error: \(error)")
        }

        return generateBasicRecommendations(device: device, cves: cves)
    }

    // MARK: - AI Custom Payload Generation

    /// Generate custom exploit payload for specific vulnerability
    func generatePayload(for vuln: Vulnerability, target: Device) async -> String? {
        guard aiBackend.activeBackend != nil else { return nil }

        let prompt = """
        Generate a proof-of-concept exploit payload for this vulnerability.

        Target: \(target.ip)
        OS: \(target.osGuess ?? "Linux")
        Vulnerability: \(vuln.cveId ?? "Unknown")
        Service: \(vuln.service) \(vuln.version)

        Provide:
        1. Exploit code (bash/python/ruby)
        2. Required prerequisites
        3. Expected output if successful
        4. Safety notes (how to avoid damage)

        Make it WORK but SAFE (no permanent damage).
        """

        do {
            let payload = try await aiBackend.generate(
                prompt: prompt,
                systemPrompt: "You are a security researcher creating proof-of-concept exploits. Code must work but be safe.",
                temperature: 0.3,
                maxTokens: 1000
            )
            return payload
        } catch {
            return nil
        }
    }

    // MARK: - AI Post-Exploitation Analysis

    /// After successful compromise, AI suggests next steps
    func analyzePostExploitation(compromisedDevice: Device, accessLevel: String) async -> PostExploitationPlan {
        guard aiBackend.activeBackend != nil else {
            return PostExploitationPlan(
                recommendations: ["Manually investigate further"],
                lateralMovementTargets: [],
                privilegeEscalationPaths: [],
                persistenceMechanisms: []
            )
        }

        let prompt = """
        We successfully compromised device \(compromisedDevice.ip) with \(accessLevel) access.

        Device info:
        - OS: \(compromisedDevice.osGuess ?? "unknown")
        - Services: \(compromisedDevice.openPorts.map { $0.service ?? "unknown" }.joined(separator: ", "))

        What should we do next? Suggest:
        1. Privilege escalation methods (if not root)
        2. Lateral movement targets (other devices we can reach from here)
        3. Persistence mechanisms (if authorized for red team)
        4. Data exfiltration opportunities (for demonstration)
        5. Additional vulnerabilities to test from this position

        Respond in JSON:
        {
            "privilegeEscalation": ["method1", "method2"],
            "lateralMovement": ["Can SSH to 192.168.1.15 using found keys"],
            "persistence": ["Add SSH key", "Cron job backdoor"],
            "nextSteps": ["recommendations"]
        }
        """

        do {
            let response = try await aiBackend.generate(
                prompt: prompt,
                systemPrompt: "You are an advanced penetration tester planning post-exploitation. Be thorough and aggressive.",
                temperature: 0.5,
                maxTokens: 600
            )

            return parsePostExploitationPlan(response)
        } catch {
            return PostExploitationPlan(recommendations: [], lateralMovementTargets: [], privilegeEscalationPaths: [], persistenceMechanisms: [])
        }
    }

    // MARK: - Helpers

    private func buildThreatLandscape(devices: [Device], cveDB: CVEDatabase) -> String {
        var landscape = "DISCOVERED DEVICES: \(devices.count)\n\n"

        for (index, device) in devices.enumerated().prefix(20) {
            let vulnCount = device.vulnerabilities?.count ?? 0
            let criticalCount = device.vulnerabilities?.filter { $0.severity == .critical }.count ?? 0

            landscape += """
            Device \(index + 1): \(device.ip) (\(device.hostname ?? "unknown"))
            - OS: \(device.osGuess ?? "detecting...")
            - Open Ports: \(device.openPorts.count)
            - Services: \(device.openPorts.prefix(5).map { "\($0.service ?? "unknown")" }.joined(separator: ", "))
            - Vulnerabilities: \(vulnCount) total, \(criticalCount) critical
            - Risk Level: \(device.riskLevel.rawValue)

            """
        }

        return landscape
    }

    private func generateBasicAttackPlan(devices: [Device]) -> AttackPlan {
        // Sort by risk level
        let prioritized = devices.sorted {
            ($0.vulnerabilities?.count ?? 0) > ($1.vulnerabilities?.count ?? 0)
        }

        let targets = prioritized.prefix(5).map { device in
            PriorityTarget(
                device: device,
                reason: "Has \(device.vulnerabilities?.count ?? 0) vulnerabilities",
                attackSequence: ["port_scan", "service_detection", "exploit_attempt"],
                successProbability: 50,
                timeToCompromise: "Unknown",
                pivotOpportunities: []
            )
        }

        return AttackPlan(
            priorityTargets: Array(targets),
            attackChains: [],
            overallStrategy: "Test devices in order of vulnerability count"
        )
    }

    private func generateBasicRecommendations(device: Device, cves: [CVE]) -> [AttackRecommendation] {
        var recommendations: [AttackRecommendation] = []

        // Default creds if SSH detected
        if device.openPorts.contains(where: { $0.port == 22 }) {
            recommendations.append(AttackRecommendation(
                name: "SSH Default Credentials",
                type: .credentialAttack,
                successProbability: 40,
                impact: "Shell access",
                stealth: "Low detection",
                reasoning: "SSH is open, test common default passwords"
            ))
        }

        // Web vulns if HTTP detected
        if device.openPorts.contains(where: { $0.port == 80 || $0.port == 443 }) {
            recommendations.append(AttackRecommendation(
                name: "Web Vulnerability Scan",
                type: .webExploit,
                successProbability: 30,
                impact: "Information disclosure or RCE",
                stealth: "Medium detection",
                reasoning: "Web server detected, test for SQL injection and XSS"
            ))
        }

        // CVE exploits
        for cve in cves.prefix(3) where cve.cvssScore >= 7.0 {
            recommendations.append(AttackRecommendation(
                name: "CVE Exploit: \(cve.id)",
                type: .cveExploit,
                successProbability: 60,
                impact: "Depends on CVE",
                stealth: "Varies",
                reasoning: "High severity CVE with potential exploit"
            ))
        }

        return recommendations
    }

    private func parseAttackPlan(_ response: String, devices: [Device]) -> AttackPlan? {
        // Parse JSON response from AI
        guard let jsonData = extractJSON(from: response)?.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            return nil
        }

        // Parse priority targets
        var targets: [PriorityTarget] = []
        if let targetsArray = json["priorityTargets"] as? [[String: Any]] {
            for targetDict in targetsArray {
                guard let ip = targetDict["ip"] as? String,
                      let device = devices.first(where: { $0.ip == ip }) else { continue }

                let target = PriorityTarget(
                    device: device,
                    reason: targetDict["reason"] as? String ?? "",
                    attackSequence: targetDict["attackSequence"] as? [String] ?? [],
                    successProbability: targetDict["successProbability"] as? Int ?? 50,
                    timeToCompromise: targetDict["timeToCompromise"] as? String ?? "Unknown",
                    pivotOpportunities: targetDict["pivotOpportunities"] as? [String] ?? []
                )
                targets.append(target)
            }
        }

        // Parse attack chains
        var chains: [AttackChain] = []
        if let chainsArray = json["attackChains"] as? [[String: Any]] {
            for chainDict in chainsArray {
                let chain = AttackChain(
                    description: chainDict["description"] as? String ?? "",
                    steps: chainDict["steps"] as? [String] ?? []
                )
                chains.append(chain)
            }
        }

        let strategy = json["overallStrategy"] as? String ?? "Attack in order of severity"

        return AttackPlan(
            priorityTargets: targets,
            attackChains: chains,
            overallStrategy: strategy
        )
    }

    private func parseExploitRecommendations(_ response: String, device: Device) -> [AttackRecommendation]? {
        guard let jsonData = extractJSON(from: response)?.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any],
              let exploitsArray = json["exploits"] as? [[String: Any]] else {
            return nil
        }

        return exploitsArray.compactMap { dict in
            guard let name = dict["name"] as? String,
                  let typeStr = dict["type"] as? String,
                  let probability = dict["successProbability"] as? Int,
                  let impact = dict["impact"] as? String,
                  let stealth = dict["stealth"] as? String,
                  let reasoning = dict["reasoning"] as? String else {
                return nil
            }

            let type = AttackType(rawValue: typeStr) ?? .other

            return AttackRecommendation(
                name: name,
                type: type,
                successProbability: probability,
                impact: impact,
                stealth: stealth,
                reasoning: reasoning
            )
        }
    }

    private func parsePostExploitationPlan(_ response: String) -> PostExploitationPlan {
        guard let jsonData = extractJSON(from: response)?.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            return PostExploitationPlan(recommendations: [], lateralMovementTargets: [], privilegeEscalationPaths: [], persistenceMechanisms: [])
        }

        return PostExploitationPlan(
            recommendations: json["nextSteps"] as? [String] ?? [],
            lateralMovementTargets: json["lateralMovement"] as? [String] ?? [],
            privilegeEscalationPaths: json["privilegeEscalation"] as? [String] ?? [],
            persistenceMechanisms: json["persistence"] as? [String] ?? []
        )
    }

    private func extractJSON(from text: String) -> String? {
        if let range = text.range(of: "\\{[\\s\\S]*\\}", options: .regularExpression) {
            return String(text[range])
        }
        return text.hasPrefix("{") ? text : nil
    }
}

// MARK: - Data Models

struct AttackPlan {
    let priorityTargets: [PriorityTarget]
    let attackChains: [AttackChain]
    let overallStrategy: String
}

struct PriorityTarget {
    let device: Device
    let reason: String
    let attackSequence: [String]
    let successProbability: Int // 0-100
    let timeToCompromise: String
    let pivotOpportunities: [String]
}

struct AttackChain {
    let description: String
    let steps: [String]
}

struct AttackRecommendation: Identifiable {
    let id = UUID()
    let name: String
    let type: AttackType
    let successProbability: Int // 0-100
    let impact: String
    let stealth: String
    let reasoning: String
}

enum AttackType: String, Codable {
    case credentialAttack = "credential_attack"
    case cveExploit = "cve_exploit"
    case webExploit = "web_exploit"
    case smbExploit = "smb_exploit"
    case privilegeEscalation = "privilege_escalation"
    case socialEngineering = "social_engineering"
    case other = "other"
}

struct PostExploitationPlan {
    let recommendations: [String]
    let lateralMovementTargets: [String]
    let privilegeEscalationPaths: [String]
    let persistenceMechanisms: [String]
}
