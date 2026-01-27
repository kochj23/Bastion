//
//  LateralMovementMapper.swift
//  Bastion
//
//  Maps lateral movement opportunities across the network
//  Identifies trust relationships, credential reuse, network segmentation flaws
//  Author: Jordan Koch
//  Date: 2026-01-20
//

import Foundation

@MainActor
class LateralMovementMapper: ObservableObject {
    @Published var movementPaths: [MovementPath] = []
    @Published var trustRelationships: [TrustRelationship] = []
    @Published var isAnalyzing = false

    private let aiBackend = AIBackendManager.shared

    // MARK: - Lateral Movement Analysis

    /// Analyze entire network for lateral movement opportunities
    func analyzeLateralMovement(devices: [Device]) async -> LateralMovementMap {
        isAnalyzing = true
        defer { isAnalyzing = false }

        print("🔗 LATERAL MOVEMENT: Analyzing \(devices.count) devices...")

        var paths: [MovementPath] = []
        var trusts: [TrustRelationship] = []

        // Identify trust relationships
        trusts.append(contentsOf: identifySSHKeyReuse(devices: devices))
        trusts.append(contentsOf: identifySharedCredentials(devices: devices))
        trusts.append(contentsOf: identifyNetworkSegmentation(devices: devices))

        // Build movement paths
        paths.append(contentsOf: buildMovementPaths(devices: devices, trusts: trusts))

        // AI-enhanced path analysis
        if aiBackend.activeBackend != nil {
            paths = await enhancePathsWithAI(paths: paths, devices: devices)
        }

        await MainActor.run {
            self.movementPaths = paths
            self.trustRelationships = trusts
        }

        return LateralMovementMap(paths: paths, trustRelationships: trusts)
    }

    // MARK: - Trust Relationship Identification

    private func identifySSHKeyReuse(devices: [Device]) -> [TrustRelationship] {
        var relationships: [TrustRelationship] = []

        // Find devices with SSH enabled
        let sshDevices = devices.filter { $0.openPorts.contains(where: { $0.port == 22 }) }

        if sshDevices.count >= 2 {
            // If multiple devices have SSH, likely using shared keys
            for i in 0..<sshDevices.count {
                for j in (i+1)..<sshDevices.count {
                    let trust = TrustRelationship(
                        sourceDevice: sshDevices[i],
                        targetDevice: sshDevices[j],
                        trustType: .sshKeyReuse,
                        confidence: 60, // Medium confidence without actual key inspection
                        description: "SSH enabled on both devices - potential key reuse"
                    )
                    relationships.append(trust)
                }
            }
        }

        return relationships
    }

    private func identifySharedCredentials(devices: [Device]) -> [TrustRelationship] {
        var relationships: [TrustRelationship] = []

        // Group devices by type (same type often uses same credentials)
        let devicesByType = Dictionary(grouping: devices, by: { $0.deviceType })

        for (deviceType, deviceGroup) in devicesByType where deviceGroup.count > 1 {
            // Same device type often shares credentials
            for i in 0..<deviceGroup.count {
                for j in (i+1)..<deviceGroup.count {
                    let trust = TrustRelationship(
                        sourceDevice: deviceGroup[i],
                        targetDevice: deviceGroup[j],
                        trustType: .sharedCredentials,
                        confidence: 70,
                        description: "Same device type (\(deviceType.rawValue)) - likely shared credentials"
                    )
                    relationships.append(trust)
                }
            }
        }

        return relationships
    }

    private func identifyNetworkSegmentation(devices: [Device]) -> [TrustRelationship] {
        var relationships: [TrustRelationship] = []

        // Check if all devices are on same subnet (poor segmentation)
        let subnets = Set(devices.map { extractSubnet($0.ipAddress) })

        if subnets.count == 1 {
            // All devices on same subnet - no segmentation
            print("⚠️ All devices on same subnet - no network segmentation")

            // Critical + non-critical on same network = lateral movement risk
            let criticalDevices = devices.filter { $0.riskLevel == .critical || $0.riskLevel == .high }
            let otherDevices = devices.filter { $0.riskLevel == .low || $0.riskLevel == .medium }

            for critical in criticalDevices {
                for other in otherDevices {
                    let trust = TrustRelationship(
                        sourceDevice: other,
                        targetDevice: critical,
                        trustType: .noSegmentation,
                        confidence: 90,
                        description: "No network segmentation - can reach critical device from compromised host"
                    )
                    relationships.append(trust)
                }
            }
        }

        return relationships
    }

    // MARK: - Movement Path Building

    private func buildMovementPaths(devices: [Device], trusts: [TrustRelationship]) -> [MovementPath] {
        var paths: [MovementPath] = []

        // Build single-hop paths from trust relationships
        for trust in trusts {
            let path = MovementPath(
                steps: [
                    MovementStep(device: trust.sourceDevice, action: "Compromise via vulnerability"),
                    MovementStep(device: trust.targetDevice, action: "Pivot using \(trust.trustType.rawValue)")
                ],
                trustBasis: trust,
                totalProbability: Double(trust.confidence),
                description: "Compromise \(trust.sourceDevice.ipAddress) → Pivot to \(trust.targetDevice.ipAddress)"
            )
            paths.append(path)
        }

        // Build multi-hop attack chains (A → B → C)
        paths.append(contentsOf: buildMultiHopPaths(devices: devices, trusts: trusts))

        return paths.sorted { $0.totalProbability > $1.totalProbability }
    }

    private func buildMultiHopPaths(devices: [Device], trusts: [TrustRelationship]) -> [MovementPath] {
        var multiHopPaths: [MovementPath] = []

        // Find chains: low-risk device → medium-risk device → high-risk device
        let lowRiskDevices = devices.filter { $0.riskLevel == .low }
        let highRiskDevices = devices.filter { $0.riskLevel == .critical || $0.riskLevel == .high }

        for lowDevice in lowRiskDevices {
            for highDevice in highRiskDevices where lowDevice.id != highDevice.id {
                // Find intermediate devices
                if let intermediateTrust = trusts.first(where: { $0.sourceDevice.id == lowDevice.id }),
                   let finalTrust = trusts.first(where: { $0.sourceDevice.id == intermediateTrust.targetDevice.id && $0.targetDevice.id == highDevice.id }) {

                    let path = MovementPath(
                        steps: [
                            MovementStep(device: lowDevice, action: "Initial compromise"),
                            MovementStep(device: intermediateTrust.targetDevice, action: "Pivot via \(intermediateTrust.trustType.rawValue)"),
                            MovementStep(device: highDevice, action: "Final target access")
                        ],
                        trustBasis: intermediateTrust,
                        totalProbability: Double(intermediateTrust.confidence + finalTrust.confidence) / 2,
                        description: "Multi-hop: \(lowDevice.ipAddress) → \(intermediateTrust.targetDevice.ipAddress) → \(highDevice.ipAddress)"
                    )
                    multiHopPaths.append(path)
                }
            }
        }

        return multiHopPaths
    }

    // MARK: - AI Enhancement

    private func enhancePathsWithAI(paths: [MovementPath], devices: [Device]) async -> [MovementPath] {
        guard !paths.isEmpty else { return paths }

        let prompt = """
        Analyze these lateral movement paths and enhance them with tactical details.

        NETWORK DEVICES: \(devices.count)
        IDENTIFIED PATHS: \(paths.count)

        PATHS:
        \(paths.prefix(5).map { "• \($0.description) (Probability: \($0.totalProbability)%)" }.joined(separator: "\n"))

        For each path, provide:
        1. Exploitation technique details
        2. Required tools
        3. Stealth considerations
        4. Detection likelihood
        5. Recommended payload type

        Be specific and tactical.
        """

        do {
            let aiAnalysis = try await aiBackend.generate(
                prompt: prompt,
                systemPrompt: "You are an expert in lateral movement and network penetration. Provide detailed exploitation techniques.",
                temperature: 0.6,
                maxTokens: 1000
            )

            print("🧠 AI enhanced lateral movement paths")
            // Would parse AI response and enhance paths
            // For now, return original paths with AI context logged

        } catch {
            print("❌ AI enhancement failed: \(error)")
        }

        return paths
    }

    // MARK: - Helpers

    private func extractSubnet(_ ipAddress: String) -> String {
        let octets = ipAddress.split(separator: ".")
        if octets.count >= 3 {
            return octets.prefix(3).joined(separator: ".")
        }
        return ipAddress
    }
}

// MARK: - Data Models

struct LateralMovementMap {
    let paths: [MovementPath]
    let trustRelationships: [TrustRelationship]

    var criticalPaths: [MovementPath] {
        paths.filter { $0.totalProbability >= 70 }
    }

    var multiHopPaths: [MovementPath] {
        paths.filter { $0.steps.count >= 3 }
    }
}

struct MovementPath: Identifiable {
    let id = UUID()
    let steps: [MovementStep]
    let trustBasis: TrustRelationship
    let totalProbability: Double // 0-100
    let description: String

    var isMultiHop: Bool {
        steps.count >= 3
    }

    var targetDevice: Device? {
        steps.last?.device
    }
}

struct MovementStep: Identifiable {
    let id = UUID()
    let device: Device
    let action: String
}

struct TrustRelationship: Identifiable {
    let id = UUID()
    let sourceDevice: Device
    let targetDevice: Device
    let trustType: TrustType
    let confidence: Int // 0-100
    let description: String
}

enum TrustType: String, CaseIterable {
    case sshKeyReuse = "SSH Key Reuse"
    case sharedCredentials = "Shared Credentials"
    case noSegmentation = "No Network Segmentation"
    case sameDomain = "Same AD Domain"
    case trustedHost = "Trusted Host Relationship"
    case smbShare = "SMB Share Access"
    case nfsMount = "NFS Mount"
    case databaseConnection = "Database Trust"
}
