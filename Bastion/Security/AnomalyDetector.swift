//
//  AnomalyDetector.swift
//  Bastion
//
//  ML-based anomaly detection for network security
//  Learns normal behavior patterns and detects deviations
//  Author: Jordan Koch
//  Date: 2026-01-20
//

import Foundation
import CreateML
import CoreML

@MainActor
class AnomalyDetector: ObservableObject {
    @Published var anomalies: [Anomaly] = []
    @Published var isTraining = false
    @Published var modelTrained = false

    private var behaviorProfiles: [String: DeviceBehaviorProfile] = [:]
    private let aiBackend = AIBackendManager.shared

    // MARK: - Behavior Learning

    /// Learn normal behavior from scan history
    func learnBaseline(scanHistory: [NetworkSnapshot]) async {
        print("🧠 ANOMALY DETECTION: Learning baseline from \(scanHistory.count) scans...")

        // Build behavior profiles for each device
        var profiles: [String: DeviceBehaviorProfile] = [:]

        for snapshot in scanHistory {
            for device in snapshot.devices {
                if profiles[device.ipAddress] == nil {
                    profiles[device.ipAddress] = DeviceBehaviorProfile(ipAddress: device.ipAddress)
                }

                profiles[device.ipAddress]?.addObservation(device: device)
            }
        }

        await MainActor.run {
            self.behaviorProfiles = profiles
            self.modelTrained = true
        }

        print("🧠 Learned profiles for \(profiles.count) devices")
    }

    // MARK: - Anomaly Detection

    /// Detect anomalies in current scan compared to learned baseline
    func detectAnomalies(devices: [Device]) async -> [Anomaly] {
        guard modelTrained else {
            print("⚠️ Model not trained - run learnBaseline() first")
            return []
        }

        var detectedAnomalies: [Anomaly] = []

        for device in devices {
            guard let profile = behaviorProfiles[device.ipAddress] else {
                // New device not in baseline
                let anomaly = Anomaly(
                    type: .newDevice,
                    severity: .medium,
                    device: device,
                    description: "Device not in baseline: \(device.ipAddress)",
                    anomalyScore: 80,
                    timestamp: Date()
                )
                detectedAnomalies.append(anomaly)
                continue
            }

            // Check for port anomalies
            let currentPorts = Set(device.openPorts.map { $0.port })
            let normalPorts = profile.normalPorts

            let unexpectedPorts = currentPorts.subtracting(normalPorts)
            if !unexpectedPorts.isEmpty {
                let anomaly = Anomaly(
                    type: .unexpectedPorts,
                    severity: .high,
                    device: device,
                    description: "Unexpected ports open: \(unexpectedPorts.sorted().map(String.init).joined(separator: ", "))",
                    anomalyScore: 90,
                    timestamp: Date()
                )
                detectedAnomalies.append(anomaly)
            }

            // Check for service changes
            let currentServices = Set(device.services.map { $0.name })
            let normalServices = profile.normalServices

            let newServices = currentServices.subtracting(normalServices)
            if !newServices.isEmpty {
                let anomaly = Anomaly(
                    type: .serviceChange,
                    severity: .medium,
                    device: device,
                    description: "New services detected: \(newServices.sorted().joined(separator: ", "))",
                    anomalyScore: 70,
                    timestamp: Date()
                )
                detectedAnomalies.append(anomaly)
            }

            // Check for vulnerability spike
            if Double(device.vulnerabilities.count) > profile.averageVulnCount + (profile.stdDevVulnCount * 2) {
                let anomaly = Anomaly(
                    type: .vulnerabilitySpike,
                    severity: .critical,
                    device: device,
                    description: "Vulnerability spike: \(device.vulnerabilities.count) vs normal \(Int(profile.averageVulnCount))",
                    anomalyScore: 95,
                    timestamp: Date()
                )
                detectedAnomalies.append(anomaly)
            }

            // Check for suspicious service combinations
            if device.openPorts.contains(where: { $0.port == 4444 || $0.port == 5555 || $0.port == 6666 }) {
                // Common backdoor ports
                let anomaly = Anomaly(
                    type: .suspiciousPort,
                    severity: .critical,
                    device: device,
                    description: "Suspicious backdoor port detected on \(device.ipAddress)",
                    anomalyScore: 100,
                    timestamp: Date()
                )
                detectedAnomalies.append(anomaly)
            }
        }

        // AI-enhanced anomaly analysis
        if aiBackend.activeBackend != nil && !detectedAnomalies.isEmpty {
            detectedAnomalies = await enhanceWithAI(anomalies: detectedAnomalies)
        }

        await MainActor.run {
            self.anomalies.append(contentsOf: detectedAnomalies)
        }

        print("🧠 Detected \(detectedAnomalies.count) anomalies")
        return detectedAnomalies
    }

    // MARK: - AI Enhancement

    private func enhanceWithAI(anomalies: [Anomaly]) async -> [Anomaly] {
        let prompt = """
        Analyze these network anomalies and assess their security significance.

        ANOMALIES DETECTED (\(anomalies.count)):
        \(anomalies.map { "• \($0.type.rawValue): \($0.description)" }.joined(separator: "\n"))

        For each anomaly, provide:
        1. Is this likely malicious, suspicious, or benign?
        2. What could have caused this change?
        3. Immediate action required?
        4. Adjusted risk score (0-100)

        Be specific and actionable.
        """

        do {
            let analysis = try await aiBackend.generate(
                prompt: prompt,
                systemPrompt: "You are a security analyst assessing network anomalies. Distinguish between benign changes and security incidents.",
                temperature: 0.5,
                maxTokens: 800
            )

            print("🧠 AI enhanced anomaly analysis")
            // Would parse AI response and update anomaly scores
            // For now, return original anomalies
        } catch {
            print("❌ AI enhancement failed: \(error)")
        }

        return anomalies
    }

    // MARK: - Behavior Profiling

    /// Get behavioral summary for device
    func getDeviceProfile(ipAddress: String) -> DeviceBehaviorProfile? {
        return behaviorProfiles[ipAddress]
    }

    /// Export all profiles for analysis
    func exportProfiles() -> String {
        var export = "# Bastion Device Behavior Profiles\n"
        export += "# Generated: \(Date().formatted())\n\n"

        for (ip, profile) in behaviorProfiles.sorted(by: { $0.key < $1.key }) {
            export += "Device: \(ip)\n"
            export += "  Observations: \(profile.observationCount)\n"
            export += "  Normal Ports: \(profile.normalPorts.sorted().map(String.init).joined(separator: ", "))\n"
            export += "  Normal Services: \(profile.normalServices.sorted().joined(separator: ", "))\n"
            export += "  Avg Vulnerabilities: \(Int(profile.averageVulnCount))\n"
            export += "  Last Seen: \(profile.lastSeen.formatted())\n\n"
        }

        return export
    }
}

// MARK: - Data Models

struct DeviceBehaviorProfile {
    let ipAddress: String
    var observationCount: Int = 0
    var normalPorts: Set<Int> = []
    var normalServices: Set<String> = []
    var vulnCounts: [Int] = []
    var lastSeen: Date = Date()

    var averageVulnCount: Double {
        guard !vulnCounts.isEmpty else { return 0 }
        return Double(vulnCounts.reduce(0, +)) / Double(vulnCounts.count)
    }

    var stdDevVulnCount: Double {
        guard vulnCounts.count > 1 else { return 0 }

        let mean = averageVulnCount
        let squaredDiffs = vulnCounts.map { pow(Double($0) - mean, 2) }
        let variance = squaredDiffs.reduce(0, +) / Double(vulnCounts.count)
        return sqrt(variance)
    }

    mutating func addObservation(device: Device) {
        observationCount += 1
        lastSeen = Date()

        // Track ports
        for port in device.openPorts {
            normalPorts.insert(port.port)
        }

        // Track services
        for service in device.services {
            normalServices.insert(service.name)
        }

        // Track vulnerability count
        vulnCounts.append(device.vulnerabilities.count)

        // Keep last 30 observations
        if vulnCounts.count > 30 {
            vulnCounts.removeFirst()
        }
    }
}

struct Anomaly: Identifiable {
    let id = UUID()
    let type: AnomalyType
    let severity: VulnerabilitySeverity
    let device: Device
    let description: String
    let anomalyScore: Int // 0-100 (higher = more anomalous)
    let timestamp: Date
}

enum AnomalyType: String, Codable {
    case newDevice = "New Device"
    case deviceOffline = "Device Offline"
    case unexpectedPorts = "Unexpected Open Ports"
    case serviceChange = "Service Configuration Change"
    case vulnerabilitySpike = "Vulnerability Spike"
    case suspiciousPort = "Suspicious Port"
    case behaviorChange = "Behavioral Anomaly"
    case trafficAnomaly = "Traffic Pattern Anomaly"
}
