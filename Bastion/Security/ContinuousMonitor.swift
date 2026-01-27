//
//  ContinuousMonitor.swift
//  Bastion
//
//  Continuous security monitoring with scheduled scans and alerting
//  Tracks changes over time and detects anomalies
//  Author: Jordan Koch
//  Date: 2026-01-20
//

import Foundation
import UserNotifications

@MainActor
class ContinuousMonitor: ObservableObject {
    @Published var isMonitoring = false
    @Published var monitoringInterval: TimeInterval = 3600 // 1 hour
    @Published var lastScan: Date?
    @Published var nextScan: Date?
    @Published var alerts: [SecurityAlert] = []
    @Published var baselineSnapshot: NetworkSnapshot?
    @Published var scanHistory: [NetworkSnapshot] = []

    private var monitoringTask: Task<Void, Never>?
    private let networkScanner: NetworkScanner
    private let cveDatabase: CVEDatabase

    init(networkScanner: NetworkScanner, cveDatabase: CVEDatabase) {
        self.networkScanner = networkScanner
        self.cveDatabase = cveDatabase
        loadScanHistory()
        requestNotificationPermissions()
    }

    // MARK: - Monitoring Control

    /// Start continuous monitoring
    func startMonitoring(networkCIDR: String) {
        guard !isMonitoring else { return }

        isMonitoring = true
        print("📊 CONTINUOUS MONITORING: Started for \(networkCIDR)")

        monitoringTask = Task {
            while !Task.isCancelled && isMonitoring {
                await performScan(networkCIDR: networkCIDR)

                await MainActor.run {
                    lastScan = Date()
                    nextScan = Date().addingTimeInterval(monitoringInterval)
                }

                // Wait for next scan
                try? await Task.sleep(nanoseconds: UInt64(monitoringInterval * 1_000_000_000))
            }
        }
    }

    /// Stop continuous monitoring
    func stopMonitoring() {
        isMonitoring = false
        monitoringTask?.cancel()
        monitoringTask = nil
        print("📊 CONTINUOUS MONITORING: Stopped")
    }

    // MARK: - Scanning

    private func performScan(networkCIDR: String) async {
        print("📊 MONITORING SCAN: Starting scan at \(Date())")

        // Perform network scan
        try? await networkScanner.scanNetwork(cidr: networkCIDR)

        // Create snapshot
        let snapshot = NetworkSnapshot(
            scanDate: Date(),
            networkCIDR: networkCIDR,
            devices: networkScanner.discoveredDevices,
            totalVulnerabilities: networkScanner.discoveredDevices.reduce(0) { $0 + $1.vulnerabilities.count }
        )

        await MainActor.run {
            scanHistory.append(snapshot)

            // Keep last 100 scans
            if scanHistory.count > 100 {
                scanHistory.removeFirst()
            }

            saveScanHistory()
        }

        // Set baseline on first scan
        if baselineSnapshot == nil {
            await MainActor.run {
                baselineSnapshot = snapshot
            }
            print("📊 Baseline snapshot captured")
            return
        }

        // Compare with baseline
        await detectChanges(current: snapshot, baseline: baselineSnapshot!)
    }

    // MARK: - Change Detection

    private func detectChanges(current: NetworkSnapshot, baseline: NetworkSnapshot) async {
        var detectedAlerts: [SecurityAlert] = []

        // Detect new devices
        let newDeviceIPs = Set(current.devices.map { $0.ipAddress })
        let baselineIPs = Set(baseline.devices.map { $0.ipAddress })
        let addedDevices = newDeviceIPs.subtracting(baselineIPs)

        if !addedDevices.isEmpty {
            for ip in addedDevices {
                if let device = current.devices.first(where: { $0.ipAddress == ip }) {
                    let alert = SecurityAlert(
                        type: .newDevice,
                        severity: .medium,
                        title: "New Device Detected",
                        description: "New device joined network: \(ip) (\(device.hostname ?? "unknown"))",
                        affectedDevice: device,
                        timestamp: Date()
                    )
                    detectedAlerts.append(alert)
                    print("🚨 ALERT: New device - \(ip)")
                }
            }
        }

        // Detect removed devices
        let removedDevices = baselineIPs.subtracting(newDeviceIPs)
        if !removedDevices.isEmpty {
            for ip in removedDevices {
                let alert = SecurityAlert(
                    type: .deviceOffline,
                    severity: .low,
                    title: "Device Offline",
                    description: "Device no longer responding: \(ip)",
                    affectedDevice: nil,
                    timestamp: Date()
                )
                detectedAlerts.append(alert)
                print("⚠️ Device offline - \(ip)")
            }
        }

        // Detect new vulnerabilities on existing devices
        for currentDevice in current.devices {
            if let baselineDevice = baseline.devices.first(where: { $0.ipAddress == currentDevice.ipAddress }) {
                // Compare vulnerability counts
                if currentDevice.vulnerabilities.count > baselineDevice.vulnerabilities.count {
                    let alert = SecurityAlert(
                        type: .newVulnerability,
                        severity: .high,
                        title: "New Vulnerabilities Detected",
                        description: "\(currentDevice.vulnerabilities.count - baselineDevice.vulnerabilities.count) new vulnerabilities on \(currentDevice.ipAddress)",
                        affectedDevice: currentDevice,
                        timestamp: Date()
                    )
                    detectedAlerts.append(alert)
                    print("🚨 ALERT: New vulnerabilities - \(currentDevice.ipAddress)")
                }

                // Detect new open ports
                let currentPorts = Set(currentDevice.openPorts.map { $0.port })
                let baselinePorts = Set(baselineDevice.openPorts.map { $0.port })
                let newPorts = currentPorts.subtracting(baselinePorts)

                if !newPorts.isEmpty {
                    let alert = SecurityAlert(
                        type: .newOpenPort,
                        severity: .high,
                        title: "New Open Ports Detected",
                        description: "New ports on \(currentDevice.ipAddress): \(newPorts.sorted().map(String.init).joined(separator: ", "))",
                        affectedDevice: currentDevice,
                        timestamp: Date()
                    )
                    detectedAlerts.append(alert)
                    print("🚨 ALERT: New open ports - \(currentDevice.ipAddress)")
                }
            }
        }

        // Detect risk level increases
        for currentDevice in current.devices {
            if let baselineDevice = baseline.devices.first(where: { $0.ipAddress == currentDevice.ipAddress }) {
                if currentDevice.riskLevel.rawValue > baselineDevice.riskLevel.rawValue {
                    let alert = SecurityAlert(
                        type: .riskIncrease,
                        severity: .high,
                        title: "Risk Level Increased",
                        description: "\(currentDevice.ipAddress): \(baselineDevice.riskLevel.rawValue) → \(currentDevice.riskLevel.rawValue)",
                        affectedDevice: currentDevice,
                        timestamp: Date()
                    )
                    detectedAlerts.append(alert)
                    print("🚨 ALERT: Risk increased - \(currentDevice.ipAddress)")
                }
            }
        }

        // Add alerts to UI
        await MainActor.run {
            alerts.append(contentsOf: detectedAlerts)

            // Keep last 100 alerts
            if alerts.count > 100 {
                alerts.removeFirst(alerts.count - 100)
            }
        }

        // Send notifications for critical alerts
        for alert in detectedAlerts where alert.severity == .critical || alert.severity == .high {
            await sendNotification(alert: alert)
        }
    }

    // MARK: - Notifications

    private func requestNotificationPermissions() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if granted {
                print("📱 Notifications enabled")
            }
        }
    }

    private func sendNotification(alert: SecurityAlert) async {
        let content = UNMutableNotificationContent()
        content.title = "🚨 Bastion Security Alert"
        content.subtitle = alert.title
        content.body = alert.description
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: alert.id.uuidString,
            content: content,
            trigger: nil // Immediate
        )

        try? await UNUserNotificationCenter.current().add(request)
    }

    // MARK: - Baseline Management

    /// Capture current network state as baseline
    func captureBaseline(devices: [Device]) {
        let snapshot = NetworkSnapshot(
            scanDate: Date(),
            networkCIDR: "baseline",
            devices: devices,
            totalVulnerabilities: devices.reduce(0) { $0 + $1.vulnerabilities.count }
        )

        baselineSnapshot = snapshot
        scanHistory.append(snapshot)
        saveScanHistory()

        print("📊 Baseline captured: \(devices.count) devices, \(snapshot.totalVulnerabilities) vulnerabilities")
    }

    /// Reset baseline to current state
    func resetBaseline() {
        if let lastSnapshot = scanHistory.last {
            baselineSnapshot = lastSnapshot
            print("📊 Baseline reset to latest scan")
        }
    }

    // MARK: - Persistence

    private func saveScanHistory() {
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(scanHistory) else { return }

        let path = getHistoryPath()
        try? data.write(to: path)
    }

    private func loadScanHistory() {
        let decoder = JSONDecoder()
        let path = getHistoryPath()

        guard let data = try? Data(contentsOf: path),
              let history = try? decoder.decode([NetworkSnapshot].self, from: data) else {
            return
        }

        scanHistory = history
        baselineSnapshot = history.first
    }

    private func getHistoryPath() -> URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let bastionDir = appSupport.appendingPathComponent("Bastion", isDirectory: true)
        try? FileManager.default.createDirectory(at: bastionDir, withIntermediateDirectories: true)
        return bastionDir.appendingPathComponent("scan_history.json")
    }

    // MARK: - Analytics

    /// Get security trend (improving or degrading)
    func getSecurityTrend() -> SecurityTrend {
        guard scanHistory.count >= 2 else {
            return SecurityTrend(direction: .stable, change: 0)
        }

        let recent = scanHistory.suffix(10)
        let vulnerabilityCounts = recent.map { $0.totalVulnerabilities }

        guard let first = vulnerabilityCounts.first,
              let last = vulnerabilityCounts.last else {
            return SecurityTrend(direction: .stable, change: 0)
        }

        let change = last - first

        if change > 5 {
            return SecurityTrend(direction: .degrading, change: change)
        } else if change < -5 {
            return SecurityTrend(direction: .improving, change: abs(change))
        } else {
            return SecurityTrend(direction: .stable, change: 0)
        }
    }
}

// MARK: - Data Models

struct NetworkSnapshot: Codable, Identifiable {
    let id = UUID()
    let scanDate: Date
    let networkCIDR: String
    let devices: [Device]
    let totalVulnerabilities: Int

    var criticalCount: Int {
        devices.reduce(0) { $0 + $1.criticalVulnCount }
    }

    var highCount: Int {
        devices.reduce(0) { $0 + $1.highVulnCount }
    }
}

struct SecurityAlert: Identifiable {
    let id = UUID()
    let type: AlertType
    let severity: VulnerabilitySeverity
    let title: String
    let description: String
    let affectedDevice: Device?
    let timestamp: Date
}

enum AlertType: String, Codable {
    case newDevice = "New Device"
    case deviceOffline = "Device Offline"
    case newVulnerability = "New Vulnerability"
    case newOpenPort = "New Open Port"
    case riskIncrease = "Risk Increase"
    case suspiciousActivity = "Suspicious Activity"
    case configurationChange = "Configuration Change"
}

struct SecurityTrend {
    let direction: TrendDirection
    let change: Int // Absolute change in vulnerability count

    enum TrendDirection {
        case improving
        case degrading
        case stable
    }
}
