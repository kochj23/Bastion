//
//  WidgetDataSync.swift
//  Bastion
//
//  Syncs scan data to the widget via App Groups
//  Author: Jordan Koch
//  Date: 2026-02-04
//

import Foundation
import WidgetKit

/// Manages synchronization of scan data to the Bastion widget
final class WidgetDataSync {
    /// Shared instance for singleton access
    static let shared = WidgetDataSync()

    /// App Group identifier for shared container
    private let appGroupIdentifier = "group.com.jkoch.bastion"

    /// Key for storing scan data in UserDefaults
    private let scanDataKey = "BastionWidgetScanData"

    /// Key for storing last update timestamp
    private let lastUpdateKey = "BastionWidgetLastUpdate"

    /// Shared UserDefaults container
    private var sharedDefaults: UserDefaults? {
        UserDefaults(suiteName: appGroupIdentifier)
    }

    private init() {}

    // MARK: - Sync Methods

    /// Updates widget data from network scan results
    /// Call this after a scan completes or when significant changes occur
    /// - Parameters:
    ///   - devices: Array of discovered devices
    ///   - networkCIDR: The network that was scanned
    ///   - isScanning: Whether a scan is currently in progress
    func syncToWidget(devices: [Device], networkCIDR: String, isScanning: Bool) {
        // Calculate aggregated statistics
        var overallScore = 100
        var criticalCount = 0
        var highCount = 0
        var mediumCount = 0
        var lowCount = 0
        var devicesAtRisk = 0

        for device in devices {
            criticalCount += device.criticalVulnCount
            highCount += device.highVulnCount
            mediumCount += device.mediumVulnCount
            lowCount += device.lowVulnCount

            if !device.vulnerabilities.isEmpty {
                devicesAtRisk += 1
            }
        }

        // Calculate overall security score
        // Weight: Critical = -20, High = -10, Medium = -5, Low = -2
        overallScore -= criticalCount * 20
        overallScore -= highCount * 10
        overallScore -= mediumCount * 5
        overallScore -= lowCount * 2
        overallScore = max(0, min(100, overallScore))

        // Create scan data structure
        let scanData = WidgetScanDataForSync(
            securityScore: overallScore,
            criticalVulnerabilities: criticalCount,
            highVulnerabilities: highCount,
            mediumVulnerabilities: mediumCount,
            lowVulnerabilities: lowCount,
            devicesAtRisk: devicesAtRisk,
            totalDevices: devices.count,
            lastScanTime: Date(),
            isScanning: isScanning,
            networkCIDR: networkCIDR
        )

        // Save to shared container
        saveToSharedContainer(scanData)

        // Request widget refresh
        WidgetCenter.shared.reloadTimelines(ofKind: "BastionWidget")

        print("[WidgetDataSync] Widget data synced: Score=\(overallScore), Devices=\(devices.count), Critical=\(criticalCount)")
    }

    /// Updates the scanning status without changing other data
    /// - Parameter isScanning: Whether scanning is in progress
    func updateScanningStatus(_ isScanning: Bool) {
        guard let defaults = sharedDefaults,
              var scanData = loadCurrentData() else {
            return
        }

        scanData.isScanning = isScanning
        saveToSharedContainer(scanData)
        WidgetCenter.shared.reloadTimelines(ofKind: "BastionWidget")
    }

    // MARK: - Private Helpers

    private func saveToSharedContainer(_ scanData: WidgetScanDataForSync) {
        guard let defaults = sharedDefaults else {
            print("[WidgetDataSync] Error: Could not access shared UserDefaults")
            return
        }

        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(scanData)
            defaults.set(data, forKey: scanDataKey)
            defaults.set(Date(), forKey: lastUpdateKey)
            defaults.synchronize()
        } catch {
            print("[WidgetDataSync] Error encoding scan data: \(error.localizedDescription)")
        }
    }

    private func loadCurrentData() -> WidgetScanDataForSync? {
        guard let defaults = sharedDefaults,
              let data = defaults.data(forKey: scanDataKey) else {
            return nil
        }

        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return try decoder.decode(WidgetScanDataForSync.self, from: data)
        } catch {
            return nil
        }
    }
}

/// Internal struct for encoding/decoding - matches WidgetScanData in widget
private struct WidgetScanDataForSync: Codable {
    var securityScore: Int
    var criticalVulnerabilities: Int
    var highVulnerabilities: Int
    var mediumVulnerabilities: Int
    var lowVulnerabilities: Int
    var devicesAtRisk: Int
    var totalDevices: Int
    var lastScanTime: Date
    var isScanning: Bool
    var networkCIDR: String
}
