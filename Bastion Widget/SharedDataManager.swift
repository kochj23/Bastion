//
//  SharedDataManager.swift
//  Bastion Widget
//
//  Manages shared data between main app and widget via App Groups
//  Author: Jordan Koch
//  Date: 2026-02-04
//

import Foundation

/// Manages data sharing between the main Bastion app and its widget
/// Uses App Groups container for shared storage
final class SharedDataManager {
    /// Shared instance for singleton access
    static let shared = SharedDataManager()

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

    // MARK: - Write Methods (Called from Main App)

    /// Saves scan data to shared container for widget access
    /// - Parameter scanData: The scan data to save
    func saveScanData(_ scanData: WidgetScanData) {
        guard let defaults = sharedDefaults else {
            print("[SharedDataManager] Error: Could not access shared UserDefaults")
            return
        }

        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(scanData)
            defaults.set(data, forKey: scanDataKey)
            defaults.set(Date(), forKey: lastUpdateKey)
            defaults.synchronize()
            print("[SharedDataManager] Scan data saved successfully")
        } catch {
            print("[SharedDataManager] Error encoding scan data: \(error.localizedDescription)")
        }
    }

    /// Updates scan data from NetworkScanner results
    /// - Parameters:
    ///   - devices: Array of discovered devices
    ///   - networkCIDR: The network that was scanned
    ///   - isScanning: Whether scan is in progress
    func updateFromScanResults(
        devices: [Any], // Device type from main app
        networkCIDR: String,
        isScanning: Bool
    ) {
        // This method will be called from the main app
        // The main app will pass Device objects, but we use Any here
        // to avoid dependency issues in the widget target
    }

    // MARK: - Read Methods (Called from Widget)

    /// Loads scan data from shared container
    /// - Returns: The stored scan data, or empty data if none exists
    func loadScanData() -> WidgetScanData {
        guard let defaults = sharedDefaults,
              let data = defaults.data(forKey: scanDataKey) else {
            print("[SharedDataManager] No scan data found, returning empty")
            return .empty
        }

        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let scanData = try decoder.decode(WidgetScanData.self, from: data)
            return scanData
        } catch {
            print("[SharedDataManager] Error decoding scan data: \(error.localizedDescription)")
            return .empty
        }
    }

    /// Returns the timestamp of the last data update
    /// - Returns: Date of last update, or nil if never updated
    func lastUpdateTime() -> Date? {
        sharedDefaults?.object(forKey: lastUpdateKey) as? Date
    }

    /// Checks if shared data is available
    /// - Returns: True if scan data exists in shared container
    func hasData() -> Bool {
        sharedDefaults?.data(forKey: scanDataKey) != nil
    }

    /// Clears all shared data (for testing/reset)
    func clearData() {
        sharedDefaults?.removeObject(forKey: scanDataKey)
        sharedDefaults?.removeObject(forKey: lastUpdateKey)
        sharedDefaults?.synchronize()
    }
}

// MARK: - Main App Extension

/// Extension with methods specifically for the main Bastion app
extension SharedDataManager {

    /// Creates WidgetScanData from main app's Device array
    /// This is called from the main app after a scan completes
    /// - Parameters:
    ///   - securityScore: Calculated overall security score
    ///   - criticalVulns: Count of critical vulnerabilities
    ///   - highVulns: Count of high vulnerabilities
    ///   - mediumVulns: Count of medium vulnerabilities
    ///   - lowVulns: Count of low vulnerabilities
    ///   - devicesAtRisk: Count of devices with vulnerabilities
    ///   - totalDevices: Total devices discovered
    ///   - networkCIDR: Network that was scanned
    ///   - isScanning: Whether scan is in progress
    func updateWidgetData(
        securityScore: Int,
        criticalVulns: Int,
        highVulns: Int,
        mediumVulns: Int,
        lowVulns: Int,
        devicesAtRisk: Int,
        totalDevices: Int,
        networkCIDR: String,
        isScanning: Bool
    ) {
        let scanData = WidgetScanData(
            securityScore: securityScore,
            criticalVulnerabilities: criticalVulns,
            highVulnerabilities: highVulns,
            mediumVulnerabilities: mediumVulns,
            lowVulnerabilities: lowVulns,
            devicesAtRisk: devicesAtRisk,
            totalDevices: totalDevices,
            lastScanTime: Date(),
            isScanning: isScanning,
            networkCIDR: networkCIDR
        )
        saveScanData(scanData)
    }
}
