//
//  WidgetData.swift
//  Bastion Widget
//
//  Data models for widget display
//  Author: Jordan Koch
//  Date: 2026-02-04
//

import Foundation

/// Data model representing security scan results for widget display
struct WidgetScanData: Codable {
    /// Overall security score (0-100, where 100 is fully secure)
    let securityScore: Int

    /// Number of critical vulnerabilities found
    let criticalVulnerabilities: Int

    /// Number of high severity vulnerabilities
    let highVulnerabilities: Int

    /// Number of medium severity vulnerabilities
    let mediumVulnerabilities: Int

    /// Number of low severity vulnerabilities
    let lowVulnerabilities: Int

    /// Number of devices at risk (with any vulnerability)
    let devicesAtRisk: Int

    /// Total number of devices scanned
    let totalDevices: Int

    /// Timestamp of the last scan
    let lastScanTime: Date

    /// Whether a scan is currently in progress
    let isScanning: Bool

    /// Network that was scanned
    let networkCIDR: String

    /// Creates default placeholder data
    static var placeholder: WidgetScanData {
        WidgetScanData(
            securityScore: 85,
            criticalVulnerabilities: 0,
            highVulnerabilities: 2,
            mediumVulnerabilities: 5,
            lowVulnerabilities: 8,
            devicesAtRisk: 3,
            totalDevices: 12,
            lastScanTime: Date(),
            isScanning: false,
            networkCIDR: "192.168.1.0/24"
        )
    }

    /// Creates empty data for when no scan has been performed
    static var empty: WidgetScanData {
        WidgetScanData(
            securityScore: 100,
            criticalVulnerabilities: 0,
            highVulnerabilities: 0,
            mediumVulnerabilities: 0,
            lowVulnerabilities: 0,
            devicesAtRisk: 0,
            totalDevices: 0,
            lastScanTime: Date.distantPast,
            isScanning: false,
            networkCIDR: "Not scanned"
        )
    }

    /// Total number of vulnerabilities
    var totalVulnerabilities: Int {
        criticalVulnerabilities + highVulnerabilities + mediumVulnerabilities + lowVulnerabilities
    }

    /// Returns security status as a human-readable string
    var securityStatus: String {
        switch securityScore {
        case 90...100:
            return "Excellent"
        case 70..<90:
            return "Good"
        case 50..<70:
            return "Fair"
        case 25..<50:
            return "Poor"
        default:
            return "Critical"
        }
    }

    /// Returns a color name based on security score
    var statusColor: String {
        switch securityScore {
        case 90...100:
            return "green"
        case 70..<90:
            return "blue"
        case 50..<70:
            return "yellow"
        case 25..<50:
            return "orange"
        default:
            return "red"
        }
    }

    /// Formats the last scan time for display
    var lastScanFormatted: String {
        if lastScanTime == Date.distantPast {
            return "Never"
        }

        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.localizedString(for: lastScanTime, relativeTo: Date())
    }

    /// Returns whether the scan data is stale (older than 24 hours)
    var isStale: Bool {
        guard lastScanTime != Date.distantPast else { return true }
        return Date().timeIntervalSince(lastScanTime) > 86400 // 24 hours
    }
}

/// Timeline entry for widget updates
struct BastionWidgetEntry: Codable {
    let date: Date
    let scanData: WidgetScanData

    static var placeholder: BastionWidgetEntry {
        BastionWidgetEntry(date: Date(), scanData: .placeholder)
    }
}
