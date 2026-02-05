//
//  BastionWidget.swift
//  Bastion Widget
//
//  WidgetKit widget showing network security status
//  Supports Small, Medium, and Large widget sizes
//  Author: Jordan Koch
//  Date: 2026-02-04
//

import WidgetKit
import SwiftUI

// MARK: - Timeline Provider

struct BastionWidgetProvider: TimelineProvider {
    typealias Entry = BastionTimelineEntry

    func placeholder(in context: Context) -> BastionTimelineEntry {
        BastionTimelineEntry(date: Date(), scanData: .placeholder)
    }

    func getSnapshot(in context: Context, completion: @escaping (BastionTimelineEntry) -> Void) {
        let scanData = SharedDataManager.shared.loadScanData()
        let entry = BastionTimelineEntry(date: Date(), scanData: scanData)
        completion(entry)
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<BastionTimelineEntry>) -> Void) {
        let scanData = SharedDataManager.shared.loadScanData()
        let entry = BastionTimelineEntry(date: Date(), scanData: scanData)

        // Update widget every 15 minutes
        let nextUpdate = Calendar.current.date(byAdding: .minute, value: 15, to: Date())!
        let timeline = Timeline(entries: [entry], policy: .after(nextUpdate))
        completion(timeline)
    }
}

// MARK: - Timeline Entry

struct BastionTimelineEntry: TimelineEntry {
    let date: Date
    let scanData: WidgetScanData
}

// MARK: - Widget Views

/// Small widget view - Shows security score and critical count
struct SmallWidgetView: View {
    let scanData: WidgetScanData

    var body: some View {
        VStack(spacing: 8) {
            // Security Score Circle
            ZStack {
                Circle()
                    .stroke(Color.gray.opacity(0.3), lineWidth: 8)

                Circle()
                    .trim(from: 0, to: CGFloat(scanData.securityScore) / 100.0)
                    .stroke(scoreColor, style: StrokeStyle(lineWidth: 8, lineCap: .round))
                    .rotationEffect(.degrees(-90))

                VStack(spacing: 0) {
                    Text("\(scanData.securityScore)")
                        .font(.system(size: 28, weight: .bold, design: .rounded))
                        .foregroundColor(.primary)

                    Text("Score")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(.secondary)
                }
            }
            .frame(width: 70, height: 70)

            // Critical vulnerabilities
            if scanData.criticalVulnerabilities > 0 {
                HStack(spacing: 4) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.red)
                        .font(.system(size: 12))

                    Text("\(scanData.criticalVulnerabilities) Critical")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.red)
                }
            } else {
                HStack(spacing: 4) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundColor(.green)
                        .font(.system(size: 12))

                    Text("Secure")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.green)
                }
            }

            // Last scan time
            Text(scanData.lastScanFormatted)
                .font(.system(size: 9))
                .foregroundColor(.secondary)
        }
        .padding()
        .containerBackground(for: .widget) {
            Color(nsColor: .windowBackgroundColor)
        }
    }

    private var scoreColor: Color {
        switch scanData.securityScore {
        case 90...100: return .green
        case 70..<90: return .blue
        case 50..<70: return .yellow
        case 25..<50: return .orange
        default: return .red
        }
    }
}

/// Medium widget view - Shows score, vulnerabilities breakdown, and devices
struct MediumWidgetView: View {
    let scanData: WidgetScanData

    var body: some View {
        HStack(spacing: 16) {
            // Left side - Security Score
            VStack(spacing: 8) {
                ZStack {
                    Circle()
                        .stroke(Color.gray.opacity(0.3), lineWidth: 10)

                    Circle()
                        .trim(from: 0, to: CGFloat(scanData.securityScore) / 100.0)
                        .stroke(scoreColor, style: StrokeStyle(lineWidth: 10, lineCap: .round))
                        .rotationEffect(.degrees(-90))

                    VStack(spacing: 0) {
                        Text("\(scanData.securityScore)")
                            .font(.system(size: 32, weight: .bold, design: .rounded))
                            .foregroundColor(.primary)

                        Text("Score")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(.secondary)
                    }
                }
                .frame(width: 90, height: 90)

                Text(scanData.securityStatus)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(scoreColor)
            }

            // Right side - Stats
            VStack(alignment: .leading, spacing: 8) {
                // Vulnerabilities
                HStack(spacing: 12) {
                    VulnBadge(count: scanData.criticalVulnerabilities, severity: "Critical", color: .red)
                    VulnBadge(count: scanData.highVulnerabilities, severity: "High", color: .orange)
                }

                HStack(spacing: 12) {
                    VulnBadge(count: scanData.mediumVulnerabilities, severity: "Medium", color: .yellow)
                    VulnBadge(count: scanData.lowVulnerabilities, severity: "Low", color: .blue)
                }

                Divider()

                // Devices
                HStack {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundColor(.orange)
                        .font(.system(size: 12))

                    Text("\(scanData.devicesAtRisk) at risk")
                        .font(.system(size: 11, weight: .medium))

                    Spacer()

                    Text("\(scanData.totalDevices) devices")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }

                // Last scan
                HStack {
                    Image(systemName: "clock")
                        .foregroundColor(.secondary)
                        .font(.system(size: 10))

                    Text(scanData.lastScanFormatted)
                        .font(.system(size: 10))
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding()
        .containerBackground(for: .widget) {
            Color(nsColor: .windowBackgroundColor)
        }
    }

    private var scoreColor: Color {
        switch scanData.securityScore {
        case 90...100: return .green
        case 70..<90: return .blue
        case 50..<70: return .yellow
        case 25..<50: return .orange
        default: return .red
        }
    }
}

/// Large widget view - Full security dashboard
struct LargeWidgetView: View {
    let scanData: WidgetScanData

    var body: some View {
        VStack(spacing: 12) {
            // Header
            HStack {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundColor(.blue)

                Text("BASTION")
                    .font(.system(size: 18, weight: .bold, design: .rounded))

                Spacer()

                if scanData.isScanning {
                    HStack(spacing: 4) {
                        ProgressView()
                            .scaleEffect(0.7)
                        Text("Scanning...")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                } else {
                    Text(scanData.networkCIDR)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary)
                }
            }

            Divider()

            HStack(spacing: 20) {
                // Security Score
                VStack(spacing: 4) {
                    ZStack {
                        Circle()
                            .stroke(Color.gray.opacity(0.3), lineWidth: 12)

                        Circle()
                            .trim(from: 0, to: CGFloat(scanData.securityScore) / 100.0)
                            .stroke(scoreColor, style: StrokeStyle(lineWidth: 12, lineCap: .round))
                            .rotationEffect(.degrees(-90))

                        VStack(spacing: 0) {
                            Text("\(scanData.securityScore)")
                                .font(.system(size: 36, weight: .bold, design: .rounded))
                                .foregroundColor(.primary)

                            Text("Score")
                                .font(.system(size: 12, weight: .medium))
                                .foregroundColor(.secondary)
                        }
                    }
                    .frame(width: 100, height: 100)

                    Text(scanData.securityStatus)
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundColor(scoreColor)
                }

                // Vulnerabilities Grid
                VStack(spacing: 8) {
                    Text("Vulnerabilities")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(.secondary)

                    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                        VulnCard(count: scanData.criticalVulnerabilities, label: "Critical", color: .red)
                        VulnCard(count: scanData.highVulnerabilities, label: "High", color: .orange)
                        VulnCard(count: scanData.mediumVulnerabilities, label: "Medium", color: .yellow)
                        VulnCard(count: scanData.lowVulnerabilities, label: "Low", color: .blue)
                    }
                }
            }

            Divider()

            // Devices section
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Network Devices")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(.secondary)

                    HStack(spacing: 20) {
                        HStack(spacing: 4) {
                            Image(systemName: "network")
                                .foregroundColor(.blue)
                            Text("\(scanData.totalDevices)")
                                .font(.system(size: 16, weight: .bold))
                            Text("Total")
                                .font(.system(size: 11))
                                .foregroundColor(.secondary)
                        }

                        HStack(spacing: 4) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange)
                            Text("\(scanData.devicesAtRisk)")
                                .font(.system(size: 16, weight: .bold))
                                .foregroundColor(.orange)
                            Text("At Risk")
                                .font(.system(size: 11))
                                .foregroundColor(.secondary)
                        }
                    }
                }

                Spacer()

                // Last scan info
                VStack(alignment: .trailing, spacing: 2) {
                    Text("Last Scan")
                        .font(.system(size: 10))
                        .foregroundColor(.secondary)

                    Text(scanData.lastScanFormatted)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(scanData.isStale ? .orange : .primary)

                    if scanData.isStale {
                        Text("Scan recommended")
                            .font(.system(size: 9))
                            .foregroundColor(.orange)
                    }
                }
            }
        }
        .padding()
        .containerBackground(for: .widget) {
            Color(nsColor: .windowBackgroundColor)
        }
    }

    private var scoreColor: Color {
        switch scanData.securityScore {
        case 90...100: return .green
        case 70..<90: return .blue
        case 50..<70: return .yellow
        case 25..<50: return .orange
        default: return .red
        }
    }
}

// MARK: - Helper Views

struct VulnBadge: View {
    let count: Int
    let severity: String
    let color: Color

    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)

            Text("\(count)")
                .font(.system(size: 12, weight: .bold, design: .rounded))

            Text(severity)
                .font(.system(size: 9))
                .foregroundColor(.secondary)
        }
    }
}

struct VulnCard: View {
    let count: Int
    let label: String
    let color: Color

    var body: some View {
        VStack(spacing: 2) {
            Text("\(count)")
                .font(.system(size: 18, weight: .bold, design: .rounded))
                .foregroundColor(count > 0 ? color : .secondary)

            Text(label)
                .font(.system(size: 9))
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(color.opacity(count > 0 ? 0.15 : 0.05))
        )
    }
}

// MARK: - Main Widget View

struct BastionWidgetEntryView: View {
    @Environment(\.widgetFamily) var family
    var entry: BastionWidgetProvider.Entry

    var body: some View {
        switch family {
        case .systemSmall:
            SmallWidgetView(scanData: entry.scanData)
        case .systemMedium:
            MediumWidgetView(scanData: entry.scanData)
        case .systemLarge:
            LargeWidgetView(scanData: entry.scanData)
        default:
            SmallWidgetView(scanData: entry.scanData)
        }
    }
}

// MARK: - Widget Configuration

@main
struct BastionWidget: Widget {
    let kind: String = "BastionWidget"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: kind, provider: BastionWidgetProvider()) { entry in
            BastionWidgetEntryView(entry: entry)
        }
        .configurationDisplayName("Bastion Security")
        .description("Monitor your network security status at a glance.")
        .supportedFamilies([.systemSmall, .systemMedium, .systemLarge])
    }
}

// MARK: - Preview

#Preview(as: .systemSmall) {
    BastionWidget()
} timeline: {
    BastionTimelineEntry(date: .now, scanData: .placeholder)
    BastionTimelineEntry(date: .now, scanData: WidgetScanData(
        securityScore: 45,
        criticalVulnerabilities: 3,
        highVulnerabilities: 5,
        mediumVulnerabilities: 8,
        lowVulnerabilities: 12,
        devicesAtRisk: 6,
        totalDevices: 15,
        lastScanTime: Date().addingTimeInterval(-3600),
        isScanning: false,
        networkCIDR: "192.168.1.0/24"
    ))
}

#Preview(as: .systemMedium) {
    BastionWidget()
} timeline: {
    BastionTimelineEntry(date: .now, scanData: .placeholder)
}

#Preview(as: .systemLarge) {
    BastionWidget()
} timeline: {
    BastionTimelineEntry(date: .now, scanData: .placeholder)
}
