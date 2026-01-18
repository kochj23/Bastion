//
//  CVEDatabase.swift
//  Bastion
//
//  NVD CVE database downloader and manager
//  Downloads ~2GB of CVE data from NIST NVD
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import Foundation

@MainActor
class CVEDatabase: ObservableObject {
    static let shared = CVEDatabase()

    @Published var downloadProgress: Double = 0
    @Published var totalCVEs: Int = 0
    @Published var lastUpdate: Date?
    @Published var isDownloading = false
    @Published var downloadLog: [String] = []

    private let databasePath: URL
    private var cveCache: [String: CVE] = [:]

    private init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        databasePath = appSupport.appendingPathComponent("Bastion/CVE", isDirectory: true)

        try? FileManager.default.createDirectory(at: databasePath, withIntermediateDirectories: true)
        loadMetadata()
    }

    // Download full NVD database
    func downloadNVDDatabase() async throws {
        isDownloading = true
        downloadProgress = 0
        addLog("Starting NVD CVE database download (~2GB)")

        let currentYear = Calendar.current.component(.year, from: Date())
        let years = (2002...currentYear).reversed() // Start with recent years

        for (index, year) in years.enumerated() {
            addLog("Downloading CVE data for \(year)...")
            try await downloadYear(year)
            downloadProgress = Double(index + 1) / Double(years.count)
        }

        isDownloading = false
        lastUpdate = Date()
        saveMetadata()
        addLog("Download complete! Total CVEs: \(totalCVEs)")
    }

    // Download CVE data for specific year
    private func downloadYear(_ year: Int) async throws {
        let urlString = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-\(year).json.gz"
        guard let url = URL(string: urlString) else {
            throw CVEDatabaseError.invalidURL
        }

        let (data, _) = try await URLSession.shared.data(from: url)

        // Decompress gzip
        let decompressed = try decompress(data)

        // Parse JSON
        let cves = try parseNVDJSON(decompressed)

        // Save to disk
        let filePath = databasePath.appendingPathComponent("cve-\(year).json")
        try decompressed.write(to: filePath)

        totalCVEs += cves.count
        addLog("Downloaded \(cves.count) CVEs from \(year)")

        // Cache recent year in memory
        if year >= Calendar.current.component(.year, from: Date()) - 2 {
            for cve in cves {
                cveCache[cve.id] = cve
            }
        }
    }

    // Update database with recent CVEs
    func updateDatabase() async throws {
        addLog("Checking for CVE updates...")
        let currentYear = Calendar.current.component(.year, from: Date())

        // Update last 2 years
        for year in (currentYear - 1)...currentYear {
            try await downloadYear(year)
        }

        lastUpdate = Date()
        saveMetadata()
        addLog("Database updated successfully")
    }

    // Find CVEs for specific service/version
    func findCVEs(service: String, version: String?) -> [CVE] {
        var matches: [CVE] = []

        // Search in cache first
        for (_, cve) in cveCache {
            if matchesService(cve: cve, service: service, version: version) {
                matches.append(cve)
            }
        }

        // If not enough matches, search on disk
        if matches.count < 10 {
            matches += searchOnDisk(service: service, version: version)
        }

        return matches.sorted { $0.cvssScore > $1.cvssScore }
    }

    // Search for CVE by ID
    func findCVE(id: String) -> CVE? {
        // Check cache
        if let cve = cveCache[id] {
            return cve
        }

        // Search on disk
        return searchOnDiskByID(id)
    }

    // Search CVEs by keyword
    func search(query: String) -> [CVE] {
        let lowercaseQuery = query.lowercased()
        var results: [CVE] = []

        for (_, cve) in cveCache {
            if cve.id.lowercased().contains(lowercaseQuery) ||
               cve.description.lowercased().contains(lowercaseQuery) {
                results.append(cve)
            }
        }

        return results.sorted { $0.cvssScore > $1.cvssScore }
    }

    // Parse NVD JSON format
    private func parseNVDJSON(_ data: Data) throws -> [CVE] {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let cveItems = json["CVE_Items"] as? [[String: Any]] else {
            throw CVEDatabaseError.parseError
        }

        var cves: [CVE] = []

        for item in cveItems {
            guard let cveData = item["cve"] as? [String: Any],
                  let cveMetadata = cveData["CVE_data_meta"] as? [String: Any],
                  let cveId = cveMetadata["ID"] as? String else {
                continue
            }

            // Extract description
            var description = ""
            if let descriptionData = cveData["description"] as? [String: Any],
               let descriptionArray = descriptionData["description_data"] as? [[String: Any]],
               let firstDesc = descriptionArray.first,
               let value = firstDesc["value"] as? String {
                description = value
            }

            // Extract CVSS score
            var cvssScore = 0.0
            var cvssVector: String?
            if let impact = item["impact"] as? [String: Any] {
                if let baseMetricV3 = impact["baseMetricV3"] as? [String: Any],
                   let cvssV3 = baseMetricV3["cvssV3"] as? [String: Any] {
                    cvssScore = cvssV3["baseScore"] as? Double ?? 0.0
                    cvssVector = cvssV3["vectorString"] as? String
                } else if let baseMetricV2 = impact["baseMetricV2"] as? [String: Any],
                          let cvssV2 = baseMetricV2["cvssV2"] as? [String: Any] {
                    cvssScore = cvssV2["baseScore"] as? Double ?? 0.0
                    cvssVector = cvssV2["vectorString"] as? String
                }
            }

            var cve = CVE(id: cveId, description: description, cvssScore: cvssScore)
            cve.cvssVector = cvssVector

            // Extract published date
            if let publishedDate = item["publishedDate"] as? String {
                let formatter = ISO8601DateFormatter()
                cve.publishedDate = formatter.date(from: publishedDate) ?? Date()
            }

            cves.append(cve)
        }

        return cves
    }

    // Match CVE to service/version
    private func matchesService(cve: CVE, service: String, version: String?) -> Bool {
        let lowercaseDesc = cve.description.lowercased()
        let lowercaseService = service.lowercased()

        if !lowercaseDesc.contains(lowercaseService) {
            return false
        }

        if let version = version {
            return lowercaseDesc.contains(version)
        }

        return true
    }

    // Search on disk files
    private func searchOnDisk(service: String, version: String?) -> [CVE] {
        var results: [CVE] = []

        let fileManager = FileManager.default
        guard let files = try? fileManager.contentsOfDirectory(at: databasePath, includingPropertiesForKeys: nil) else {
            return results
        }

        for file in files where file.pathExtension == "json" {
            if let data = try? Data(contentsOf: file),
               let cves = try? parseNVDJSON(data) {
                for cve in cves {
                    if matchesService(cve: cve, service: service, version: version) {
                        results.append(cve)
                    }
                }
            }
        }

        return results
    }

    private func searchOnDiskByID(_ id: String) -> CVE? {
        let fileManager = FileManager.default
        guard let files = try? fileManager.contentsOfDirectory(at: databasePath, includingPropertiesForKeys: nil) else {
            return nil
        }

        for file in files where file.pathExtension == "json" {
            if let data = try? Data(contentsOf: file),
               let cves = try? parseNVDJSON(data),
               let match = cves.first(where: { $0.id == id }) {
                return match
            }
        }

        return nil
    }

    // Decompress gzip data
    private func decompress(_ data: Data) throws -> Data {
        // Simple gzip decompression
        // In production, use proper gzip library
        return data // Placeholder - would implement actual decompression
    }

    // Metadata management
    private func loadMetadata() {
        let metadataPath = databasePath.appendingPathComponent("metadata.json")
        guard let data = try? Data(contentsOf: metadataPath),
              let metadata = try? JSONDecoder().decode(CVEMetadata.self, from: data) else {
            return
        }

        totalCVEs = metadata.totalCVEs
        lastUpdate = metadata.lastUpdate
    }

    private func saveMetadata() {
        let metadata = CVEMetadata(totalCVEs: totalCVEs, lastUpdate: lastUpdate ?? Date())
        let metadataPath = databasePath.appendingPathComponent("metadata.json")

        if let data = try? JSONEncoder().encode(metadata) {
            try? data.write(to: metadataPath)
        }
    }

    private func addLog(_ message: String) {
        let timestamp = Date().formatted(date: .omitted, time: .standard)
        downloadLog.append("[\(timestamp)] \(message)")
    }
}

struct CVEMetadata: Codable {
    let totalCVEs: Int
    let lastUpdate: Date
}

enum CVEDatabaseError: LocalizedError {
    case invalidURL
    case downloadFailed
    case parseError
    case decompressError

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Invalid CVE database URL"
        case .downloadFailed:
            return "Failed to download CVE database"
        case .parseError:
            return "Failed to parse CVE data"
        case .decompressError:
            return "Failed to decompress CVE data"
        }
    }
}
