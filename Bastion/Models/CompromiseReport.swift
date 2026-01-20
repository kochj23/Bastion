//
//  CompromiseReport.swift
//  Bastion
//
//  Post-compromise assessment report model
//  Author: Jordan Koch
//  Date: 2025-01-20
//

import Foundation

/// Comprehensive post-compromise assessment report
struct CompromiseReport: Identifiable, Codable {
    let id: UUID
    let targetIP: String
    let scanDate: Date
    var isCompromised: Bool
    var compromiseConfidence: CompromiseConfidence
    var findings: [CompromiseFinding]

    // Detection results
    var rootkits: [RootkitFinding]
    var backdoors: [BackdoorFinding]
    var hiddenProcesses: [HiddenProcessFinding]
    var suspiciousUsers: [SuspiciousUserFinding]
    var persistenceMechanisms: [PersistenceFinding]
    var binaryIntegrityIssues: [BinaryIntegrityFinding]
    var kernelModuleIssues: [KernelModuleFinding]
    var logTamperingIssues: [LogTamperingFinding]
    var networkSniffers: [NetworkSnifferFinding]

    var summary: String
    var recommendations: [String]

    init(targetIP: String) {
        self.id = UUID()
        self.targetIP = targetIP
        self.scanDate = Date()
        self.isCompromised = false
        self.compromiseConfidence = .none
        self.findings = []
        self.rootkits = []
        self.backdoors = []
        self.hiddenProcesses = []
        self.suspiciousUsers = []
        self.persistenceMechanisms = []
        self.binaryIntegrityIssues = []
        self.kernelModuleIssues = []
        self.logTamperingIssues = []
        self.networkSniffers = []
        self.summary = ""
        self.recommendations = []
    }

    var totalFindings: Int {
        return rootkits.count + backdoors.count + hiddenProcesses.count +
               suspiciousUsers.count + persistenceMechanisms.count +
               binaryIntegrityIssues.count + kernelModuleIssues.count +
               logTamperingIssues.count + networkSniffers.count
    }

    var criticalFindings: Int {
        return findings.filter { $0.severity == VulnerabilitySeverity.critical }.count
    }

    mutating func assessCompromise() {
        let critical = findings.filter { $0.severity == VulnerabilitySeverity.critical }.count
        let high = findings.filter { $0.severity == VulnerabilitySeverity.high }.count

        if critical >= 3 || rootkits.count > 0 {
            compromiseConfidence = .definite
            isCompromised = true
        } else if critical >= 1 || high >= 3 {
            compromiseConfidence = .likely
            isCompromised = true
        } else if high >= 1 {
            compromiseConfidence = .possible
            isCompromised = true
        } else {
            compromiseConfidence = .none
            isCompromised = false
        }
    }
}

enum CompromiseConfidence: String, Codable {
    case none = "No signs of compromise"
    case possible = "Possible compromise"
    case likely = "Likely compromised"
    case definite = "Definitely compromised"

    var color: String {
        switch self {
        case .none: return "#00FF00"
        case .possible: return "#FFFF00"
        case .likely: return "#FF9500"
        case .definite: return "#FF0000"
        }
    }
}

/// Generic compromise finding
struct CompromiseFinding: Identifiable, Codable {
    let id: UUID
    let category: CompromiseCategory
    let severity: VulnerabilitySeverity
    let title: String
    let description: String
    var evidence: [String]
    var remediation: String?

    init(category: CompromiseCategory, severity: VulnerabilitySeverity, title: String, description: String) {
        self.id = UUID()
        self.category = category
        self.severity = severity
        self.title = title
        self.description = description
        self.evidence = []
        self.remediation = nil
    }
}

enum CompromiseCategory: String, Codable {
    case rootkit = "Rootkit"
    case backdoor = "Backdoor"
    case hiddenProcess = "Hidden Process"
    case suspiciousUser = "Suspicious User"
    case persistence = "Persistence Mechanism"
    case binaryIntegrity = "Binary Integrity"
    case kernelModule = "Kernel Module"
    case logTampering = "Log Tampering"
    case networkSniffer = "Network Sniffer"
}

// MARK: - Specific Finding Types

struct RootkitFinding: Identifiable, Codable {
    let id: UUID
    let name: String
    let type: RootkitType
    let detectionMethod: String
    var files: [String]
    var processes: [String]

    init(name: String, type: RootkitType, detectionMethod: String) {
        self.id = UUID()
        self.name = name
        self.type = type
        self.detectionMethod = detectionMethod
        self.files = []
        self.processes = []
    }
}

enum RootkitType: String, Codable {
    case userland = "Userland Rootkit"
    case kernel = "Kernel Rootkit (LKM)"
    case bootkit = "Bootkit"
    case firmware = "Firmware Rootkit"
}

struct BackdoorFinding: Identifiable, Codable {
    let id: UUID
    let port: Int
    let service: String
    let description: String
    var suspicionReason: String

    init(port: Int, service: String, description: String, suspicionReason: String) {
        self.id = UUID()
        self.port = port
        self.service = service
        self.description = description
        self.suspicionReason = suspicionReason
    }
}

struct HiddenProcessFinding: Identifiable, Codable {
    let id: UUID
    let pid: Int
    let command: String
    let hideMethod: String

    init(pid: Int, command: String, hideMethod: String) {
        self.id = UUID()
        self.pid = pid
        self.command = command
        self.hideMethod = hideMethod
    }
}

struct SuspiciousUserFinding: Identifiable, Codable {
    let id: UUID
    let username: String
    let uid: Int
    let gid: Int
    let suspicionReasons: [String]
    var homeDirectory: String?
    var shell: String?

    init(username: String, uid: Int, gid: Int, suspicionReasons: [String]) {
        self.id = UUID()
        self.username = username
        self.uid = uid
        self.gid = gid
        self.suspicionReasons = suspicionReasons
        self.homeDirectory = nil
        self.shell = nil
    }
}

struct PersistenceFinding: Identifiable, Codable {
    let id: UUID
    let mechanism: PersistenceMechanism
    let location: String
    let description: String
    var content: String?

    init(mechanism: PersistenceMechanism, location: String, description: String) {
        self.id = UUID()
        self.mechanism = mechanism
        self.location = location
        self.description = description
        self.content = nil
    }
}

enum PersistenceMechanism: String, Codable {
    case cron = "Cron Job"
    case systemd = "Systemd Service/Timer"
    case initScript = "Init Script"
    case rcScript = "RC Script"
    case bashProfile = "Bash Profile"
    case sshKey = "SSH Authorized Key"
    case kernelModule = "Kernel Module"
}

struct BinaryIntegrityFinding: Identifiable, Codable {
    let id: UUID
    let binaryPath: String
    let issue: IntegrityIssue
    var expectedHash: String?
    var actualHash: String?

    init(binaryPath: String, issue: IntegrityIssue) {
        self.id = UUID()
        self.binaryPath = binaryPath
        self.issue = issue
        self.expectedHash = nil
        self.actualHash = nil
    }
}

enum IntegrityIssue: String, Codable {
    case hashMismatch = "Hash Mismatch"
    case trojanized = "Trojanized Binary"
    case modifiedTimestamp = "Modified Timestamp"
    case suspiciousPermissions = "Suspicious Permissions"
}

struct KernelModuleFinding: Identifiable, Codable {
    let id: UUID
    let moduleName: String
    let suspicionReasons: [String]
    var isLoaded: Bool
    var modulePath: String?

    init(moduleName: String, suspicionReasons: [String], isLoaded: Bool = true) {
        self.id = UUID()
        self.moduleName = moduleName
        self.suspicionReasons = suspicionReasons
        self.isLoaded = isLoaded
        self.modulePath = nil
    }
}

struct LogTamperingFinding: Identifiable, Codable {
    let id: UUID
    let logFile: String
    let tamperingType: TamperingType
    let description: String

    init(logFile: String, tamperingType: TamperingType, description: String) {
        self.id = UUID()
        self.logFile = logFile
        self.tamperingType = tamperingType
        self.description = description
    }
}

enum TamperingType: String, Codable {
    case cleared = "Log Cleared"
    case missing = "Log Missing"
    case gapDetected = "Gaps Detected"
    case suspiciousPermissions = "Suspicious Permissions"
}

struct NetworkSnifferFinding: Identifiable, Codable {
    let id: UUID
    let interface: String
    let isPromiscuous: Bool
    let snifferProcess: String?

    init(interface: String, isPromiscuous: Bool, snifferProcess: String? = nil) {
        self.id = UUID()
        self.interface = interface
        self.isPromiscuous = isPromiscuous
        self.snifferProcess = snifferProcess
    }
}
