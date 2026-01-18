//
//  ServiceFingerprinter.swift
//  Bastion
//
//  Service version detection and banner grabbing
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import Foundation
import Network

@MainActor
class ServiceFingerprinter: ObservableObject {
    @Published var fingerprintLog: [String] = []

    // Fingerprint service on specific port
    func fingerprint(ip: String, port: Int) async -> ServiceInfo? {
        var service = ServiceInfo(name: "Unknown", port: port)

        // Try banner grabbing
        if let banner = await grabBanner(ip: ip, port: port) {
            service.banner = banner
            service = parseServiceFromBanner(banner: banner, port: port)
        } else {
            // If no banner, guess by port
            service.name = guessServiceByPort(port)
        }

        addLog("Fingerprinted \(ip):\(port) -> \(service.displayVersion)")
        return service
    }

    // Grab banner from service
    private func grabBanner(ip: String, port: Int) async -> String? {
        return await withCheckedContinuation { continuation in
            let host = NWEndpoint.Host(ip)
            let portEndpoint = NWEndpoint.Port(integerLiteral: UInt16(port))
            let connection = NWConnection(host: host, port: portEndpoint, using: .tcp)

            var completed = false

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    // Send probe and wait for response
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, error in
                        guard !completed else { return }
                        completed = true
                        connection.cancel()

                        if let data = data, let banner = String(data: data, encoding: .utf8) {
                            continuation.resume(returning: banner)
                        } else {
                            continuation.resume(returning: nil)
                        }
                    }

                    // Send probe for HTTP
                    if port == 80 || port == 8080 || port == 443 || port == 8443 {
                        let httpProbe = "GET / HTTP/1.0\r\n\r\n"
                        connection.send(content: httpProbe.data(using: .utf8), completion: .idempotent)
                    }

                case .failed, .cancelled:
                    if !completed {
                        completed = true
                        continuation.resume(returning: nil)
                    }
                default:
                    break
                }
            }

            connection.start(queue: .global())

            // Timeout after 3 seconds
            Task {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                if !completed {
                    completed = true
                    connection.cancel()
                    continuation.resume(returning: nil)
                }
            }
        }
    }

    // Parse service information from banner
    private func parseServiceFromBanner(banner: String, port: Int) -> ServiceInfo {
        var service = ServiceInfo(name: "Unknown", port: port)

        let lowercaseBanner = banner.lowercased()

        // SSH detection
        if lowercaseBanner.contains("ssh") {
            service.name = "SSH"
            if let versionRange = banner.range(of: "SSH-[0-9.]+-OpenSSH_[0-9.]+p[0-9]+", options: .regularExpression) {
                let version = String(banner[versionRange])
                service.version = version.replacingOccurrences(of: "SSH-2.0-OpenSSH_", with: "")
            }
        }

        // HTTP/Apache detection
        else if lowercaseBanner.contains("apache") {
            service.name = "Apache"
            if let versionRange = banner.range(of: "Apache/[0-9.]+", options: .regularExpression) {
                service.version = String(banner[versionRange]).replacingOccurrences(of: "Apache/", with: "")
            }
        }

        // Nginx detection
        else if lowercaseBanner.contains("nginx") {
            service.name = "nginx"
            if let versionRange = banner.range(of: "nginx/[0-9.]+", options: .regularExpression) {
                service.version = String(banner[versionRange]).replacingOccurrences(of: "nginx/", with: "")
            }
        }

        // FTP detection
        else if lowercaseBanner.contains("ftp") {
            service.name = "FTP"
            if lowercaseBanner.contains("vsftpd") {
                service.name = "vsftpd"
            } else if lowercaseBanner.contains("proftpd") {
                service.name = "ProFTPD"
            }
        }

        // MySQL detection
        else if lowercaseBanner.contains("mysql") {
            service.name = "MySQL"
        }

        // PostgreSQL detection
        else if lowercaseBanner.contains("postgresql") || lowercaseBanner.contains("postgres") {
            service.name = "PostgreSQL"
        }

        // SMB/Samba detection
        else if lowercaseBanner.contains("smb") || lowercaseBanner.contains("samba") {
            service.name = "Samba"
        }

        return service
    }

    // Guess service by port number
    private func guessServiceByPort(_ port: Int) -> String {
        let services: [Int: String] = [
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP",
            8443: "HTTPS",
            27017: "MongoDB"
        ]
        return services[port] ?? "Unknown"
    }

    // Detect OS fingerprint (simplified)
    func detectOS(device: Device) async -> String? {
        // Check SSH banner for OS hints
        if let sshPort = device.openPorts.first(where: { $0.port == 22 }),
           let banner = sshPort.service {
            if banner.contains("Ubuntu") {
                return "Ubuntu Linux"
            } else if banner.contains("Debian") {
                return "Debian Linux"
            } else if banner.contains("raspbian") || banner.contains("raspberry") {
                return "Raspberry Pi OS"
            }
        }

        // Check HTTP headers for OS hints
        if device.openPorts.contains(where: { $0.port == 80 || $0.port == 443 }) {
            // Would check Server headers here
        }

        return nil
    }

    private func addLog(_ message: String) {
        let timestamp = Date().formatted(date: .omitted, time: .standard)
        fingerprintLog.append("[\(timestamp)] \(message)")
    }
}
