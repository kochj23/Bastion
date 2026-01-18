//
//  NetworkScanner.swift
//  Bastion
//
//  Pure Swift network scanner using Darwin BSD APIs
//  Author: Jordan Koch
//  Date: 2025-01-17
//

import Foundation
import Network

@MainActor
class NetworkScanner: ObservableObject {
    @Published var discoveredDevices: [Device] = []
    @Published var isScanning = false
    @Published var scanProgress: Double = 0
    @Published var currentScanTarget: String = ""
    @Published var scanLog: [String] = []

    private let commonPorts = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
        995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888
    ]

    // Scan network for devices
    func scanNetwork(cidr: String) async throws {
        isScanning = true
        discoveredDevices = []
        scanProgress = 0
        addLog("Starting network scan: \(cidr)")

        let ipAddresses = try parseCIDR(cidr)
        let totalHosts = ipAddresses.count

        for (index, ip) in ipAddresses.enumerated() {
            currentScanTarget = ip
            scanProgress = Double(index) / Double(totalHosts)

            if await isHostAlive(ip) {
                addLog("Found device: \(ip)")
                var device = Device(ipAddress: ip)

                // Reverse DNS lookup
                device.hostname = await resolveHostname(ip)

                // Port scan
                let openPorts = await scanPorts(ip: ip, ports: commonPorts)
                device.openPorts = openPorts

                discoveredDevices.append(device)
            }
        }

        scanProgress = 1.0
        isScanning = false
        addLog("Scan complete. Found \(discoveredDevices.count) devices.")
    }

    // Quick network scan (top 100 most common ports)
    func quickScan(cidr: String) async throws {
        let quickPorts = Array(commonPorts.prefix(10))
        isScanning = true
        addLog("Quick scan started")

        let ipAddresses = try parseCIDR(cidr)
        for ip in ipAddresses {
            if await isHostAlive(ip) {
                var device = Device(ipAddress: ip)
                device.openPorts = await scanPorts(ip: ip, ports: quickPorts)
                discoveredDevices.append(device)
            }
        }

        isScanning = false
        addLog("Quick scan complete")
    }

    // Check if host is alive (ICMP-like via TCP connection attempt)
    private func isHostAlive(_ ip: String) async -> Bool {
        // Try connecting to common ports to detect if host is up
        let testPorts = [80, 443, 22, 445]

        return await withTaskGroup(of: Bool.self) { group in
            for port in testPorts {
                group.addTask {
                    await self.isPortOpen(ip: ip, port: port)
                }
            }

            for await result in group {
                if result {
                    return true
                }
            }
            return false
        }
    }

    // Scan specific ports on a host
    func scanPorts(ip: String, ports: [Int]) async -> [OpenPort] {
        var openPorts: [OpenPort] = []

        await withTaskGroup(of: OpenPort?.self) { group in
            for port in ports {
                group.addTask {
                    if await self.isPortOpen(ip: ip, port: port) {
                        var openPort = OpenPort(port: port)
                        openPort.service = self.serviceForPort(port)
                        return openPort
                    }
                    return nil
                }
            }

            for await result in group {
                if let openPort = result {
                    openPorts.append(openPort)
                }
            }
        }

        return openPorts.sorted { $0.port < $1.port }
    }

    // Check if specific port is open
    private func isPortOpen(ip: String, port: Int) async -> Bool {
        return await withCheckedContinuation { continuation in
            let host = NWEndpoint.Host(ip)
            let port = NWEndpoint.Port(integerLiteral: UInt16(port))
            let connection = NWConnection(host: host, port: port, using: .tcp)

            var completed = false

            connection.stateUpdateHandler = { state in
                guard !completed else { return }

                switch state {
                case .ready:
                    completed = true
                    connection.cancel()
                    continuation.resume(returning: true)
                case .failed, .cancelled:
                    completed = true
                    continuation.resume(returning: false)
                default:
                    break
                }
            }

            connection.start(queue: .global())

            // Timeout after 2 seconds
            Task {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                if !completed {
                    completed = true
                    connection.cancel()
                    continuation.resume(returning: false)
                }
            }
        }
    }

    // Resolve hostname from IP
    private func resolveHostname(_ ip: String) async -> String? {
        return await withCheckedContinuation { continuation in
            var hints = addrinfo()
            hints.ai_flags = AI_NUMERICHOST

            var result: UnsafeMutablePointer<addrinfo>?
            defer { if result != nil { freeaddrinfo(result) } }

            let status = getaddrinfo(ip, nil, &hints, &result)
            guard status == 0, let addr = result else {
                continuation.resume(returning: nil)
                return
            }

            var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let reverseStatus = getnameinfo(
                addr.pointee.ai_addr,
                addr.pointee.ai_addrlen,
                &hostname,
                socklen_t(hostname.count),
                nil, 0,
                NI_NAMEREQD
            )

            if reverseStatus == 0 {
                continuation.resume(returning: String(cString: hostname))
            } else {
                continuation.resume(returning: nil)
            }
        }
    }

    // Parse CIDR notation to IP addresses
    private func parseCIDR(_ cidr: String) throws -> [String] {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2,
              let baseIP = parts.first,
              let mask = Int(parts.last!) else {
            throw NetworkError.invalidCIDR
        }

        let octets = baseIP.split(separator: ".").compactMap { Int($0) }
        guard octets.count == 4 else {
            throw NetworkError.invalidCIDR
        }

        // For /24 networks (most common)
        if mask == 24 {
            var ips: [String] = []
            for i in 1..<255 {
                ips.append("\(octets[0]).\(octets[1]).\(octets[2]).\(i)")
            }
            return ips
        }

        // For /16 networks
        if mask == 16 {
            var ips: [String] = []
            for i in 0..<255 {
                for j in 1..<255 {
                    ips.append("\(octets[0]).\(octets[1]).\(i).\(j)")
                }
            }
            return ips
        }

        // Default to /24
        return try parseCIDR("\(baseIP)/24")
    }

    // Get service name for common ports
    private func serviceForPort(_ port: Int) -> String? {
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
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt"
        ]
        return services[port]
    }

    private func addLog(_ message: String) {
        let timestamp = Date().formatted(date: .omitted, time: .standard)
        scanLog.append("[\(timestamp)] \(message)")
    }

    // Get current local network
    func detectLocalNetwork() -> String? {
        // Try to detect local network automatically
        // This is a simplified implementation
        return "192.168.1.0/24"
    }
}

enum NetworkError: LocalizedError {
    case invalidCIDR
    case scanFailed
    case timeoutError

    var errorDescription: String? {
        switch self {
        case .invalidCIDR:
            return "Invalid CIDR notation. Use format: 192.168.1.0/24"
        case .scanFailed:
            return "Network scan failed"
        case .timeoutError:
            return "Connection timeout"
        }
    }
}
