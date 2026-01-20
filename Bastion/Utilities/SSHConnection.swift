//
//  SSHConnection.swift
//  Bastion
//
//  SSH connection helper for executing remote commands
//  Author: Jordan Koch
//  Date: 2025-01-20
//

import Foundation

/// Represents an authenticated SSH connection to a remote host
class SSHConnection {
    let host: String
    let port: Int
    let username: String
    let password: String

    private var isConnected = false

    init(host: String, port: Int = 22, username: String, password: String) {
        self.host = host
        self.port = port
        self.username = username
        self.password = password
    }

    /// Execute a command on the remote host via SSH
    /// - Parameter command: The shell command to execute
    /// - Returns: Command output as string, or nil if execution failed
    func execute(_ command: String) async -> String? {
        return await withCheckedContinuation { continuation in
            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
            task.arguments = [
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=10",
                "-o", "PasswordAuthentication=yes",
                "-o", "PreferredAuthentications=password",
                "-p", "\(port)",
                "\(username)@\(host)",
                command
            ]

            let outputPipe = Pipe()
            let errorPipe = Pipe()
            task.standardOutput = outputPipe
            task.standardError = errorPipe
            task.standardInput = Pipe()

            do {
                try task.run()

                // Timeout after 30 seconds
                DispatchQueue.global().asyncAfter(deadline: .now() + 30) {
                    if task.isRunning {
                        task.terminate()
                    }
                }

                task.waitUntilExit()

                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

                if task.terminationStatus == 0 {
                    let output = String(data: outputData, encoding: .utf8) ?? ""
                    continuation.resume(returning: output)
                } else {
                    let error = String(data: errorData, encoding: .utf8) ?? ""
                    print("[SSHConnection] Command failed: \(error)")
                    continuation.resume(returning: nil)
                }
            } catch {
                print("[SSHConnection] Execution error: \(error)")
                continuation.resume(returning: nil)
            }
        }
    }

    /// Check if a file exists on the remote system
    func fileExists(_ path: String) async -> Bool {
        if let output = await execute("test -e \(path) && echo 'EXISTS' || echo 'NOTFOUND'") {
            return output.trimmingCharacters(in: .whitespacesAndNewlines).contains("EXISTS")
        }
        return false
    }

    /// Read a file from the remote system
    func readFile(_ path: String) async -> String? {
        return await execute("cat \(path) 2>/dev/null")
    }

    /// Check if we have root/sudo access
    func hasRootAccess() async -> Bool {
        if let output = await execute("id -u") {
            return output.trimmingCharacters(in: .whitespacesAndNewlines) == "0"
        }
        return false
    }

    /// Try to execute command with sudo
    func executeSudo(_ command: String) async -> String? {
        // Try with sudo -n (no password prompt)
        return await execute("sudo -n \(command)")
    }
}
