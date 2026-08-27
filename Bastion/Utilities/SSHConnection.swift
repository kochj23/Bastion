//
//  SSHConnection.swift
//  Bastion
//
//  SSH connection helper for executing remote commands with password authentication
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

    init(host: String, port: Int = 22, username: String, password: String) {
        self.host = host
        self.port = port
        self.username = username
        self.password = password
    }

    /// Execute a command on the remote host via SSH with password authentication
    /// - Parameter command: The shell command to execute
    /// - Returns: Command output as string, or nil if execution failed
    func execute(_ command: String) async -> String? {
        return await withCheckedContinuation { continuation in
            // Validate host/username against a strict allowlist so shell/argv
            // metacharacters cannot reach a command boundary. Port is an Int.
            guard self.isValidHostOrUser(self.host),
                  self.isValidHostOrUser(self.username) else {
                print("[SSHConnection] Invalid host or username")
                continuation.resume(returning: nil)
                return
            }

            guard let sshpass = self.sshpassPath() else {
                print("[SSHConnection] sshpass not found; cannot authenticate with password")
                continuation.resume(returning: nil)
                return
            }

            // Drive ssh via sshpass, passing every value as a literal argv element.
            // The password is delivered through the SSHPASS environment variable,
            // never concatenated into a shell/Tcl string.
            let task = Process()
            task.executableURL = URL(fileURLWithPath: sshpass)
            task.arguments = [
                "-e",
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=10",
                "-p", "\(self.port)",
                "\(self.username)@\(self.host)",
                command
            ]

            var environment = ProcessInfo.processInfo.environment
            environment["SSHPASS"] = self.password
            task.environment = environment

            let outputPipe = Pipe()
            let errorPipe = Pipe()
            task.standardOutput = outputPipe
            task.standardError = errorPipe

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
                    // Clean up expect output (remove expect prompts/debug info)
                    let cleanOutput = self.cleanExpectOutput(output)
                    continuation.resume(returning: cleanOutput)
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

    /// Strict allowlist for host / username so metacharacters cannot reach the
    /// argv or the remote shell boundary.
    private func isValidHostOrUser(_ value: String) -> Bool {
        return !value.isEmpty
            && value.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil
    }

    /// Locate an installed sshpass binary, if any.
    private func sshpassPath() -> String? {
        let candidates = ["/opt/homebrew/bin/sshpass", "/usr/local/bin/sshpass"]
        return candidates.first { FileManager.default.fileExists(atPath: $0) }
    }

    /// Clean expect output (remove expect control sequences and SSH warnings)
    private func cleanExpectOutput(_ output: String) -> String {
        var cleaned = output

        // Remove common SSH warnings
        let warningsToRemove = [
            "Warning: Permanently added",
            "Pseudo-terminal will not be allocated",
            "spawn ssh"
        ]

        for warning in warningsToRemove {
            if let range = cleaned.range(of: ".*\(warning).*\n", options: .regularExpression) {
                cleaned.removeSubrange(range)
            }
        }

        // Remove expect spawn line
        if let range = cleaned.range(of: "^spawn.*\n", options: .regularExpression) {
            cleaned.removeSubrange(range)
        }

        return cleaned.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Execute a command and return raw output (for testing)
    func executeRaw(_ command: String) async -> String? {
        return await execute(command)
    }

    /// Check if a file exists on the remote system
    func fileExists(_ path: String) async -> Bool {
        if let output = await execute("test -e '\(path)' && echo 'EXISTS' || echo 'NOTFOUND'") {
            return output.contains("EXISTS")
        }
        return false
    }

    /// Read a file from the remote system
    func readFile(_ path: String) async -> String? {
        return await execute("cat '\(path)' 2>/dev/null")
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
        if let output = await execute("sudo -n \(command) 2>/dev/null") {
            if !output.isEmpty {
                return output
            }
        }

        // If that failed, try with password
        return await executeSudoWithPassword(command)
    }

    /// Execute command with sudo using password
    private func executeSudoWithPassword(_ command: String) async -> String? {
        return await withCheckedContinuation { continuation in
            guard self.isValidHostOrUser(self.host),
                  self.isValidHostOrUser(self.username) else {
                print("[SSHConnection] Invalid host or username")
                continuation.resume(returning: nil)
                return
            }

            guard let sshpass = self.sshpassPath() else {
                print("[SSHConnection] sshpass not found; cannot authenticate with password")
                continuation.resume(returning: nil)
                return
            }

            // sshpass -e authenticates the ssh session via the SSHPASS environment
            // variable. The remote `sudo -S` reads its password from stdin, which we
            // feed below over ssh — never on argv and never in a Tcl/shell string.
            let task = Process()
            task.executableURL = URL(fileURLWithPath: sshpass)
            task.arguments = [
                "-e",
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=10",
                "-p", "\(self.port)",
                "\(self.username)@\(self.host)",
                "sudo -S -p '' \(command)"
            ]

            var environment = ProcessInfo.processInfo.environment
            environment["SSHPASS"] = self.password
            task.environment = environment

            let inputPipe = Pipe()
            let outputPipe = Pipe()
            task.standardInput = inputPipe
            task.standardOutput = outputPipe
            task.standardError = outputPipe

            do {
                try task.run()

                // Deliver the sudo password over ssh's stdin.
                if let data = (self.password + "\n").data(using: .utf8) {
                    inputPipe.fileHandleForWriting.write(data)
                }
                try? inputPipe.fileHandleForWriting.close()

                DispatchQueue.global().asyncAfter(deadline: .now() + 30) {
                    if task.isRunning {
                        task.terminate()
                    }
                }

                task.waitUntilExit()

                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                if task.terminationStatus == 0 {
                    let output = String(data: outputData, encoding: .utf8) ?? ""
                    let cleanOutput = self.cleanExpectOutput(output)
                    continuation.resume(returning: cleanOutput)
                } else {
                    continuation.resume(returning: nil)
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }

    /// Test the SSH connection
    func testConnection() async -> Bool {
        if let output = await execute("echo 'CONNECTION_OK'") {
            return output.contains("CONNECTION_OK")
        }
        return false
    }
}
