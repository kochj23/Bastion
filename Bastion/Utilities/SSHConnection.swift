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
            // Use expect to handle SSH password authentication
            let expectScript = self.generateExpectScript(command: command)

            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/usr/bin/expect")
            task.arguments = ["-c", expectScript]

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

    /// Generate expect script for SSH with password authentication
    private func generateExpectScript(command: String) -> String {
        // Escape special characters in password and command
        let escapedPassword = password.replacingOccurrences(of: "\"", with: "\\\"")
        let escapedCommand = command.replacingOccurrences(of: "\"", with: "\\\"")

        return """
        set timeout 30
        spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p \(port) \(username)@\(host) "\(escapedCommand)"
        expect {
            "password:" {
                send "\(escapedPassword)\\r"
                expect {
                    eof
                }
            }
            "Password:" {
                send "\(escapedPassword)\\r"
                expect {
                    eof
                }
            }
            "(yes/no" {
                send "yes\\r"
                expect "password:" { send "\(escapedPassword)\\r" }
                expect eof
            }
            eof
        }
        catch wait result
        exit [lindex $result 3]
        """
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
            let escapedPassword = password.replacingOccurrences(of: "\"", with: "\\\"")
            let escapedCommand = command.replacingOccurrences(of: "\"", with: "\\\"")

            let expectScript = """
            set timeout 30
            spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p \(port) \(username)@\(host) "sudo -S \(escapedCommand)"
            expect {
                "password:" {
                    send "\(escapedPassword)\\r"
                    expect {
                        "password for" {
                            send "\(escapedPassword)\\r"
                            expect eof
                        }
                        eof
                    }
                }
                "Password:" {
                    send "\(escapedPassword)\\r"
                    expect {
                        "password for" {
                            send "\(escapedPassword)\\r"
                            expect eof
                        }
                        eof
                    }
                }
                "(yes/no" {
                    send "yes\\r"
                    expect "password:" { send "\(escapedPassword)\\r" }
                    expect "password for" { send "\(escapedPassword)\\r" }
                    expect eof
                }
                eof
            }
            """

            let task = Process()
            task.executableURL = URL(fileURLWithPath: "/usr/bin/expect")
            task.arguments = ["-c", expectScript]

            let outputPipe = Pipe()
            task.standardOutput = outputPipe
            task.standardError = outputPipe

            do {
                try task.run()

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
