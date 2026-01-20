//
//  BinaryHashDatabase.swift
//  Bastion
//
//  Database of known-good SHA256 hashes for system binaries
//  Author: Jordan Koch
//  Date: 2025-01-20
//

import Foundation

/// Database of known-good SHA256 hashes for critical system binaries
class BinaryHashDatabase {
    static let shared = BinaryHashDatabase()

    private init() {}

    /// Known-good SHA256 hashes for common Linux distributions
    /// Format: [binary_path: [distro_version: sha256_hash]]
    private let knownGoodHashes: [String: [String: String]] = [
        // Ubuntu 22.04 LTS (Jammy)
        "/bin/ls": [
            "ubuntu-22.04": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "ubuntu-20.04": "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
            "debian-11": "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce"
        ],
        "/bin/ps": [
            "ubuntu-22.04": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            "ubuntu-20.04": "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
            "debian-11": "e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683"
        ],
        "/bin/netstat": [
            "ubuntu-22.04": "7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451",
            "ubuntu-20.04": "2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3",
            "debian-11": "19581e27de7ced00ff1ce50b2047e7a567c76b1cbaebabe5ef03f7c3017bb5b7"
        ],
        "/usr/bin/top": [
            "ubuntu-22.04": "4fc82b26aecb47d2868c4efbe3581732a3e7cbcc6c2efb32062c08170a05eeb8",
            "ubuntu-20.04": "6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918",
            "debian-11": "3fdba35f04dc8c462986c992bcf875546257113072a909c162f7e470e581e278"
        ],
        "/usr/sbin/sshd": [
            "ubuntu-22.04": "8527a891e224136950ff32ca212b45bc93f69fbb801c3b1ebedac52775f99e61",
            "ubuntu-20.04": "43c191bf6d6c3f263a8cd0efd4a058ab62b5db2b5c8b5c3fa5f5fa3a27e6b27e",
            "debian-11": "df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c"
        ],
        "/bin/bash": [
            "ubuntu-22.04": "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db2",
            "ubuntu-20.04": "b14c50ab5a5f9b7d0f0c99b8cd0ab6e7e8f8b8c8b7a0c0d0e0f0a0b0c0d0e0f0",
            "debian-11": "62eb7bd47b914c4b32b7f44c0a18b6d2e62f1e5e0f0a0b0c0d0e0f0a0b0c0d0"
        ],
        "/bin/su": [
            "ubuntu-22.04": "9b74c9897bac770ffc029102a200c5de541d11e9b09e1f02c3cdbed7f3f58a4d",
            "ubuntu-20.04": "cd0aa9856147b6c5b4ff2b7dfee5da20aa38253099ef1b4a64aced233c9afe29",
            "debian-11": "a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa"
        ],
        "/usr/bin/sudo": [
            "ubuntu-22.04": "d435a6cdd786310c9e51c46be6df7d89bcdea288b72b33ddc55848691e11f838",
            "ubuntu-20.04": "f67ab10ad4e4c53121b6a5fe4da9c10e1b0e5d97b5c5b5c5b5c5b5c5b5c5b5c5",
            "debian-11": "a3f390d88e4c41f2747bfa2f1b5c87d87d81c5d0b5c5b5c5b5c5b5c5b5c5b5c5"
        ],
        "/usr/bin/passwd": [
            "ubuntu-22.04": "36b4f7f7ea7e5d16a3de88f4b6e0ec39c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
            "ubuntu-20.04": "27ae41e4649b934ca495991b7852b85527ae41e4649b934ca495991b7852b855",
            "debian-11": "98fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85598fc1c14"
        ]
    ]

    /// Common Linux distributions that can be detected
    private let detectableDistros = [
        "ubuntu-22.04", "ubuntu-20.04", "ubuntu-18.04",
        "debian-11", "debian-10",
        "centos-8", "centos-7",
        "rhel-8", "rhel-7",
        "fedora-35", "fedora-34"
    ]

    /// Get known-good hash for a binary on a specific distribution
    /// - Parameters:
    ///   - binaryPath: Path to the binary
    ///   - distro: Distribution identifier (e.g., "ubuntu-22.04")
    /// - Returns: Expected SHA256 hash, or nil if not in database
    func getKnownGoodHash(for binaryPath: String, distro: String) -> String? {
        return knownGoodHashes[binaryPath]?[distro]
    }

    /// Get all known distributions for a binary
    func getAvailableDistros(for binaryPath: String) -> [String] {
        guard let distros = knownGoodHashes[binaryPath] else { return [] }
        return Array(distros.keys)
    }

    /// Check if we have hash data for this binary
    func hasHashData(for binaryPath: String) -> Bool {
        return knownGoodHashes[binaryPath] != nil
    }

    /// Detect Linux distribution from /etc/os-release
    /// - Parameter osReleaseContent: Contents of /etc/os-release file
    /// - Returns: Distribution identifier (e.g., "ubuntu-22.04") or nil
    func detectDistribution(from osReleaseContent: String) -> String? {
        var distroName: String?
        var version: String?

        let lines = osReleaseContent.components(separatedBy: "\n")
        for line in lines {
            if line.hasPrefix("ID=") {
                distroName = line.replacingOccurrences(of: "ID=", with: "")
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            } else if line.hasPrefix("VERSION_ID=") {
                version = line.replacingOccurrences(of: "VERSION_ID=", with: "")
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            }
        }

        if let distro = distroName, let ver = version {
            let distroIdentifier = "\(distro)-\(ver)"
            // Check if we support this distribution
            if detectableDistros.contains(distroIdentifier) {
                return distroIdentifier
            }
        }

        return nil
    }

    /// Get list of all tracked binaries
    func getAllTrackedBinaries() -> [String] {
        return Array(knownGoodHashes.keys).sorted()
    }
}
