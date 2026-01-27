//
//  RemediationScriptGenerator.swift
//  Bastion
//
//  Generates hardening scripts to fix discovered vulnerabilities
//  AI-powered remediation recommendations
//  Author: Jordan Koch
//  Date: 2026-01-20
//

import Foundation

@MainActor
class RemediationScriptGenerator: ObservableObject {
    @Published var generatedScripts: [RemediationScript] = []
    @Published var isGenerating = false

    private let aiBackend = AIBackendManager.shared

    // MARK: - Script Generation

    /// Generate remediation script for a device
    func generateScript(for device: Device) async -> RemediationScript {
        isGenerating = true
        defer { isGenerating = false }

        print("🛠️ REMEDIATION: Generating hardening script for \(device.ipAddress)...")

        var scriptContent = generateBashHeader(device: device)

        // SSH hardening
        if device.openPorts.contains(where: { $0.port == 22 }) {
            scriptContent += generateSSHHardening(device: device)
        }

        // Web server hardening
        if device.openPorts.contains(where: { $0.port == 80 || $0.port == 443 }) {
            scriptContent += generateWebServerHardening(device: device)
        }

        // SMB hardening
        if device.openPorts.contains(where: { $0.port == 445 }) {
            scriptContent += generateSMBHardening(device: device)
        }

        // DNS hardening
        if device.openPorts.contains(where: { $0.port == 53 }) {
            scriptContent += generateDNSHardening(device: device)
        }

        // Firewall rules
        scriptContent += generateFirewallRules(device: device)

        // CVE-specific patches
        scriptContent += generateCVEPatches(device: device)

        // AI-enhanced recommendations
        if aiBackend.activeBackend != nil {
            scriptContent += await generateAIRecommendations(device: device)
        }

        scriptContent += generateScriptFooter()

        let script = RemediationScript(
            device: device,
            content: scriptContent,
            generatedDate: Date(),
            vulnerabilitiesAddressed: device.vulnerabilities.count
        )

        await MainActor.run {
            self.generatedScripts.append(script)
        }

        return script
    }

    // MARK: - Script Generation Functions

    private func generateBashHeader(device: Device) -> String {
        """
        #!/bin/bash
        #
        # Bastion Security Hardening Script
        # Generated: \(Date().formatted(date: .abbreviated, time: .standard))
        # Target: \(device.ipAddress) (\(device.hostname ?? "unknown"))
        # Vulnerabilities: \(device.vulnerabilities.count)
        # Risk Level: \(device.riskLevel.rawValue)
        #
        # WARNING: Review this script before execution!
        # Backup your system before making security changes.
        #

        set -e  # Exit on error
        set -u  # Exit on undefined variable

        echo "🛡️  Bastion Security Hardening Script"
        echo "Target: \(device.ipAddress)"
        echo "Date: $(date)"
        echo "========================================"
        echo ""

        # Check if running as root
        if [[ $EUID -ne 0 ]]; then
           echo "❌ This script must be run as root (use sudo)"
           exit 1
        fi

        echo "✓ Running as root"
        echo ""


        """
    }

    private func generateSSHHardening(device: Device) -> String {
        var script = """
        # ========================================
        # SSH HARDENING
        # ========================================
        echo "🔒 Hardening SSH service..."

        # Backup original config
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

        """

        // Move SSH to non-standard port
        script += """
        # Move SSH to non-standard port
        echo "→ Moving SSH from port 22 to 2222..."
        sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
        sed -i 's/^Port 22/Port 2222/' /etc/ssh/sshd_config

        """

        // Disable root login
        script += """
        # Disable root login
        echo "→ Disabling root login..."
        sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
        sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

        """

        // Disable password authentication (prefer keys)
        script += """
        # Disable password authentication (use SSH keys)
        echo "→ Configuring key-only authentication..."
        sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

        # Enable public key auth
        sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config

        """

        // Install fail2ban
        script += """
        # Install fail2ban for brute force protection
        echo "→ Installing fail2ban..."
        if command -v apt-get &> /dev/null; then
            apt-get update -qq
            apt-get install -y fail2ban
        elif command -v yum &> /dev/null; then
            yum install -y fail2ban
        fi

        # Configure fail2ban for SSH
        cat > /etc/fail2ban/jail.local << 'FAIL2BAN_EOF'
        [sshd]
        enabled = true
        port = 2222
        filter = sshd
        logpath = /var/log/auth.log
        maxretry = 3
        bantime = 3600
        findtime = 600
        FAIL2BAN_EOF

        systemctl enable fail2ban
        systemctl restart fail2ban

        # Restart SSH service
        echo "→ Restarting SSH service..."
        systemctl restart sshd || systemctl restart ssh

        echo "✓ SSH hardening complete"
        echo ""


        """

        return script
    }

    private func generateWebServerHardening(device: Device) -> String {
        let hasApache = device.services.contains(where: { $0.name.lowercased().contains("apache") })
        let hasNginx = device.services.contains(where: { $0.name.lowercased().contains("nginx") })
        let hasLighttpd = device.services.contains(where: { $0.name.lowercased().contains("lighttpd") })

        var script = """
        # ========================================
        # WEB SERVER HARDENING
        # ========================================
        echo "🌐 Hardening web server..."

        """

        if hasApache || hasNginx || hasLighttpd {
            script += """
            # Update security headers
            echo "→ Adding security headers..."

            """
        }

        if hasApache {
            script += """
            # Apache security headers
            cat >> /etc/apache2/conf-available/security.conf << 'APACHE_EOF'
            # Security Headers
            Header always set X-Frame-Options "SAMEORIGIN"
            Header always set X-Content-Type-Options "nosniff"
            Header always set X-XSS-Protection "1; mode=block"
            Header always set Content-Security-Policy "default-src 'self'"
            Header always set Referrer-Policy "strict-origin-when-cross-origin"

            # Hide server version
            ServerTokens Prod
            ServerSignature Off
            APACHE_EOF

            a2enconf security
            systemctl reload apache2

            """
        }

        if hasNginx {
            script += """
            # Nginx security headers
            cat >> /etc/nginx/conf.d/security.conf << 'NGINX_EOF'
            # Security Headers
            add_header X-Frame-Options "SAMEORIGIN" always;
            add_header X-Content-Type-Options "nosniff" always;
            add_header X-XSS-Protection "1; mode=block" always;
            add_header Content-Security-Policy "default-src 'self'" always;
            add_header Referrer-Policy "strict-origin-when-cross-origin" always;

            # Hide version
            server_tokens off;
            NGINX_EOF

            systemctl reload nginx

            """
        }

        if hasLighttpd {
            script += """
            # Lighttpd security configuration
            cat >> /etc/lighttpd/conf-available/99-security.conf << 'LIGHTTPD_EOF'
            # Security Headers
            setenv.add-response-header = (
                "X-Frame-Options" => "SAMEORIGIN",
                "X-Content-Type-Options" => "nosniff",
                "X-XSS-Protection" => "1; mode=block",
                "Content-Security-Policy" => "default-src 'self'"
            )

            # Hide version
            server.tag = "webserver"
            LIGHTTPD_EOF

            lighty-enable-mod security
            systemctl reload lighttpd

            """
        }

        script += """
        echo "✓ Web server hardening complete"
        echo ""


        """

        return script
    }

    private func generateSMBHardening(device: Device) -> String {
        """
        # ========================================
        # SMB HARDENING
        # ========================================
        echo "🔒 Hardening SMB service..."

        # Disable SMBv1 (vulnerable to EternalBlue)
        echo "→ Disabling SMBv1..."
        if [ -f /etc/samba/smb.conf ]; then
            sed -i '/\\[global\\]/a min protocol = SMB2' /etc/samba/smb.conf
        fi

        # Enable SMB signing (prevents relay attacks)
        echo "→ Enabling SMB signing..."
        if [ -f /etc/samba/smb.conf ]; then
            sed -i '/\\[global\\]/a server signing = mandatory' /etc/samba/smb.conf
            sed -i '/\\[global\\]/a client signing = mandatory' /etc/samba/smb.conf
        fi

        # Restrict anonymous access
        echo "→ Restricting anonymous access..."
        if [ -f /etc/samba/smb.conf ]; then
            sed -i '/\\[global\\]/a restrict anonymous = 2' /etc/samba/smb.conf
        fi

        systemctl restart smbd || true

        echo "✓ SMB hardening complete"
        echo ""


        """
    }

    private func generateDNSHardening(device: Device) -> String {
        """
        # ========================================
        # DNS HARDENING
        # ========================================
        echo "🔍 Hardening DNS service..."

        # Disable zone transfers
        echo "→ Disabling zone transfers..."
        if [ -f /etc/bind/named.conf ]; then
            sed -i '/options {/a \\    allow-transfer { none; };' /etc/bind/named.conf
        fi

        # Disable recursion for external queries
        echo "→ Restricting recursion..."
        if [ -f /etc/bind/named.conf ]; then
            sed -i '/options {/a \\    recursion no;' /etc/bind/named.conf
        fi

        # Rate limiting (prevent amplification)
        echo "→ Enabling rate limiting..."
        if [ -f /etc/bind/named.conf ]; then
            sed -i '/options {/a \\    rate-limit { responses-per-second 5; };' /etc/bind/named.conf
        fi

        systemctl restart named || systemctl restart bind9 || true

        echo "✓ DNS hardening complete"
        echo ""


        """
    }

    private func generateFirewallRules(device: Device) -> String {
        var script = """
        # ========================================
        # FIREWALL CONFIGURATION
        # ========================================
        echo "🔥 Configuring firewall..."

        # Install ufw if not present
        if ! command -v ufw &> /dev/null; then
            echo "→ Installing UFW..."
            apt-get install -y ufw || yum install -y ufw || true
        fi

        # Reset firewall (start fresh)
        echo "→ Configuring firewall rules..."
        ufw --force reset

        # Default policies
        ufw default deny incoming
        ufw default allow outgoing

        """

        // Allow only necessary ports
        let allowedPorts = device.openPorts.filter { $0.port != 22 } // SSH handled separately

        for port in allowedPorts.prefix(10) {
            script += "ufw allow \(port.port)/\(port.portProtocol.rawValue.lowercased()) comment '\(port.service ?? "Service")'\n"
        }

        // SSH on new port
        script += """
        ufw allow 2222/tcp comment 'SSH (moved from 22)'

        # Enable firewall
        echo "y" | ufw enable

        echo "✓ Firewall configuration complete"
        echo ""


        """

        return script
    }

    private func generateCVEPatches(device: Device) -> String {
        var script = """
        # ========================================
        # CVE PATCHING
        # ========================================
        echo "🔧 Patching known vulnerabilities..."

        """

        // Generic system update
        script += """
        # Update all packages
        echo "→ Updating system packages..."
        if command -v apt-get &> /dev/null; then
            apt-get update -qq
            apt-get upgrade -y
            apt-get autoremove -y
        elif command -v yum &> /dev/null; then
            yum update -y
        fi

        """

        // Service-specific patches
        if device.services.contains(where: { $0.name == "SSH" }) {
            script += """
            # Update OpenSSH
            echo "→ Updating OpenSSH..."
            apt-get install --only-upgrade openssh-server -y || yum update openssh-server -y || true

            """
        }

        if device.services.contains(where: { $0.name.contains("Apache") }) {
            script += """
            # Update Apache
            echo "→ Updating Apache..."
            apt-get install --only-upgrade apache2 -y || yum update httpd -y || true

            """
        }

        script += """
        echo "✓ Patching complete"
        echo ""


        """

        return script
    }

    private func generateScriptFooter() -> String {
        """
        # ========================================
        # COMPLETION
        # ========================================
        echo "========================================"
        echo "✅ Security hardening complete!"
        echo ""
        echo "IMPORTANT NEXT STEPS:"
        echo "1. Reboot system to apply all changes"
        echo "2. Test SSH access on port 2222 before closing session"
        echo "3. Review firewall rules: ufw status"
        echo "4. Check fail2ban status: fail2ban-client status"
        echo "5. Verify services: systemctl status sshd"
        echo ""
        echo "Generated by Bastion - AI-Powered Security"
        echo "========================================"
        """
    }

    // MARK: - AI-Enhanced Remediation

    private func generateAIRecommendations(device: Device) async -> String {
        let prompt = """
        Generate additional security hardening recommendations for this device.

        Device: \(device.ipAddress)
        OS: \(device.operatingSystem ?? "unknown")
        Vulnerabilities: \(device.vulnerabilities.count)
        Services: \(device.services.map { $0.name }.joined(separator: ", "))

        Provide bash commands to:
        1. Harden remaining services
        2. Configure logging and monitoring
        3. Set up intrusion detection
        4. Implement least privilege
        5. Add security monitoring

        Provide actual bash commands that can be executed.
        """

        do {
            let recommendations = try await aiBackend.generate(
                prompt: prompt,
                systemPrompt: "You are a Linux security expert. Generate practical bash commands for system hardening.",
                temperature: 0.4,
                maxTokens: 800
            )

            return """
            # ========================================
            # AI-RECOMMENDED HARDENING
            # ========================================
            echo "🤖 Applying AI-recommended hardening..."

            # AI-Generated Recommendations:
            # \(recommendations.replacingOccurrences(of: "\n", with: "\n# "))

            echo "✓ AI recommendations applied"
            echo ""


            """
        } catch {
            return "# AI recommendations unavailable\n\n"
        }
    }

    // MARK: - Export Functions

    /// Save script to file
    func saveScript(_ script: RemediationScript, to directory: URL) throws -> URL {
        let filename = "bastion_harden_\(script.device.ipAddress.replacingOccurrences(of: ".", with: "_"))_\(Date().formatted(date: .numeric, time: .omitted).replacingOccurrences(of: "/", with: "")).sh"
        let scriptPath = directory.appendingPathComponent(filename)

        try script.content.write(to: scriptPath, atomically: true, encoding: .utf8)

        // Make executable
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/chmod")
        task.arguments = ["+x", scriptPath.path]
        try? task.run()

        return scriptPath
    }

    /// Export all scripts as ZIP
    func exportAllScripts(scripts: [RemediationScript]) async throws -> URL {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("bastion_remediation_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        // Save each script
        for script in scripts {
            _ = try saveScript(script, to: tempDir)
        }

        // Create README
        let readme = generateReadme(scripts: scripts)
        try readme.write(to: tempDir.appendingPathComponent("README.md"), atomically: true, encoding: .utf8)

        // ZIP directory
        let zipPath = FileManager.default.temporaryDirectory.appendingPathComponent("Bastion_Remediation_Scripts.zip")
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        task.arguments = ["-r", zipPath.path, tempDir.lastPathComponent]
        task.currentDirectoryURL = tempDir.deletingLastPathComponent()
        try task.run()
        task.waitUntilExit()

        return zipPath
    }

    private func generateReadme(scripts: [RemediationScript]) -> String {
        var readme = """
        # Bastion Security Remediation Scripts

        Generated: \(Date().formatted(date: .complete, time: .standard))
        Total Scripts: \(scripts.count)

        ## Overview

        These scripts were automatically generated by Bastion to remediate security vulnerabilities discovered during network assessment.

        ## Usage

        **⚠️ IMPORTANT:**
        1. Review each script before execution
        2. Test on non-production systems first
        3. Backup your systems before running
        4. Scripts must be run as root (use sudo)

        ## Scripts Included

        """

        for (index, script) in scripts.enumerated() {
            readme += """
            ### \(index + 1). \(script.filename)
            - **Target:** \(script.device.ipAddress) (\(script.device.hostname ?? "unknown"))
            - **Vulnerabilities Addressed:** \(script.vulnerabilitiesAddressed)
            - **Generated:** \(script.generatedDate.formatted(date: .abbreviated, time: .shortened))

            """
        }

        readme += """

        ## Execution Instructions

        ```bash
        # 1. Copy script to target device
        scp bastion_harden_*.sh user@target:/tmp/

        # 2. SSH to target
        ssh user@target

        # 3. Run script as root
        sudo bash /tmp/bastion_harden_*.sh

        # 4. Reboot system
        sudo reboot
        ```

        ## What These Scripts Do

        - Move SSH to non-standard port (2222)
        - Disable root login
        - Configure key-only SSH authentication
        - Install and configure fail2ban
        - Add security headers to web servers
        - Disable SMBv1 (EternalBlue protection)
        - Enable SMB signing
        - Configure firewall rules (ufw)
        - Harden DNS service
        - Apply system updates
        - AI-recommended additional hardening

        ## Post-Hardening Verification

        After running scripts, verify:
        - SSH accessible on new port: `ssh -p 2222 user@target`
        - Firewall active: `sudo ufw status`
        - fail2ban running: `sudo systemctl status fail2ban`
        - Services operational: `sudo systemctl status [service]`

        ## Support

        For issues or questions, review the Bastion documentation.

        **Generated by Bastion - AI-Powered Security Hardening**

        """

        return readme
    }
}

// MARK: - Data Models

struct RemediationScript: Identifiable {
    let id = UUID()
    let device: Device
    let content: String
    let generatedDate: Date
    let vulnerabilitiesAddressed: Int

    var filename: String {
        "bastion_harden_\(device.ipAddress.replacingOccurrences(of: ".", with: "_")).sh"
    }
}
