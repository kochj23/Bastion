#!/usr/bin/env ruby
require 'securerandom'

project_path = 'Bastion.xcodeproj/project.pbxproj'
content = File.read(project_path)

# Files with CORRECT paths (relative to project root with "Bastion/" prefix)
files = [
  { name: 'SMBModule.swift', path: 'Bastion/Security/ExploitModules/SMBModule.swift' },
  { name: 'DNSModule.swift', path: 'Bastion/Security/ExploitModules/DNSModule.swift' },
  { name: 'LDAPModule.swift', path: 'Bastion/Security/ExploitModules/LDAPModule.swift' },
  { name: 'LateralMovementMapper.swift', path: 'Bastion/Security/LateralMovementMapper.swift' },
  { name: 'VulnerabilityChainer.swift', path: 'Bastion/Security/VulnerabilityChainer.swift' },
  { name: 'MITREATTACKMapper.swift', path: 'Bastion/Security/MITREATTACKMapper.swift' },
  { name: 'RemediationScriptGenerator.swift', path: 'Bastion/Security/RemediationScriptGenerator.swift' },
  { name: 'ContinuousMonitor.swift', path: 'Bastion/Security/ContinuousMonitor.swift' },
  { name: 'AnomalyDetector.swift', path: 'Bastion/Security/AnomalyDetector.swift' },
  { name: 'TimelineReconstructor.swift', path: 'Bastion/Security/TimelineReconstructor.swift' }
]

files.each do |file|
  file_ref_id = SecureRandom.uuid.gsub('-', '')[0..23].upcase
  build_file_id = SecureRandom.uuid.gsub('-', '')[0..23].upcase
  
  # Add PBXFileReference (look at existing format)
  file_ref = "\t\t#{file_ref_id} /* #{file[:name]} */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = #{file[:path]}; sourceTree = \"<group>\"; };\n"
  content.sub!(/\/\* End PBXFileReference section \*\//, file_ref + "\t\t/* End PBXFileReference section */")
  
  # Add PBXBuildFile
  build_file = "\t\t#{build_file_id} /* #{file[:name]} in Sources */ = {isa = PBXBuildFile; fileRef = #{file_ref_id} /* #{file[:name]} */; };\n"
  content.sub!(/\/\* End PBXBuildFile section \*\//, build_file + "\t\t/* End PBXBuildFile section */")
  
  # Add to Sources phase
  content.sub!(/(\/\* Sources \*\/ = \{[^}]*files = \([^)]*)/m) { $1 + "\n\t\t\t\t#{build_file_id} /* #{file[:name]} in Sources */," }
  
  puts "✓ #{file[:name]} - #{file_ref_id}"
end

File.write(project_path, content)
puts "\n✅ All files added with correct paths!"
