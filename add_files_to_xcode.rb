#!/usr/bin/env ruby
require 'securerandom'
require 'fileutils'

project_path = 'Bastion.xcodeproj/project.pbxproj'
backup_path = 'Bastion.xcodeproj/project.pbxproj.backup'

# Backup original
FileUtils.cp(project_path, backup_path)

# Read project file
content = File.read(project_path)

# New files to add
new_files = [
  'Bastion/Security/ExploitModules/SMBModule.swift',
  'Bastion/Security/ExploitModules/DNSModule.swift',
  'Bastion/Security/ExploitModules/LDAPModule.swift',
  'Bastion/Security/LateralMovementMapper.swift',
  'Bastion/Security/VulnerabilityChainer.swift',
  'Bastion/Security/MITREATTACKMapper.swift',
  'Bastion/Security/RemediationScriptGenerator.swift',
  'Bastion/Security/ContinuousMonitor.swift',
  'Bastion/Security/AnomalyDetector.swift',
  'Bastion/Security/TimelineReconstructor.swift'
]

file_refs = []
build_files = []

# Generate UUIDs and file references
new_files.each do |file_path|
  file_ref_uuid = SecureRandom.uuid.gsub('-', '')[0..23].upcase
  build_file_uuid = SecureRandom.uuid.gsub('-', '')[0..23].upcase
  file_name = File.basename(file_path)
  
  file_refs << file_ref_uuid
  build_files << [build_file_uuid, file_ref_uuid]
  
  # Add to PBXFileReference section
  file_ref_entry = "\t\t#{file_ref_uuid} /* #{file_name} */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = #{file_name}; sourceTree = \"<group>\"; };\n"
  
  # Find PBXFileReference section and add before the end
  content.gsub!(/\/\* End PBXFileReference section \*\//) do
    file_ref_entry + $&
  end
  
  # Add to PBXBuildFile section
  build_file_entry = "\t\t#{build_file_uuid} /* #{file_name} in Sources */ = {isa = PBXBuildFile; fileRef = #{file_ref_uuid} /* #{file_name} */; };\n"
  
  content.gsub!(/\/\* End PBXBuildFile section \*\//) do
    build_file_entry + $&
  end
  
  # Add to PBXSourcesBuildPhase
  build_phase_entry = "\t\t\t\t#{build_file_uuid} /* #{file_name} in Sources */,\n"
  
  content.gsub!(/(\/\* Sources \*\/ = \{[^}]+files = \([^)]+)(\);)/) do
    $1 + build_phase_entry + $2
  end
  
  puts "✓ Added: #{file_name}"
end

# Write modified project file
File.write(project_path, content)

puts ""
puts "✅ All files added to Xcode project!"
puts "Backup saved to: #{backup_path}"
