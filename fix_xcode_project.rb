#!/usr/bin/env ruby
require 'securerandom'
require 'fileutils'

project_path = 'Bastion.xcodeproj/project.pbxproj'

# Read project file
content = File.read(project_path)

# Files with correct relative paths from Bastion/ folder
files_info = [
  { name: 'SMBModule.swift', path: 'Security/ExploitModules/SMBModule.swift' },
  { name: 'DNSModule.swift', path: 'Security/ExploitModules/DNSModule.swift' },
  { name: 'LDAPModule.swift', path: 'Security/ExploitModules/LDAPModule.swift' },
  { name: 'LateralMovementMapper.swift', path: 'Security/LateralMovementMapper.swift' },
  { name: 'VulnerabilityChainer.swift', path: 'Security/VulnerabilityChainer.swift' },
  { name: 'MITREATTACKMapper.swift', path: 'Security/MITREATTACKMapper.swift' },
  { name: 'RemediationScriptGenerator.swift', path: 'Security/RemediationScriptGenerator.swift' },
  { name: 'ContinuousMonitor.swift', path: 'Security/ContinuousMonitor.swift' },
  { name: 'AnomalyDetector.swift', path: 'Security/AnomalyDetector.swift' },
  { name: 'TimelineReconstructor.swift', path: 'Security/TimelineReconstructor.swift' }
]

build_files = []

files_info.each do |info|
  file_ref_uuid = SecureRandom.uuid.gsub('-', '')[0..23].upcase
  build_file_uuid = SecureRandom.uuid.gsub('-', '')[0..23].upcase
  
  build_files << [build_file_uuid, file_ref_uuid]
  
  # Add PBXFileReference
  file_ref = "\t\t#{file_ref_uuid} /* #{info[:name]} */ = {isa = PBXFileReference; fileEncoding = 4; lastKnownFileType = sourcecode.swift; path = #{info[:name]}; sourceTree = \"<group>\"; };\n"
  content.sub!(/\/\* End PBXFileReference section \*\//, file_ref + "\t\t/* End PBXFileReference section */")
  
  # Add PBXBuildFile
  build_file = "\t\t#{build_file_uuid} /* #{info[:name]} in Sources */ = {isa = PBXBuildFile; fileRef = #{file_ref_uuid} /* #{info[:name]} */; };\n"
  content.sub!(/\/\* End PBXBuildFile section \*\//, build_file + "\t\t/* End PBXBuildFile section */")
  
  puts "✓ #{info[:name]}"
end

# Add to Sources build phase
build_files.each do |build_uuid, file_uuid|
  name = files_info.find { |f| build_files.any? { |b| b[1] == file_uuid } }
  file_name = name ? files_info.find { |f| build_files.find { |b| b[1] == file_uuid } }[:name] : "file"
  
  # Find Sources build phase and add
  content.sub!(/(\/\* Sources \*\/ = \{[^}]*isa = PBXSourcesBuildPhase;[^}]*files = \([^)]*)/m) do
    $1 + "\n\t\t\t\t#{build_uuid} /* #{file_name} in Sources */,"
  end
end

# Write back
File.write(project_path, content)

puts ""
puts "✅ All files added to Xcode project!"
