#!/usr/bin/env ruby
require 'securerandom'

project_path = 'Bastion.xcodeproj/project.pbxproj'
content = File.read(project_path)

# Add Assets.xcassets as folder reference
assets_ref_id = SecureRandom.uuid.gsub('-', '')[0..23].upcase
assets_build_id = SecureRandom.uuid.gsub('-', '')[0..23].upcase

# Add PBXFileReference for Assets.xcassets
assets_ref = "\t\t#{assets_ref_id} /* Assets.xcassets */ = {isa = PBXFileReference; lastKnownFileType = folder.assetcatalog; path = Assets.xcassets; sourceTree = \"<group>\"; };\n"
content.sub!(/\/\* End PBXFileReference section \*\//, assets_ref + "\t\t/* End PBXFileReference section */")

# Add PBXBuildFile for Assets.xcassets
build_file = "\t\t#{assets_build_id} /* Assets.xcassets in Resources */ = {isa = PBXBuildFile; fileRef = #{assets_ref_id} /* Assets.xcassets */; };\n"
content.sub!(/\/\* End PBXBuildFile section \*\//, build_file + "\t\t/* End PBXBuildFile section */")

# Add to Resources build phase
content.sub!(/(\/\* Resources \*\/ = \{[^}]*files = \([^)]*)/m) { $1 + "\n\t\t\t\t#{assets_build_id} /* Assets.xcassets in Resources */," }

File.write(project_path, content)
puts "✓ Added Assets.xcassets to Bastion project"
