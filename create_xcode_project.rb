#!/usr/bin/env ruby
require 'securerandom'
require 'fileutils'

# Generate Xcode-style UUIDs
def generate_uuid
  SecureRandom.uuid.delete('-').upcase[0..23]
end

project_name = "Bastion"
project_dir = File.expand_path(".")
pbxproj_path = "#{project_dir}/#{project_name}.xcodeproj/project.pbxproj"

# Create xcodeproj directory
FileUtils.mkdir_p("#{project_name}.xcodeproj")

# Find all Swift files
swift_files = Dir.glob("#{project_dir}/Bastion/**/*.swift")
puts "Found #{swift_files.length} Swift files"

# Generate UUIDs for all files
file_refs = {}
build_files = {}

swift_files.each do |file|
  relative_path = file.sub("#{project_dir}/", "")
  file_refs[file] = generate_uuid
  build_files[file] = generate_uuid
end

# Additional UUIDs for project structure
main_group = generate_uuid
bastion_group = generate_uuid
products_group = generate_uuid
frameworks_group = generate_uuid
target_uuid = generate_uuid
sources_phase = generate_uuid
frameworks_phase = generate_uuid
resources_phase = generate_uuid
app_product = generate_uuid
project_uuid = generate_uuid
config_list = generate_uuid
debug_config = generate_uuid
release_config = generate_uuid

puts "Generating project.pbxproj..."

# Create project.pbxproj content
pbxproj_content = <<PBXPROJ
// !$*UTF8*$!
{
	archiveVersion = 1;
	classes = {
	};
	objectVersion = 56;
	objects = {

/* Begin PBXBuildFile section */
PBXPROJ

# Add build file references
swift_files.each do |file|
  filename = File.basename(file)
  pbxproj_content += "\t\t#{build_files[file]} /* #{filename} in Sources */ = {isa = PBXBuildFile; fileRef = #{file_refs[file]} /* #{filename} */; };\n"
end

pbxproj_content += <<PBXPROJ
/* End PBXBuildFile section */

/* Begin PBXFileReference section */
PBXPROJ

# Add file references
swift_files.each do |file|
  filename = File.basename(file)
  relative_path = file.sub("#{project_dir}/", "")
  pbxproj_content += "\t\t#{file_refs[file]} /* #{filename} */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = #{relative_path}; sourceTree = \"<group>\"; };\n"
end

pbxproj_content += "\t\t#{app_product} /* #{project_name}.app */ = {isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = #{project_name}.app; sourceTree = BUILT_PRODUCTS_DIR; };\n"

pbxproj_content += <<PBXPROJ
/* End PBXFileReference section */

/* Begin PBXFrameworksBuildPhase section */
		#{frameworks_phase} /* Frameworks */ = {
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
/* End PBXFrameworksBuildPhase section */

/* Begin PBXGroup section */
		#{main_group} = {
			isa = PBXGroup;
			children = (
				#{bastion_group} /* Bastion */,
				#{products_group} /* Products */,
			);
			sourceTree = "<group>";
		};
		#{bastion_group} /* Bastion */ = {
			isa = PBXGroup;
			children = (
PBXPROJ

# Add all file references to group
swift_files.each do |file|
  filename = File.basename(file)
  pbxproj_content += "\t\t\t\t#{file_refs[file]} /* #{filename} */,\n"
end

pbxproj_content += <<PBXPROJ
			);
			path = Bastion;
			sourceTree = "<group>";
		};
		#{products_group} /* Products */ = {
			isa = PBXGroup;
			children = (
				#{app_product} /* #{project_name}.app */,
			);
			name = Products;
			sourceTree = "<group>";
		};
/* End PBXGroup section */

/* Begin PBXNativeTarget section */
		#{target_uuid} /* #{project_name} */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = #{config_list} /* Build configuration list for PBXNativeTarget "#{project_name}" */;
			buildPhases = (
				#{sources_phase} /* Sources */,
				#{frameworks_phase} /* Frameworks */,
				#{resources_phase} /* Resources */,
			);
			buildRules = (
			);
			dependencies = (
			);
			name = #{project_name};
			productName = #{project_name};
			productReference = #{app_product} /* #{project_name}.app */;
			productType = "com.apple.product-type.application";
		};
/* End PBXNativeTarget section */

/* Begin PBXProject section */
		#{project_uuid} /* Project object */ = {
			isa = PBXProject;
			attributes = {
				BuildIndependentTargetsInParallel = 1;
				LastSwiftUpdateCheck = 1500;
				LastUpgradeCheck = 1500;
			};
			buildConfigurationList = #{config_list} /* Build configuration list for PBXProject "#{project_name}" */;
			compatibilityVersion = "Xcode 14.0";
			developmentRegion = en;
			hasScannedForEncodings = 0;
			knownRegions = (
				en,
			);
			mainGroup = #{main_group};
			productRefGroup = #{products_group} /* Products */;
			projectDirPath = "";
			projectRoot = "";
			targets = (
				#{target_uuid} /* #{project_name} */,
			);
		};
/* End PBXProject section */

/* Begin PBXResourcesBuildPhase section */
		#{resources_phase} /* Resources */ = {
			isa = PBXResourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
/* End PBXResourcesBuildPhase section */

/* Begin PBXSourcesBuildPhase section */
		#{sources_phase} /* Sources */ = {
			isa = PBXSourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
PBXPROJ

# Add all build file references
swift_files.each do |file|
  filename = File.basename(file)
  pbxproj_content += "\t\t\t\t#{build_files[file]} /* #{filename} in Sources */,\n"
end

pbxproj_content += <<PBXPROJ
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
/* End PBXSourcesBuildPhase section */

/* Begin XCBuildConfiguration section */
		#{debug_config} /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;
				CODE_SIGN_STYLE = Automatic;
				COMBINE_HIDPI_IMAGES = YES;
				CURRENT_PROJECT_VERSION = 1;
				DEVELOPMENT_TEAM = "";
				ENABLE_HARDENED_RUNTIME = YES;
				GENERATE_INFOPLIST_FILE = YES;
				INFOPLIST_KEY_NSHumanReadableCopyright = "Copyright © 2025 Jordan Koch";
				INFOPLIST_KEY_NSMainStoryboardFile = Main;
				INFOPLIST_KEY_NSPrincipalClass = NSApplication;
				LD_RUNPATH_SEARCH_PATHS = (
					"$(inherited)",
					"@executable_path/../Frameworks",
				);
				MACOSX_DEPLOYMENT_TARGET = 13.0;
				MARKETING_VERSION = 1.0;
				PRODUCT_BUNDLE_IDENTIFIER = com.kochj.bastion;
				PRODUCT_NAME = "$(TARGET_NAME)";
				SWIFT_EMIT_LOC_STRINGS = YES;
				SWIFT_VERSION = 5.0;
			};
			name = Debug;
		};
		#{release_config} /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;
				CODE_SIGN_STYLE = Automatic;
				COMBINE_HIDPI_IMAGES = YES;
				CURRENT_PROJECT_VERSION = 1;
				DEVELOPMENT_TEAM = "";
				ENABLE_HARDENED_RUNTIME = YES;
				GENERATE_INFOPLIST_FILE = YES;
				INFOPLIST_KEY_NSHumanReadableCopyright = "Copyright © 2025 Jordan Koch";
				INFOPLIST_KEY_NSMainStoryboardFile = Main;
				INFOPLIST_KEY_NSPrincipalClass = NSApplication;
				LD_RUNPATH_SEARCH_PATHS = (
					"$(inherited)",
					"@executable_path/../Frameworks",
				);
				MACOSX_DEPLOYMENT_TARGET = 13.0;
				MARKETING_VERSION = 1.0;
				PRODUCT_BUNDLE_IDENTIFIER = com.kochj.bastion;
				PRODUCT_NAME = "$(TARGET_NAME)";
				SWIFT_EMIT_LOC_STRINGS = YES;
				SWIFT_VERSION = 5.0;
			};
			name = Release;
		};
/* End XCBuildConfiguration section */

/* Begin XCConfigurationList section */
		#{config_list} /* Build configuration list */ = {
			isa = XCConfigurationList;
			buildConfigurations = (
				#{debug_config} /* Debug */,
				#{release_config} /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		};
/* End XCConfigurationList section */
	};
	rootObject = #{project_uuid} /* Project object */;
}
PBXPROJ

File.write(pbxproj_path, pbxproj_content)
puts "✓ Created #{pbxproj_path}"
puts "✓ Xcode project ready to open!"
