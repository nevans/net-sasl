# frozen_string_literal: true

require_relative "lib/net/sasl/version"

Gem::Specification.new do |spec|
  spec.name          = "net-sasl"
  spec.version       = Net::SASL::VERSION
  spec.authors       = ["nicholas a. evans", "Shugo Maeda"]
  spec.email         = ["nicholas.evans@gmail.com", "shugo@ruby-lang.org"]

  spec.summary       = "Pluggable SASL mechanisms"
  spec.description   = "Pluggable mechanisms to support protocols which use SASL"
  spec.homepage      = "https://github.com/nevans/net-sasl"
  spec.license       = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.5.0")

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) {
    `git ls-files -z`.split("\x0").reject {|f| f.match(%r{\A(?:test|spec|features)/}) }
  }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{\Aexe/}) {|f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "digest"
  spec.add_dependency "strscan"
end
