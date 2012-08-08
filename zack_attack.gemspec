# -*- encoding: utf-8 -*-

require File.expand_path('../lib/zack_attack/version', __FILE__)

Gem::Specification.new do |gem|
  gem.name          = "ZackAttack"
  gem.version       = ZackAttack::VERSION
  gem.summary       = %q{Realying NTLM Like Nobody's Business}
  gem.description   = %q{ZackAttack! is a new Tool Set to do NTLM Authentication relaying unlike any other tool currently out there.}
  # gem.license       = "MIT"
  gem.authors       = ["Zack Fasel"]
  # gem.email         = ""
  gem.homepage      = "https://github.com/zfasel/ZackAttack#readme"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ['lib']

  gem.add_development_dependency 'bundler', '~> 1.0'
  gem.add_development_dependency 'rake', '~> 0.8'
  gem.add_development_dependency 'rspec', '~> 2.4'
  gem.add_development_dependency 'rubygems-tasks', '~> 0.2'
  gem.add_development_dependency 'yard', '~> 0.8'
end
