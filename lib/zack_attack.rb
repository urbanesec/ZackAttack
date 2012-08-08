require "erb"
require "socket"
require "base64"
require 'webrick'

require "zack_attack/cli"
require "zack_attack/clients"
require "zack_attack/payloads"
require "zack_attack/version"
require "zack_attack/zfdb"
require "zack_attack/zfadmingui"
require "zack_attack/zfhttpd"
require "zack_attack/zfsmbd"
require "zack_attack/zfsocks"


# ZackAttack Module
module ZackAttack

  def self.run(args)
    cli = ZackAttack::CLI.new(args)
    self.options = cli.options 
    cli.run
  end

  def self.options=(options={})
    @options = options
  end

  def self.options
    @options
  end

end

