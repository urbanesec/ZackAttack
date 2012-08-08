require 'optparse'
require 'pathname'

require "zack_attack/zfsmbd"

# ZackAttack Module
module ZackAttack


  # CLI Class
  class CLI

    attr_accessor :options

    #
    # Initialize CLI Options
    #
    # @param [Array] args CLI arguments
    #
    def initialize(args)
      @args = args

      # Option Defaults
      @options = {
        :smbd_ip => "0.0.0.0",
        :http_ip => "0.0.0.0",
        :http_port => 80,
        :mgmt_ip => "0.0.0.0",
        :mgmt_port => 4531,
        :socks_ip => "127.0.0.1",
        :socks_port => 4532,
        :mgmt_user => "zf",
        :mgmt_password => "zf",
        :api_user => "api",
        :api_password => "api",
        :db_file => File.expand_path(File.join(File.dirname(__FILE__), 
                    "../../results/", "zack_attack.db")),
        :GUID => "\x6e\x09\x9f\x3f\x4a\xf0\x64\x4f\xa2\x9f\xd8\xb2\xd6\x5f\x4f\x7d",
        :native_os => "Unix",
        :native_lm => "Samba"
      }

      @opts = parse_options
      self
    end

    def options
      @options
    end

    #
    # Run
    #
    def run
      unless @options[:run]
        puts "#{@opts}\n" 
        exit
      end

      puts "=================================================="
      puts "Here Goes ZackAttack! Booting Up!....."
      puts "=================================================="
      
      # clear out old sessions / stuf TODO: consolidate into an init sequence / db cleanup
      
      db = ZFdb::DB.new(@options[:db_file])
      db.ClearActiveSessions
      db.db.execute("DELETE FROM aresults")

      smb = ZFsmb::Server.new(@options[:smbd_ip]) #only works on 445
      http = ZFhttpd::Server.new(@options[:http_ip], @options[:http_port])
      gui = ZFadmingui::Http.new(@options[:mgmt_ip], @options[:mgmt_port])
      socks = ZFsocks::Server.new(@options[:socks_ip], @options[:socks_port])
      #add CLI

      c = Thread.new{ gui.start() } 
      d = Thread.new{ socks.start() }
      b = Thread.new{ smb.start() }
      a = Thread.new{ http.start() }
      c.join

      puts "exiting"
    end

  private

    def parse_options
      opts = OptionParser.new

      opts.banner = "zackattack - Version: #{ZackAttack::VERSION}\n\n" + 
      "Usage: \n\tzackatack --run --http-ip 127.0.0.1 --http-port 8000\n\n"

      opts.on('-r', '--run', "Start the ZackAttack.") do |option|
        @options[:run] = option
      end

      opts.on('--smbd-ip ', "SMBD IP Address. Default: #{@options[:http_ip]}") do |option|
        @options[:smbd_ip] = option
      end

      opts.on('--http-port ', "HTTP server port. Default: #{@options[:http_port]}") do |option|
        @options[:http_port] = option
      end

      opts.on('--mgmt-ip ', "Management IP Address. Default: #{@options[:mgmt_ip]}") do |option|
        @options[:http_ip] = option
      end

      opts.on('--mgmt-port ', "Management Port. Default: #{@options[:mgmt_port]}") do |option|
        @options[:mgmt_port] = option
      end

      opts.on('--mgmt-user ', "Management user. Default: #{@options[:mgmt_user]}") do |option|
        @options[:mgmt_user] = option
      end

      opts.on('--mgmt-password ', "Management password. Default: #{@options[:mgmt_password]}") do |option|
        @options[:mgmt_password] = option
      end

      opts.on('--socks-ip ', "SOCKS IP Address. Default: #{@options[:socks_ip]}") do |option|
        @options[:socks_ip] = option
      end

      opts.on('--socks-port ', "SOCKS Port. Default: #{@options[:socks_port]}") do |option|
        @options[:socks_port] = option
      end

      opts.on('--api-user ', "API Username. Default: #{@options[:api_user]}") do |option|
        @options[:api_user] = option
      end

      opts.on('--api-password ', "API Password. Default: #{@options[:api_password]}") do |option|
        @options[:api_password] = option
      end

      opts.on('--database ', "Database File Path. Default: #{@options[:db_file]}") do |option|
        @options[:db_file] = option
      end

      opts.on('--guid ', "GUID. Default: #{@options[:guid]}") do |option|
        @options[:guid] = option
      end

      opts.on('--native-os ', "Native OS. Default: #{@options[:native_os]}") do |option|
        @options[:native_os] = option
      end

      opts.on('--native-lm ', "Native LM. Default: #{@options[:native_lm]}") do |option|
        @options[:native_lm] = option
      end

      opts.on('-h', '--help', 'Print application usage.') do |help|
        STDOUT.puts "#{opts}\n"
        exit
      end

      opts.on('-v', '--verbose', 'Turn on verbose logging.') do |verbose|
        @options[:verbose] = verbose
      end

      opts.on('--version', 'Print version information.') do |version|
        puts "Zack Attack Version: " + ZackAttack::VERSION
        exit
      end

      opts.parse!(@args)
      opts
    end

  end # Class CLI End
end # Module ZackAttack End


