#!/usr/bin/env ruby
require 'rubygems'
require 'webrick'
require 'erb'
require 'config'

module ZFadmingui
  attr_accessor :server
  def self.Header
    ERB.new(File.read('./bootstrap/header.erb')).result(binding)
  end
  def self.Leftbar
    ERB.new(File.read('./bootstrap/leftbar.erb')).result(binding)
  end
  def self.Footer
    ERB.new(File.read('./bootstrap/footer.erb')).result(binding)
  end
  class Http
    class ZFweb3 < WEBrick::HTTPServlet::ERBHandler
      def do_GET(req, resp)
        do_POST(req, resp)
      end
      def do_POST(req, resp)
        WEBrick::HTTPAuth.basic_auth(req, resp, 'ZackATTACK') do |user, pass|
          user == MGMTUser && pass == MGMTPass
        end

        if req.path == '/'
          resp.status = 302
          resp['Location'] = 'http://' + req.host + ':' + '4531' + '/index'
        elsif File.exist?('bootstrap' + req.path + '.erb')
          @script_filename = './bootstrap' + req.path + '.erb'
        else
          @script_filename = './bootstrap' + '/404.erb'
        end
        super
        if req.query['dl'] == '1'
          resp['Content-Type'] = 'application/force-download'
          if (req.query['dlname'] != nil)
            resp['Content-Disposition'] = 'attachment; filename=\"' + req.query['dlname'] + "\""
          end
        else
          resp['Content-Type'] = 'text/html'
        end
      end
    end

    class ZFwebapi < WEBrick::HTTPServlet::AbstractServlet
      def do_GET(req, resp)
        WEBrick::HTTPAuth.basic_auth(req, resp, 'ZackATTACK') do |user, pass|
          user == APIUser && pass == APIPass
        end
        resp['Content-Type'] = 'text/html'

        if req.query['a'] == 'type2'
          require 'zfdb'
          zfdb = ZFdb::DB.new
          domain = req.query['d']
          username = req.query['u']
          type2 = req.query['msg']
          reqid = zfdb.AddApiReq(username, domain, type2)
          type3msg = zfdb.WaitForApiResp(reqid, 15)[0]
          resp.body = type3msg
        end
      end

      def do_POST(req, resp)
        self.do_GET(req, resp)
      end
    end
    def initialize(ip, port)
      @s = WEBrick::HTTPServer.new(BindAddress: ip,
                                   Port: port, AccessLog: [],
                                   Logger: WEBrick::Log.new('/dev/null', 7))
    rescue Errno::EADDRINUSE, Errno::EACCES
      puts 'ADMIN HTTP - PORT IN USE OR PERMS'
      return false
    end
    def start
      puts 'Starting Admin GUI'
      @s.mount('/static', WEBrick::HTTPServlet::FileHandler, './bootstrap')
      @s.mount('/api', ZFwebapi)
      @s.mount('/', ZFweb3, './bootstrap/index.erb')
      trap('INT') do
        @s.shutdown
      end
      puts "\n==========================================================="
      puts ' WELCOME TO ZackAttack! - Version 0.a.lessfail.'
      puts ' Less Bugs than..er...a version ago!'
      puts ' No CLI Gui for Now. Connect to http://' + MGMTUser + ':' + MGMTPass + '@' + MGMTIP + ':' + MGMTPort
      puts '==========================================================='
      @s.start
    end
  end
end
