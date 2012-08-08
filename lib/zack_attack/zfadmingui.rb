
module ZFadmingui
  attr_accessor :server

  def self.path(path=false, read_file=true)
    base_path = File.expand_path(File.join(File.dirname(__FILE__), 
          "../../data/", "bootstrap")) 

    if path
      file = File.join(base_path, path)
      return File.read(file) if file && read_file
      file
    else
      base_path
    end
  end

  def self.Header
    return ERB.new(ZFadmingui.path('header.erb')).result(binding)
  end
  def self.Leftbar
    return ERB.new(ZFadmingui.path('leftbar.erb')).result(binding)
  end
  def self.Footer
    return ERB.new(ZFadmingui.path('footer.erb')).result(binding)
  end
  class Http
    class ZFweb3 < WEBrick::HTTPServlet::ERBHandler
      def do_GET(req, resp)
        do_POST(req,resp)
      end
      def do_POST(req, resp)
        WEBrick::HTTPAuth.basic_auth(req, resp, "ZackATTACK") {|user, pass|
          user == ZackAttack.options[:mgmt_user] && pass == ZackAttack.options[:mgmt_password]
        }
        
        if req.path == "/" then
          resp.status = 302
          resp['Location'] = "http://" + req.host + ":" + "4531" +"/index" 
        elsif File.exists?(ZFadmingui.path(req.path + '.erb', false)) then
          @script_filename = ZFadmingui.path(req.path, false) + ".erb"
        else 
          @script_filename = ZFadmingui.path('404.erb', false) + ".erb"
        end
        super
        if req.query["dl"] == "1" then
            resp['Content-Type'] = "application/force-download"
            if (req.query["dlname"] != nil) then
              resp['Content-Disposition'] = "attachment; filename=\"" + req.query["dlname"] + "\""
            end
        else
          resp['Content-Type'] = "text/html"
        end
      end
    end
    class ZFwebapi < WEBrick::HTTPServlet::AbstractServlet
      def do_GET(req, resp)
        WEBrick::HTTPAuth.basic_auth(req, resp, "ZackATTACK") {|user, pass|
          user == ZackAttack.options[:api_user] && pass == ZackAttack.options[:api_password]
        }
        resp['Content-Type'] = "text/html"
        
        if req.query["a"] == "type2" then
          require 'zfdb'
          zfdb = ZFdb::DB.new()
          domain = req.query["d"]
          username = req.query["u"]
          type2 = req.query["msg"]
          reqid = zfdb.AddApiReq(username,domain,type2)
          type3msg = zfdb.WaitForApiResp(reqid,15)[0]
          resp.body = type3msg
        end
      end
      def do_POST(req,resp)
        self.do_GET(req,resp)
      end
    end
    def initialize (ip, port)
      @s = WEBrick::HTTPServer.new(:BindAddress => ip, 
                                   :Port => port, 
                                   :AccessLog => [], 
                                   :Logger => WEBrick::Log::new("/dev/null", 7))
    end
    def start()
      puts "Starting Admin GUI"
      static_path = ZFadmingui.path
      index_path = ZFadmingui.path('index.erb', false)

      @s.mount("/static", WEBrick::HTTPServlet::FileHandler, static_path)
      @s.mount("/api", ZFwebapi)
      @s.mount("/", ZFweb3, index_path)

      trap("INT"){
        @s.shutdown
      }
      puts "\n==========================================================="
      puts " WELCOME TO ZackAttack! - Version: #{ZackAttack::VERSION}"
      puts " Now with even more win!"
      puts " No CLI Gui for Now. Connect to http://" + ZackAttack.options[:mgmt_user] + ":" + 
        ZackAttack.options[:mgmt_password] + "@" + ZackAttack.options[:mgmt_ip] + 
        ":" + ZackAttack.options[:mgmt_port].to_s
      puts "==========================================================="
      @s.start
    end
  end
end
