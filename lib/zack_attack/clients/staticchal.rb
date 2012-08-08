require 'zack_attack/zfntlm'

module ZFClient
  class StaticType2

    def initialize (server,port)
      @server = "woof"
      return true
    end

    def connect

    end

    def sendtype1(type1msg)
      a = ZFNtlm::Message.new()
      return a.buildtype2
    end

    def sendtype3(type3msg, rawpkt, details=nil)
      return 
    end

    def execute

    end
  end
end
