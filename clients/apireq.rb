#!/usr/bin/env ruby
#encoding: ASCII-8BIT
=begin
api requests
=end
require 'zfdb'
require 'base64'

module ZFClient
  class Apireq
    def initialize (server,port)
      @db = ZFdb::DB.new
      @reqid = server
      @uid = port
    end

    def sendtype1(type1msg)
      res = @db.ProcessApiReq(@reqid) #type2msg
      return Base64.decode64(res[2])#.gsub("\n",'')
    end

    def sendtype3(type3msg, rawpkt,  details)
      begin
      
      @db.SetApiResp(@reqid,Base64.encode64(type3msg).gsub("\n",'').strip)
      rescue
        puts $! end
    end
    

  end
end