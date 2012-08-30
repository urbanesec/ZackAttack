#!/usr/bin/env ruby
#encoding: ASCII-8BIT
=begin
exchange web services client
=end
require 'ews'
require 'smb'
require 'ldap'
require 'staticchal'
require 'zfdb'
require 'apireq'


module ZFClient
  class Router
    def initialize (uid,timeout)
      #puts "uid"
      #puts uid.inspect
      
      @db = ZFdb::DB.new
      begin
        item = nil
        Timeout.timeout(timeout) { 
          while item == nil do
            item = @db.GetApiReq(uid)
            if item == nil then item = @db.GetTodoItem(uid)[0] end
            if item == nil then sleep 0.2 end
          end
        @details = {"uid" => uid, "aid" => item["aid"],"tid" => item["tid"] }
        @arid = @db.ActionPerformed(item["aid"],item["tid"],uid)
        @tip = item["tipaddr"]
        
        # Look for stuff from db a loop minding timeout
        # try to connect minding timeout
        # if can't connect, break it and repeat trying to find stuff
        mtype = item["moduleid"]
        if mtype == 1 then
          puts "EWS Action " + @tip
          if !(@client = ZFClient::EWS.new(@tip,443)) then
            #todo CONNECTION REFUSED ERRORS!
            puts "FAIL!"
          end
        elsif mtype == 2 then
          puts "SMB Action " + @tip
          if !(@client = ZFClient::Smb.new(@tip,445)) then
            puts "FAIL!"
          end
        elsif mtype == 3 then
          puts "LDAP Action " + @tip
          if !(@client = ZFClient::Ldap.new(@tip,389)) then
            puts "FAIL!"
          end
        elsif mtype == 0 then
          puts "API Action " + @tip
          @client = ZFClient::Apireq.new(@tip,uid)
        end
        
        }
      rescue Timeout::Error
        puts "No Instructions for " + uid.to_s
      end
      if @client == nil
        @client = ZFClient::StaticType2.new("0.0.0.0",0)
      end
    end

    def sendtype1(ntlmdata)
       return @client.sendtype1(ntlmdata)
    end
    def sendtype3(ntlmdata,rawpkt=nil)
      # this should be a send it and forget it kind of thing. should be already threaded by httpd and smbd
      #puts "Type3Data sending to client"
      @client.sendtype3(ntlmdata,rawpkt,@details)
    end
  end
end
