#!/usr/bin/env ruby
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
    def initialize(uid, timeout)
      # puts 'uid'
      # puts uid.inspect
      @db = ZFdb::DB.new
      begin
        item = nil
        Timeout.timeout(timeout) do
          while item.nil?
            item = @db.GetApiReq(uid)
            item = @db.GetTodoItem(uid)[0] if item.nil?
            sleep 0.2 if item.nil?
          end
          @details = { 'uid' => uid, 'aid' => item['aid'],
                       'tid' => item['tid'] }
          @arid = @db.ActionPerformed(item['aid'], item['tid'], uid)
          @tip = item['tipaddr']

          # Look for stuff from db a loop minding timeout
          # try to connect minding timeout
          # if can't connect, break it and repeat trying to find stuff
          mtype = item['moduleid']
          case mtype
          when 1
            puts 'EWS Action ' + @tip
            if !(@client = ZFClient::EWS.new(@tip, 443))
              # TODO: CONNECTION REFUSED ERRORS!
              puts 'FAIL!'
            end
          when 2
            puts 'SMB Action ' + @tip
            if !(@client = ZFClient::Smb.new(@tip, 445))
              puts 'FAIL!'
            end
          when 3
            puts 'LDAP Action ' + @tip
            if !(@client = ZFClient::Ldap.new(@tip, 389))
              puts 'FAIL!'
            end
          when 0
            puts 'API Action ' + @tip
            @client = ZFClient::Apireq.new(@tip, uid)
          end

        end
      rescue Timeout::Error
        puts 'No Instructions for ' + uid.to_s
      end
      @client = ZFClient::StaticType2.new('0.0.0.0', 0) if @client.nil?
    end

    def sendtype1(ntlmdata)
      @client.sendtype1(ntlmdata)
    end

    def sendtype3(ntlmdata, rawpkt = nil)
      # this should be a send it and forget it kind of thing.
      # should be already threaded by httpd and smbd
      # puts 'Type3Data sending to client'
      @client.sendtype3(ntlmdata, rawpkt, @details)
    end
  end
end
