#!/usr/bin/env ruby
#encoding: ASCII-8BIT
require 'zfmoduletest'
require 'zfdb'

module ZFClient
  class Smb
    def initialize (server,port)
      @db = ZFdb::DB.new
      @server = server
      @s = TCPSocket.open(server,port)
      ZFsmb::Smbclientnego(@s)
      @q, x = @s.recvfrom(2000)
    end
    
    def sendtype1(type1msg)
      ZFsmb::Smbclientntlmnego(@s, 1, type1msg, "\x00\x00")
      q, x = @s.recvfrom(2000)
      temp = ZFsmb::Client.new(q)
      @uid = temp.smbuid
      msgresp = ZFsmb::Parsentlmfromspnego(q)
      a = ZFNtlm::Message.new()

      return msgresp
    end
    
    def sendtype3(type3msg,rawpkt=nil,items=nil)
      ZFsmb::Smbclientntlmnego(@s, 3, type3msg, @uid, rawpkt)
      q, x = @s.recvfrom(2000)
      actions = @db.GetActionItems(items["aid"])
      actions.each do |act|
        if act[3] == 2 then
          puts "Not Yet Supported, but coming very soon :("
        elsif act[3] == 1 then 
          puts "enum users from group"
          group = (eval act[4])["group"]
          @s.write(ZFsmb::SmbTreeConnectAndX.new(@uid).getpacket)
          q, x = @s.recvfrom(2000)
          # TODO: Parse TREEID From Response!
          @s.write(ZFsmb::SmbNTCreateAndX.new(@uid).getpacket)
          q, x = @s.recvfrom(2000)
          f3 = ZFsmb::SMBTransDCEBind.new(1)
          fid = q[42,2]
          f3.setfid(fid)
          @s.write(f3.getpacket)
          q, x = @s.recvfrom(2000)
          @s.write(ZFsmb::LsaOpenPolicy.new(fid).getpacket)
          q, x = @s.recvfrom(2000)
          handle = ZFsmb.Parsehandle(q)
          f5 = ZFsmb::LsaQueryInfoPolicy.new(handle, fid)
          @s.write(f5.getpacket)
          q, x = @s.recvfrom(2000)
          sid = ZFsmb::ParsesidFromLSA(q)
          f = ZFsmb::LsaClose.new(handle, fid)
          @s.write(f.getpacket)
          q, x = @s.recvfrom(2000)
          f = ZFsmb::SMBClose.new(fid,@uid)
          @s.write(f.getpacket)
          q, x = @s.recvfrom(2000)
          f = ZFsmb::SmbNTCreateAndX.new(@uid,"\\samr")
          @s.write(f.getpacket)
          q, x = @s.recvfrom(2000)
          fid = q[42,2]
          f3 = ZFsmb::SMBTransDCEBind.new(2)
          f3.setfid(fid)
          @s.write(f3.getpacket)
          q, x = @s.recvfrom(2000)
          f = ZFsmb::SamrConnect.new(@server,fid)
          @s.write(f.getpacket)
          q, x = @s.recvfrom(2000)
          handle = ZFsmb.Parsehandle(q)
          f = ZFsmb::SamrOpenDomain.new(handle, fid, sid)
          @s.write(f.getpacket)
          q, x = @s.recvfrom(2000)
          handle2 = ZFsmb.Parsehandle(q)
          f = ZFsmb::SamrLookupNames.new(handle2, fid, group)
          @s.write(f.getpacket)
          q, x = @s.recvfrom(2000)
          if q[q.length-4,4] == "\x73\x00\x00\xc0" then
            @s.write(ZFsmb::SamrClose.new(handle2, fid).getpacket)
            q, x = @s.recvfrom(2000)
            sid = "\x01\x01\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00"
            f = ZFsmb::SamrOpenDomain.new(handle, fid, sid)
            @s.write(f.getpacket)
            q2, x = @s.recvfrom(2000)
            handle2 =  ZFsmb.Parsehandle(q2)
            f = ZFsmb::SamrLookupNames.new(handle2, fid, group)
            @s.write(f.getpacket)
            q, x = @s.recvfrom(2000)
            if q[q.length-4,4] != "\x00\x00\x00\x00" then
              puts "shits fucked up" 
            end
          elsif q[q.length-4,4] != "\x00\x00\x00\x00" then
            puts "crap"
          end
          rid = ZFsmb.ParseSamrLookup(q)
          #rid="\x20\x02\x00\x00" #TODO parse out later
          f = ZFsmb::SamrOpenAlias.new(handle2, fid, rid)
          @s.write(f.getpacket)
          q, x = @s.recvfrom(2000)
          aliashandle = ZFsmb.Parsehandle(q)
          f = ZFsmb::SamrGetMembersInAlias.new(aliashandle, fid)
          @s.write(f.getpacket)
          q, x = @s.recvfrom(2000)
          wtf = ZFsmb.ParseGetMembersInAlias(q)
          #TODO parse sids
          @s.write(ZFsmb::SmbNTCreateAndX.new(@uid).getpacket)
          q, x = @s.recvfrom(2000)
          f3 = ZFsmb::SMBTransDCEBind.new(1)
          fid2 = q[42,2]
          f3.setfid(fid2)
          @s.write(f3.getpacket)
          q, x = @s.recvfrom(2000)
          @s.write(ZFsmb::LsaOpenPolicy.new(fid2).getpacket)
          q, x = @s.recvfrom(2000)
          lsahandle = ZFsmb.Parsehandle(q)
          f = ZFsmb::LsaLookupSids.new(lsahandle, fid2, wtf)
          @s.write(f.getpacket)
          q, x = @s.recvfrom(2000)
          ZFsmb.Parselookupsid(q, wtf)
          @s.write(ZFsmb::SMBClose.new(fid2,@uid).getpacket)
          q, x = @s.recvfrom(2000)
          @s.write(ZFsmb::SMBClose.new(fid,@uid).getpacket)
          q, x = @s.recvfrom(2000)
        else
          puts "unknown smb"
        end
        
      end
    end
  end
end