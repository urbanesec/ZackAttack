#!/usr/bin/env ruby
#encoding: ASCII-8BIT
=begin
 
 #####################################################################
 
 YOUR CONFIGS!!!!!! RAWR
 TODO: Put in a real about for the configs :)
 
 #####################################################################
  
 So things the user should set after startup
  - Domain Controllers (if external)
  - dns server?
  - EWS target
  - default domain for 1122334455667788
  - default hostname for 1122334455667788
  - default challange hash
  - socks ports to disect (i.e. 445,445/8443,80/8080/8000, etc.)
=end
  SMBDIP = "0.0.0.0"
  HTTPIP = "0.0.0.0"
  HTTPPort = "80"
  MGMTIP = "0.0.0.0"
  MGMTPort = "4531"
  SOCKSIP = "127.0.0.1"
  SOCKSPort = "4532"

  MGMTUser = "zf"
  MGMTPass = "zf"
  
  APIUser = "api"
  APIPass = "api"
  
  DBFile = File.expand_path(File.dirname(__FILE__) + "/za.db")
  
  GUID = "\x6e\x09\x9f\x3f\x4a\xf0\x64\x4f\xa2\x9f\xd8\xb2\xd6\x5f\x4f\x7d"
  NativeOS = "Unix"
  NativeLM = "Samba"

=begin
  Configs to add:
  httpd bind ip
  smbd bind ip
  managmeent port / password
  api password
  database file
=end 
