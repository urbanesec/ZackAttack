#!/usr/bin/env ruby
#encoding: ASCII-8BIT
$: << File.expand_path(File.dirname(__FILE__))
$: << File.expand_path(File.dirname(__FILE__) + "/lib")
$: << File.expand_path(File.dirname(__FILE__) + "/clients")
$: << File.expand_path(File.dirname(__FILE__) + "/payloads")
require 'config'
require 'zfhttpd'
require 'zfsmbd'
require 'zfadmingui'
require 'zfsocks'
puts "=================================================="
puts "Here Goes ZackAttack! Booting Up!....."
puts "=================================================="
#clear out old sessions / stuf TODO: consolidate into an init sequence / db cleanup
db = ZFdb::DB.new()
db.ClearActiveSessions
db.db.execute("DELETE FROM aresults")

  smb = ZFsmb::Server.new(SMBDIP) #only works on 445
  http = ZFhttpd::Server.new(HTTPIP,HTTPPort)
  gui = ZFadmingui::Http.new(MGMTIP,MGMTPort)
  socks = ZFsocks::Server.new(SOCKSIP,SOCKSPort)
  #add CLI

  c = Thread.new{gui.start()} 
  d = Thread.new{socks.start()}
  b = Thread.new{smb.start()}
  a = Thread.new{http.start()}
  c.join
  
  puts "exiting"