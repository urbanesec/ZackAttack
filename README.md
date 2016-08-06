=====
ZackAttack! - Relaying NTLM Like Nobody's Business
=====


=======
WTF Is This?
=======

tl;dr version - ZackAttack! is a new Tool Set to do NTLM Authentication relaying unlike any other tool currently out there.

=
So how is ZackAttack! different / better? Compared to other tools...
=

 - Supports NTLMv2 :)
 - Brings up external impact for NTLM by relaying to external Exchange Web Services servers ( think mobile phone users :) )
 - Custom Rogue HTTP and SMB Server funneling into a single pooled source and knows who the user is and keeps them authenticating without closing the socket
 - Rule based logic to auto-perform actions upon seing a user belonging to a group. When no rule exists, the rogue server holds on to the auth session as long as possible until a rule or api request comes in.
 - Auto / Guided generation to creating methods to get users to auto-authenticate without interaction
 - New methods for client auto authentication including geting FF/Chrome to auto-auth via UNC SMB shares (similar to IE)
 - Relaying to LDAP (critical for relaying to Domain Controllers), Exchange Web Services, and soon mssql.
 - SOCKS proxy to allow NTLM relay attacks with your favorite tools (proxychains smbclient....etc)
 - Focuses on not just poping the shells that traditional relays do, but leveraging dumb users as well and getting data through them.
 
So much for tl;dr ;) The goal? A Firesheep esque tool for relaying NTLM auths

=
How do I Get Started
=

1) ruby zackattack.rb 

2) open your favorite browser to http://zf:zf@localhost:4531/ 

3) ..... 

4) PROFIT! Or not. It's alpha still. 

Code is written for ruby1.9 but should work with 1.8. Requires net/http(s) and webrick rubygems

=
So What Are the Components
=

The Rogue Servers - HTTP and SMB. These get the auth requests and keep recycling them 

The Clients - These connect to target servers and request NTLM creds from the Rogue Servers 

The Rules - Define auto actions to perform upon seeing a user. 

The Payloads - Methods to get users to autoauth with Integrated Windows Auth ergo not prompting the user for auth.

=
XYZ Doesn't work
=

I'm sure it doesn't ;) I don't always code in ruby, but when i do, i make sure to introduce as many bugs as possible :)

Submit as much info as you can (comfortably) to the issues page. Please try to get a wireshark / pcap capture if it's a client issue. If it contains sensitive data (i.e. ntlm creds of a client) let me know and we can work around that if possible.

Feature request? I want to hear it! Check the todo file and see if i already mentioned it in there, otherwise submit!

I'll fill in more details later....