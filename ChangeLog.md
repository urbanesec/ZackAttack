### 0.1.2 / 2014-10-10

* Code clean up
* Added Gemfile
* Confrim starts on kali

### 0.1.1 / 2012-08-29

* Disabled Left Nav Bar Dropdown Rules as they were not coded. Coming soon.
* Updated Users page to include auth method and path. Integrated coding to ignore IPC$
* Fixed EWS bug where CHANGEME was not being replaced in the xml with a folder name.
* Fixed issue with random auths failing due to use of gsub("\n","") of base64 encoded api data and \x0a used in some ntlm auths.
* Fixed Rule logic for user not executing rules on first connection attempt (i.e. no user id created and recieving 0)
* Fixed typo for Errno::EACCES
* Fixed issue with left bar not removing users after connection terminates

### 0.1.0 / 2012-08-08

* Initial release:
