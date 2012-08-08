require "sqlite3"

module ZFdb
  class DB
    attr_accessor :db
    def initialize(db_file)
      if !(File::exists?(db_file)) then
        puts "No DB Exists yet. Creating One!"
        @db = SQLite3::Database.new(db_file)
        @db.execute " 
          CREATE TABLE users (
            uid INTEGER PRIMARY KEY AUTOINCREMENT,
            uname VARCHAR(256),
            udomain VARCHAR(64),
            ufirstseen TIMESTAMP DEFAULT (datetime('now','localtime'))
          );"
        @db.execute" INSERT INTO users ('udomain','uname') VALUES ('ZACKATTACK','ZACKATTACK')"
        @db.execute "
            CREATE TABLE authsessions (
            authsessionid INTEGER PRIMARY KEY AUTOINCREMENT,
            userid INTEGER,
            hostname VARCHAR(64),
            timestamp TIMESTAMP DEFAULT (datetime('now','localtime')),
            updatetimestamp TIMESTAMP DEFAULT (datetime('now','localtime')),
            osid INTEGER DEFAULT 0,
            ipaddr VARCHAR(16),
            reqpath VARCHAR(256),
            reqactive BOOLEAN,
            method INTEGER DEFAULT 0,
            type1 BLOB
          );"
        @db.execute "
          CREATE TABLE hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid INTEGER,
            schal VARCHAR(32),
            ntlmhash VARCHAR,
            lmhash VARCHAR,
            type3resp BLOB,
            timeseen TIMESTAMP DEFAULT (datetime('now','localtime')),
            authsessionid INTEGER DEFAULT 0
          );"
        @db.execute "
          CREATE TABLE os (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            osname VARCHAR(256)
          );"
        @db.execute "
          CREATE TABLE groups (
            gid INTEGER PRIMARY KEY AUTOINCREMENT,
            groupname VARCHAR
          );"
        @db.execute "
          CREATE TABLE groupmembers (
            gid INTEGER,
            uid INTEGER
          );"
        @db.execute "
          CREATE TABLE targets (
            tid INTEGER PRIMARY KEY AUTOINCREMENT,
            tname VARCHAR,
            tipaddr VARCHAR(16),
            tpriority INTEGER DEFAULT 50
        );"
        @db.execute "
          CREATE TABLE tgroups (
            tgid INTEGER PRIMARY KEY AUTOINCREMENT,
            tgname VARCHAR,
            tgnotes BLOB
          );"
        @db.execute "
          CREATE TABLE tgroupmembers (
            tgid INTEGER,
            tid INTEGER
          );"
        @db.execute "
          CREATE TABLE actions (
            aid INTEGER PRIMARY KEY AUTOINCREMENT,
            apriority INTEGER DEFAULT 50,
            aname VARCHAR,
            anotes VARCHAR,
            moduleid INTEGER,
            aalltargets BOOLEAN,
            aallusers BOOLEAN
          );"
        @db.execute "
          CREATE TABLE aitem (
            aitemid INTEGER PRIMARY KEY AUTOINCREMENT,
            aid INTEGER,
            aipriority INTEGER DEFAULT 50,
            aitemact INTEGER,
            aitemdetail VARCHAR,
            moduleid INTEGER
            )"
        @db.execute "
          CREATE TABLE modules (
            moduleid INTEGER PRIMARY KEY,
            moduleName VARCHAR,
            moduleNotes BLOB,
            modulefxn VARCHAR 
          );"
        @db.execute "INSERT INTO modules (moduleid,moduleName,moduleNotes,modulefxn) VALUES (1,'Exchange Web Services','moduleNotes','ZFClient::EWS')"
        @db.execute "INSERT INTO modules (moduleid,moduleName,moduleNotes,modulefxn) VALUES (2,'SMB','moduleNotes','ZFClient::Smbenum')"
        @db.execute "INSERT INTO modules (moduleid,moduleName,moduleNotes,modulefxn) VALUES (3,'LDAP','moduleNotes','ZFClient::Ldap')"
        @db.execute "INSERT INTO modules (moduleid,moduleName,moduleNotes,modulefxn) VALUES (4,'MSSQL','moduleNotes','ZFClient::Mssql')"
        @db.execute "INSERT INTO modules (moduleid,moduleName,moduleNotes,modulefxn) VALUES (5,'Sharepoint','moduleNotes','ZFClient::Sharepoint')"
        @db.execute "
          CREATE TABLE agroup (
            aid INTEGER,
            gid INTEGER,
            agpriority INTEGER
          );"
        @db.execute "
          CREATE TABLE atgroup (
            aid INTEGER,
            tgid INTEGER,
            atgpriority INTEGER
          );"
        @db.execute "
          CREATE TABLE aresults (
            aresid INTEGER PRIMARY KEY AUTOINCREMENT,
            aid INTEGER,
            tid INTEGER,
            uid INTEGER,
            authsessionid INTEGER DEFAULT 0,
            responsecode INTEGER,
            response BLOB
          );"
        @db.execute "
          CREATE TABLE airesults (
            airesid INTEGER PRIMARY KEY AUTOINCREMENT,
            uid INTEGER,
            tid INTEGER,
            aiteimid INTEGER,
            aistatus INTEGER,
            ainotes VARCHAR)"
        @db.execute "
          CREATE TABLE apireq (
            reqid INTEGER PRIMARY KEY AUTOINCREMENT,
            uid INTEGER,
            type2 BLOB,
            type3 BLOB,
            status INTEGER DEFAULT 0);"
        @db.execute "
          CREATE TABLE aitemact (
            aitemactid INTEGER,
            moduleid INTEGER,
            aitemdesc VARCHAR)"
         @db.execute "INSERT INTO aitemact (aitemactid,moduleid,aitemdesc) VALUES (1,1,'Pull Emails')"
         @db.execute "INSERT INTO aitemact (aitemactid,moduleid,aitemdesc) VALUES (1,2,'Pull Calendar')"
         @db.execute "INSERT INTO aitemact (aitemactid,moduleid,aitemdesc) VALUES (1,3,'Pull Contacts')"
         @db.execute "INSERT INTO aitemact (aitemactid,moduleid,aitemdesc) VALUES (1,4,'Add Email Rule')"
         @db.execute "INSERT INTO aitemact (aitemactid,moduleid,aitemdesc) VALUES (2,1,'Enum Users')"
         @db.execute "INSERT INTO aitemact (aitemactid,moduleid,aitemdesc) VALUES (2,2,'Execute Command')"
         @db.execute "INSERT INTO aitemact (aitemactid,moduleid,aitemdesc) VALUES (2,3,'Create User')"
         @db.execute "INSERT INTO aitemact (aitemactid,moduleid,aitemdesc) VALUES (2,4,'Add User To Group')"
         @db.execute "INSERT INTO aitemact (aitemactid,moduleid,aitemdesc) VALUES (3,1,'Enum Users')"
         @db.execute "INSERT INTO aitemact (aitemactid,moduleid,aitemdesc) VALUES (3,2,'Add User to Group')"
         @db.execute "INSERT INTO aitemact (aitemactid,moduleid,aitemdesc) VALUES (3,3,'Change User Password')" #requires ssl
         @db.execute "INSERT INTO aitemact (aitemactid,moduleid,aitemdesc) VALUES (3,10,'Enum All Users and Groups')"
         
      else
        @db = SQLite3::Database.open(db_file)        
      end
      @db.results_as_hash
    end
    
    def Getuserid(username,domain)
      username = username.upcase
      domain = domain.upcase
      @db.execute("SELECT uid FROM users WHERE uname = ? and udomain = ?",username,domain) do |woof| 
        return woof
      end
      @db.execute("INSERT INTO users('uname','udomain') VALUES (?,?);" ,username,domain)
      return @db.last_insert_row_id
    end
    def GetUserFromId(uid)
      return @db.execute("SELECT uname,udomain FROM users WHERE uid = ? LIMIT 1",uid)[0]
    end
    
    def Getosid(os)
      @db.execute("SELECT id FROM os WHERE osname = ?;",os) do |woof| 
        return woof
      end
      @db.execute("INSERT INTO os ('osname') VALUES (?) ",os)
      return @db.last_insert_row_id
    end
    
    def Newsession(userid=0,hostname="UNKNOWN",osid=0,ipaddr="0.0.0.0",method=0,path="/UNKNOWN")
      @db.execute("INSERT INTO authsessions ('userid','hostname','osid','ipaddr','method','reqpath','reqactive') VALUES(?,?,?,?,?,?,1)",userid,hostname,osid,ipaddr,method,path)
      sessionid = @db.last_insert_row_id
      return sessionid
    end
    def Endsession(sessionid)
      @db.execute("UPDATE authsessions SET 'reqactive'=0 '' = updatetimestamp = (datetime('now','localtime')) WHERE authsessionid=?",sessionid )
    end
    def close()
      @db.close
    end
    def GetActiveSessions
      final = Hash.new
      @db.execute("SELECT * FROM authsessions LEFT JOIN users ON authsessions.userid=users.uid LEFT JOIN os ON authsessions.osid = os.id WHERE reqactive=1 GROUP BY uid ORDER BY authsessionid DESC") do |res|
        final[res[0]] = { :username => res[12],
                          :userid => res[1],
                          :domain => res[13],
                          :starttime => res[3],
                          :hostname => res[2],
                          :sessionfirstseen => res[3], 
                          :userfirstseen => res[14],
                          :path => res[7],
                          :ip => res[6],
                          :os => res[14],
                          :method => res[9] }
      end
      return final
    end
    def ClearActiveSessions(sessid=false)
      return @db.execute("UPDATE authsessions SET 'reqactive'=0")
    end
    
    def StoreHash(userid,lmhash,ntlmhash,schal="1122334455667788",authsessionid="0",type3resp="")
      @db.execute("INSERT INTO hashes ('uid','schal','lmhash','ntlmhash','type3resp','authsessionid') VALUES (?,?,?,?,?,?)",userid,schal,lmhash.unpack("H*"),ntlmhash.unpack("H*"),type3resp,authsessionid)
    end
    
    def GetHashes(userid)
      final = Hash.new            
      @db.execute("SELECT * FROM hashes WHERE uid = ?",userid) do |res|
        final[res[0]] = res
      end
      return final
    end
        
    def GetTodoItem(uid)
      # ugh, here goes the crazy querypalooza
      @db.results_as_hash = true
      res= @db.execute("SELECT users.*, targets.* FROM
        (SELECT users.*, actions.*
        FROM  `users` 
        LEFT JOIN groupmembers on groupmembers.uid = users.uid
        LEFT JOIN groups ON groups.gid = groupmembers.gid
        LEFT JOIN agroup ON agroup.gid = groups.gid 
        LEFT JOIN actions ON actions.aid = agroup.aid
        WHERE (users.uid = ?)   
          OR (users.uname='ZACKATTACK' AND users.udomain='ZACKATTACK')  
          GROUP BY actions.aid ) as users
        LEFT JOIN modules ON modules.moduleid = users.moduleid
        LEFT JOIN atgroup ON atgroup.aid = users.aid
        LEFT JOIN tgroups ON atgroup.tgid = tgroups.tgid
        LEFT JOIN tgroupmembers ON tgroupmembers.tgid = atgroup.tgid
        LEFT JOIN targets ON tgroupmembers.tid = targets.tid
        LEFT JOIN aresults ON users.aid = aresults.aid 
          AND ( ( (users.aalltargets =1 AND users.aallusers =1) AND (aresults.tid = tgroupmembers.tid AND (aresults.uid = users.uid OR (users.uname='ZACKATTACK' AND users.udomain='ZACKATTACK') )) )
          OR ((users.aalltargets =1 AND users.aallusers =0) AND ((aresults.tid = tgroupmembers.tid AND aresults.responsecode = 1) OR (aresults.tid = tgroupmembers.tid AND (aresults.uid = users.uid OR (users.uname='ZACKATTACK' AND users.udomain='ZACKATTACK')))) )
          OR ((users.aalltargets =0 AND users.aallusers =1) AND ((aresults.uid = users.uid AND aresults.responsecode = 1) OR (aresults.tid = tgroupmembers.tid AND (aresults.uid = users.uid OR (users.uname='ZACKATTACK' AND users.udomain='ZACKATTACK')))))
          OR ((users.aalltargets =0 AND users.aallusers =0) AND (aresults.responsecode = 1 OR (aresults.tid = tgroupmembers.tid AND (aresults.uid = users.uid OR (users.uname='ZACKATTACK' AND users.udomain='ZACKATTACK')))))
        ) WHERE responsecode IS NULL AND tipaddr IS NOT NULL ORDER BY apriority DESC, atgpriority DESC, tpriority DESC, RANDOM() LIMIT 1", uid)
        @db.results_as_hash = false
#        @db.execute("UPDATE ")
        return res
    end
    def GetTodoActions(aid)
      # ugh, here goes the crazy querypalooza
      @db.results_as_hash = true
      res= @db.execute("SELECT aitem.* FROM actions LEFT JOIN aitem ON actions.aid = aitem.aid WHERE actions.aid = ?", aid)
        @db.results_as_hash = false
#        @db.execute("UPDATE ")
        return res
    end
    def GetGroupID(groupname)
      @db.execute("SELECT gid FROM groups WHERE groupname = ?",groupname) do |woof| 
        return woof
      end
      @db.execute("INSERT INTO groups ('groupname') VALUES (?);" ,groupname)
      return @db.last_insert_row_id
    end
    def AddUserToGroup(uid,gid)
      @db.execute("SELECT gid from groupmembers WHERE gid = ? AND uid = ?",gid, uid) do |woof| 
        return false
      end
      return @db.execute("INSERT INTO groupmembers ('gid','uid') VALUES (?,?);" ,gid, uid)
    end
    def DelUserFromGroup(uid,gid)
      @db.execute("DELETE from groupmembers WHERE gid = ? AND uid = ?",gid, uid)
    end
    def NewActionItem(aid,amoduleid,aitemact,aitemdetail,aipriority=50)
      @db.execute("INSERT INTO aitem ('aid','moduleid','aitemact','aitemdetail','aipriority') VALUES (?,?,?,?,?)",aid,amoduleid,aitemact,aitemdetail,aipriority)
      return @db.last_insert_row_id
    end
    def NewAction(aname,anotes,amoduleid,aalltargets=1,aallusers=1, priority=50)
      @db.execute("INSERT INTO actions ('aname','anotes','moduleid','aalltargets','aallusers') VALUES(?,?,?,?,?)",aname,anotes,amoduleid,aalltargets,aallusers)
      last = @db.last_insert_row_id
      if amoduleid == "1" then
        details = {"folder" => "inbox"} #autoadd download inbox items
        NewActionItem(last,amoduleid,1,details.inspect)
      elsif amoduleid == "2" then
        details = {"group" => "Administrators"} #autoadd enum Admins
        NewActionItem(last,amoduleid,1,details.inspect)
      elsif amoduleid == "3" then
        details = {"group" => "Domain Administrators"} #autoadd enum DAs
        NewActionItem(last,amoduleid,1,details.inspect)
      end
      return last 
    end
    def GetActionItems(aid)
      return @db.execute("SELECT aitem.*,aitemact.aitemdesc FROM aitem LEFT JOIN actions ON actions.aid = aitem.aid LEFT JOIN aitemact ON aitem.aitemact = aitemact.aitemactid AND aitemact.moduleid = actions.moduleid WHERE aitem.aid = ? ",aid)
    end
    def AddGroupToAction(gid,aid)
      @db.execute("SELECT gid from agroup WHERE gid = ? AND aid = ?",gid, aid) do |woof| 
        return false
      end
      return @db.execute("INSERT INTO agroup ('gid','aid') VALUES (?,?);" ,gid, aid)
    end
    def DeleteAction(aid)
      @db.execute("DELETE FROM actions WHERE aid = ?;",aid)
      @db.execute("DELETE FROM agroup WHERE aid = ?;",aid)
      @db.execute("DELETE FROM atgroup WHERE aid = ?;",aid)
    end
    def DeleteActionItem(aiid)
      @db.execute("DELETE FROM aitem WHERE aitemid = ?",aiid)
    end
    def GetTargetId(tipaddr,tname)
      @db.execute("SELECT tid FROM targets WHERE tipaddr = ?",tipaddr) do |woof| 
        return woof
      end
      @db.execute("INSERT INTO targets ('tipaddr','tname') VALUES (?,?);" ,tipaddr,tname)
      return @db.last_insert_row_id 
    end
    def GetTgroupID(tgname)
      @db.execute("SELECT tgid FROM tgroups WHERE tgname = ?",tgname) do |woof| 
        return woof
      end
      @db.execute("INSERT INTO tgroups ('tgname') VALUES (?);" ,tgname)
      return @db.last_insert_row_id
    end
    def AddTargetToTgroup(tid,tgid)
      @db.execute("SELECT tgid from tgroupmembers WHERE tgid = ? AND tid = ?",tgid, tid) do |woof| 
        return false
      end
      return @db.execute("INSERT INTO tgroupmembers ('tgid','tid') VALUES (?,?);" ,tgid, tid)     
    end
    def AddTgroupToAction(tgid,aid)
      @db.execute("SELECT tgid from atgroup WHERE tgid = ? AND aid = ?",tgid, aid) do |woof| 
        return false
      end
      return @db.execute("INSERT INTO atgroup ('tgid','aid') VALUES (?,?);" ,tgid, aid)
    end
    def ActionPerformed(aid,tid,uid,responsecode=2,response="SETUP REQUESTED") 
      @db.execute("INSERT INTO aresults ('aid','tid','uid','responsecode','response') VALUES (?,?,?,?,?)",aid,tid,uid,responsecode,response)
      return @db.last_insert_row_id
    end
    def ModifyActionResonse(arid,resonsecode,response)
      @db.execute("UPDATE arresults SET 'responsecode' = ?, 'response' = ? WHERE aresid = ?",responsecode,repsonse,arid)
    end
    def GetGroups(uid=nil)
      if uid==nil then return @db.execute("SELECT * FROM groups")
      else return @db.execute("SELECT groups.* FROM groups LEFT JOIN groupmembers ON groups.gid = groupmembers.gid  LEFT JOIN users ON groupmembers.uid = users.uid WHERE users.uid = ?",uid)
      end
    end
    def GetGroupMembers(gid)
      return @db.execute("SELECT users.* FROM groups LEFT JOIN groupmembers ON groups.gid = groupmembers.gid LEFT JOIN users ON users.uid = groupmembers.uid WHERE groups.gid = ?",gid)
    end
    def DeleteGroup
      #not supported yet - deleting would break shit
    end
    def GetUsers
      return @db.execute("SELECT users.*,authsessions.timestamp,authsessions.ipaddr FROM users LEFT JOIN authsessions ON users.uid=authsessions.userid AND authsessions.timestamp = (SELECT MAX(timestamp) FROM authsessions WHERE authsessions.userid = users.uid) ORDER BY timestamp DESC")
    end
    def GetTargets(tgid=0)
      if (tgid==0) then
       return @db.execute("SELECT * FROM targets")
      else
        return @db.execute("SELECT targets.* FROM targets LEFT JOIN tgroupmembers ON tgroupmembers.tid = targets.tid WHERE tgroupmembers.tgid = ?",tgid)
      end
    end
    def GetTGroups
      return @db.execute("SELECT * FROM tgroups")
    end 
    def DelTargetFromTgroup(tid,tgid)
      return @db.execute("DELETE FROM tgroupmembers WHERE tid = ? AND tgid = ?",tid,tgid)
    end
    def GetActions()
      return @db.execute("SELECT * FROM actions")
    end
    def GetActionsUGroup(aid)
      return @db.execute("SELECT groups.* FROM agroup LEFT JOIN groups ON agroup.gid = groups.gid WHERE agroup.aid = ?",aid)
    end
    def GetActionsTGroup(aid)
      return @db.execute("SELECT tgroups.* FROM atgroup LEFT JOIN tgroups on atgroup.tgid = tgroups.tgid WHERE atgroup.aid = ?",aid)
    end
    def ExportHashes()
      res = @db.execute("SELECT * FROM hashes LEFT JOIN users ON hashes.uid = users.uid GROUP BY hashes.uid")
      return res
    end
    def GetMods()
      res = @db.execute("SELECT * FROM modules")
    end
    def GetApiReq(uid)
      res = @db.execute("SELECT * FROM apireq WHERE uid = ? AND status=0 LIMIT 1",uid)
      if res[0]==nil then return nil
      else 
        
        return {"moduleid" =>0, "aid"=>0, "tipaddr" => res[0][0].to_s }
      end
      #return reqid
    end
    def AddApiReq(uname,udomain,type2)
      uid = Getuserid(uname,udomain)
      @db.execute("INSERT INTO apireq (uid,type2) VALUES (?,?)", uid,type2)
      return @db.last_insert_row_id
    end
    def ProcessApiReq(reqid)
      @db.execute("UPDATE apireq SET status = 2 WHERE reqid = ?", reqid)
      return @db.execute("SELECT * FROM apireq WHERE reqid = ? LIMIT 1",reqid)[0]
      #return type2
    end
    def SetApiResp(reqid, type3resp)
      @db.execute("UPDATE apireq SET status = 1 , type3 = ? WHERE reqid = ?",type3resp,reqid)
      #set type3
    end
    def WaitForApiResp(reqid,timeout)
      begin
      Timeout.timeout(timeout) {
        resp = nil
        while resp==nil do
          resp = @db.execute("SELECT type3 FROM apireq WHERE reqid = ? AND status = 1",reqid)[0]
          sleep 0.1
        end
        return resp
      }
      rescue Timeout::Error
        puts "No API Response In Timeout Window"
        return nil
      rescue 
        puts $! 
      end
    end
  end
end
