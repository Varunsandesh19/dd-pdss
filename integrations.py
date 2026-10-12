"""Optional Google & Microsoft read-only OAuth integrations. Requires cryptography."""
import os, json, sqlite3, secrets, base64, re, html
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlencode, urlsplit, parse_qs, quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from email.utils import parsedate_to_datetime
from cryptography.fernet import Fernet

ROOT=Path(__file__).resolve().parent
GOOGLE_SCOPES='https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/classroom.courses.readonly https://www.googleapis.com/auth/classroom.coursework.me.readonly'
MS_SCOPES='offline_access User.Read Mail.Read Calendars.Read'
PROVIDERS={
 'google':('GOOGLE_CLIENT_ID','GOOGLE_CLIENT_SECRET','https://accounts.google.com/o/oauth2/v2/auth','https://oauth2.googleapis.com/token',GOOGLE_SCOPES),
 'microsoft':('MS_CLIENT_ID','MS_CLIENT_SECRET','https://login.microsoftonline.com/common/oauth2/v2.0/authorize','https://login.microsoftonline.com/common/oauth2/v2.0/token',MS_SCOPES)
}
def now():return datetime.now(timezone.utc)
def iso(t):return t.isoformat(timespec='seconds')
def key():
 p=Path(os.getenv('DD_TOKEN_KEY_FILE',str(ROOT/'.token_key')))
 if not p.exists():
  p.parent.mkdir(parents=True,exist_ok=True)
  try:
   with p.open('xb') as f:f.write(Fernet.generate_key())
   os.chmod(p,0o600)
  except FileExistsError:pass
 return Fernet(p.read_bytes().strip())
def encrypt(t):return key().encrypt(json.dumps(t).encode()).decode()
def decrypt(t):return json.loads(key().decrypt(t.encode()))
def request_json(url,data=None,headers=None):
 body=urlencode(data).encode() if isinstance(data,dict) else data
 hdr={'Accept':'application/json',**(headers or {})}
 if isinstance(data,dict):hdr['Content-Type']='application/x-www-form-urlencoded'
 try:
  with urlopen(Request(url,data=body,headers=hdr),timeout=15) as r:return json.load(r)
 except HTTPError as e:
  raise ValueError('Provider API rejected the request (HTTP '+str(e.code)+'). Check permissions and app setup.')
def init(db):
 with db() as c:c.executescript('''
 CREATE TABLE IF NOT EXISTS oauth_states(state TEXT PRIMARY KEY,user_id INTEGER NOT NULL,provider TEXT NOT NULL,expires TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS connections(user_id INTEGER NOT NULL,provider TEXT NOT NULL,token TEXT NOT NULL,updated TEXT NOT NULL,PRIMARY KEY(user_id,provider));
 CREATE TABLE IF NOT EXISTS suggestions(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,source TEXT NOT NULL,external_id TEXT NOT NULL,title TEXT NOT NULL,starts_at TEXT NOT NULL,ends_at TEXT NOT NULL,notes TEXT NOT NULL DEFAULT '',created TEXT NOT NULL,UNIQUE(user_id,source,external_id));
 CREATE TABLE IF NOT EXISTS imported_events(user_id INTEGER,source TEXT,external_id TEXT,event_id INTEGER,UNIQUE(user_id,source,external_id));''')
def configured(p):
 item=PROVIDERS[p];return all(os.getenv(n) for n in item[:2]) and bool(os.getenv('DD_PUBLIC_URL'))
def root_url():return os.getenv('DD_PUBLIC_URL','').rstrip('/')
def callback(p):return root_url()+'/oauth/'+p+'/callback'
def redirect(handler,url):
 handler.send_response(302);handler.send_header('Location',url);handler.send_header('Cache-Control','no-store');handler.end_headers()
def start(handler,p,user,db):
 if not configured(p):return handler.send_json({'error':p.title()+' connection needs OAuth credentials and DD_PUBLIC_URL. See SETUP.md.'},409)
 state=secrets.token_urlsafe(35)
 with db() as c:c.execute('INSERT INTO oauth_states VALUES(?,?,?,?)',(state,user['id'],p,iso(now()+timedelta(minutes=10))))
 client_id=os.environ[PROVIDERS[p][0]]
 args={'client_id':client_id,'redirect_uri':callback(p),'response_type':'code','scope':PROVIDERS[p][4],'state':state}
 if p=='google':args.update(access_type='offline',prompt='consent',include_granted_scopes='true')
 else:args['prompt']='select_account'
 return handler.send_json({'url':PROVIDERS[p][2]+'?'+urlencode(args)})
def finish(handler,p,db):
 q=parse_qs(urlsplit(handler.path).query);state=q.get('state',[''])[0];code=q.get('code',[''])[0]
 with db() as c:
  entry=c.execute('SELECT * FROM oauth_states WHERE state=? AND provider=?',(state,p)).fetchone()
  c.execute('DELETE FROM oauth_states WHERE state=?',(state,))
 if not entry or entry['expires']<iso(now()) or not code:return redirect(handler,'/?integration=failed')
 try:
  token=request_json(PROVIDERS[p][3],{'client_id':os.environ[PROVIDERS[p][0]],'client_secret':os.environ[PROVIDERS[p][1]],'code':code,'grant_type':'authorization_code','redirect_uri':callback(p)})
  token['expires_at']=int(now().timestamp())+int(token.get('expires_in',3600))-90
  if not token.get('access_token'):raise ValueError('Missing token')
  with db() as c:c.execute('INSERT INTO connections VALUES(?,?,?,?) ON CONFLICT(user_id,provider) DO UPDATE SET token=excluded.token,updated=excluded.updated',(entry['user_id'],p,encrypt(token),iso(now())))
  redirect(handler,'/?integration=connected')
 except Exception as e:
  print('OAuth callback error:',str(e));redirect(handler,'/?integration=failed')
def access(db,user,p):
 with db() as c:rec=c.execute('SELECT token FROM connections WHERE user_id=? AND provider=?',(user,p)).fetchone()
 if not rec:raise ValueError(p.title()+' is not connected')
 token=decrypt(rec['token'])
 if int(token.get('expires_at',0))<int(now().timestamp()):
  if not token.get('refresh_token'):raise ValueError('Re-connect account to renew permission')
  fresh=request_json(PROVIDERS[p][3],{'client_id':os.environ[PROVIDERS[p][0]],'client_secret':os.environ[PROVIDERS[p][1]],'grant_type':'refresh_token','refresh_token':token['refresh_token']})
  token.update(fresh);token['expires_at']=int(now().timestamp())+int(fresh.get('expires_in',3600))-90
  with db() as c:c.execute('UPDATE connections SET token=?,updated=? WHERE user_id=? AND provider=?',(encrypt(token),iso(now()),user,p))
 return token['access_token']
def get(db,user,p,url):return request_json(url,headers={'Authorization':'Bearer '+access(db,user,p)})
def date(s):
 if not s:return None
 try:
  if len(s)==10:s+='T09:00:00'
  d=datetime.fromisoformat(s.replace('Z','+00:00'))
  return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
 except Exception:return None
def add_suggestion(db,user,source,ext,title,start,end,notes=''):
 if not start or not end or end<=start:return False
 with db() as c:
  existing=c.execute('SELECT 1 FROM imported_events WHERE user_id=? AND source=? AND external_id=?',(user,source,ext)).fetchone()
  if existing:return False
  cur=c.execute('INSERT OR IGNORE INTO suggestions(user_id,source,external_id,title,starts_at,ends_at,notes,created) VALUES(?,?,?,?,?,?,?,?)',(user,source,str(ext),title[:120],iso(start),iso(end),notes[:1000],iso(now())))
  return cur.rowcount>0
# Conservative email extraction; uncertain dates are not automatically inserted into calendar.
MONTHS='January February March April May June July August September October November December Jan Feb Mar Apr Jun Jul Aug Sep Sept Oct Nov Dec'
def extract_date(text):
 regex=r'\b(?:20\d{2}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}\s+(?:'+ '|'.join(MONTHS.split())+r')\s+20\d{2})\b'
 m=re.search(regex,text,re.I)
 if not m:return None
 s=m.group();start=None
 try:
  if re.match(r'^20\d\d',s):start=datetime.fromisoformat(s.replace('/','-')).replace(tzinfo=timezone.utc)
  else:
   for fmt in ('%d %B %Y','%d %b %Y'):
    try:start=datetime.strptime(s,fmt).replace(tzinfo=timezone.utc);break
    except ValueError:pass
 except ValueError:pass
 if not start:return None
 tm=re.search(r'\b(1[0-2]|0?[1-9])(?::([0-5]\d))?\s*(am|pm)\b',text,re.I)
 if tm:
  hr=int(tm.group(1))%12+(12 if tm.group(3).lower()=='pm' else 0)
  start=start.replace(hour=hr,minute=int(tm.group(2) or 0))
 else:start=start.replace(hour=9)
 return start
ACADEMIC=re.compile(r'exam|assignment|deadline|lecture|timetable|schedule|class|quiz|workshop|presentation|assessment|submission|coursework|semester|reschedul',re.I)
def sync(db,user,p):
 added=0;checked=0;issues=[]
 if p=='google':
  sources=[('Google Calendar','https://www.googleapis.com/calendar/v3/calendars/primary/events?'+urlencode({'timeMin':iso(now()-timedelta(days=5)),'timeMax':iso(now()+timedelta(days=120)),'singleEvents':'true','maxResults':100})),('Gmail','https://gmail.googleapis.com/gmail/v1/users/me/messages?'+urlencode({'q':'newer_than:90d (exam OR assignment OR timetable OR rescheduled OR deadline OR presentation)','maxResults':35}))]
 else:
  sources=[('Outlook Calendar','https://graph.microsoft.com/v1.0/me/calendarView?'+urlencode({'startDateTime':iso(now()-timedelta(days=5)),'endDateTime':iso(now()+timedelta(days=120)),'$top':100})),('Outlook Mail','https://graph.microsoft.com/v1.0/me/messages?'+urlencode({'$top':35,'$select':'id,subject,bodyPreview,receivedDateTime',' $orderby'.strip():'receivedDateTime desc'}))]
 for source,url in sources:
  try:
   result=get(db,user,p,url)
   items=result.get('items',result.get('messages',result.get('value',[])))
   for item in items:
    checked+=1
    if 'Calendar' in source:
     if p=='google':
      start=date(item.get('start',{}).get('dateTime') or item.get('start',{}).get('date'))
      end=date(item.get('end',{}).get('dateTime') or item.get('end',{}).get('date'))
     else:
      start=date(item.get('start',{}).get('dateTime'));end=date(item.get('end',{}).get('dateTime'))
     # All-day events are imported as full-day commitments; user can remove ones irrelevant to academics.
     title=item.get('summary') or item.get('subject') or 'Calendar event'
     if add_suggestion(db,user,source,item.get('id'),title,start,end,'Review imported calendar event before adding.') :added+=1
    else:
     if p=='google':
      msg=get(db,user,p,'https://gmail.googleapis.com/gmail/v1/users/me/messages/'+quote(item['id'])+'?format=metadata&metadataHeaders=Subject')
      title=next((h['value'] for h in msg.get('payload',{}).get('headers',[]) if h.get('name','').lower()=='subject'),'Email update');body=msg.get('snippet','')
     else:title=item.get('subject','Email update');body=item.get('bodyPreview','')
     if not ACADEMIC.search(title+' '+body):continue
     st=extract_date(title+' '+body)
     if st and add_suggestion(db,user,source,item['id'],title,st,st+timedelta(hours=1),'Tentative date extracted from email. Confirm against original email before accepting.'):added+=1
  except Exception as e:issues.append(source+': '+str(e))
 if p=='google':
  try:
   courses=get(db,user,p,'https://classroom.googleapis.com/v1/courses?'+urlencode({'studentId':'me','pageSize':20})).get('courses',[])
   for course in courses:
    try:
     tasks=get(db,user,p,'https://classroom.googleapis.com/v1/courses/'+quote(course['id'])+'/courseWork?pageSize=30').get('courseWork',[])
     for task in tasks:
      checked+=1
      dd=task.get('dueDate',{});tt=task.get('dueTime',{})
      if not dd:continue
      st=date(f"{dd.get('year'):04d}-{dd.get('month'):02d}-{dd.get('day'):02d}T{tt.get('hours',23):02d}:{tt.get('minutes',59):02d}:00")
      if st and add_suggestion(db,user,'Google Classroom',task['id'],task.get('title','Coursework'),st,st+timedelta(minutes=30),'Course: '+course.get('name','')):added+=1
    except Exception as e:issues.append('Classroom course '+course.get('name','')+': '+str(e))
  except Exception as e:issues.append('Google Classroom: '+str(e))
 return {'checked':checked,'added':added,'warnings':issues[:5]}
def handle(handler,method,path,user,db):
 if path=='/api/integrations' and method=='GET':
  with db() as c:rows=c.execute('SELECT provider,updated FROM connections WHERE user_id=?',(user['id'],)).fetchall()
  return handler.send_json({'providers':{p:{'configured':configured(p),'connected':any(r['provider']==p for r in rows),'updated':next((r['updated'] for r in rows if r['provider']==p),None)} for p in PROVIDERS},'college':'Requires a college-specific authorized API'})
 if path=='/api/suggestions' and method=='GET':
  with db() as c:rows=[dict(r) for r in c.execute('SELECT id,source,title,starts_at,ends_at,notes FROM suggestions WHERE user_id=? ORDER BY starts_at LIMIT 150',(user['id'],))]
  return handler.send_json({'suggestions':rows})
 m=re.fullmatch(r'/api/integrations/(google|microsoft)/(connect|sync|disconnect)',path)
 if m and method=='POST':
  if not handler.safe_mutation(user):return
  p,action=m.groups()
  if action=='connect':return start(handler,p,user,db)
  if action=='disconnect':
   with db() as c:c.execute('DELETE FROM connections WHERE user_id=? AND provider=?',(user['id'],p))
   return handler.send_json({'ok':True})
  return handler.send_json(sync(db,user['id'],p))
 m=re.fullmatch(r'/api/suggestions/(\d+)/(accept|dismiss)',path)
 if m and method=='POST':
  if not handler.safe_mutation(user):return
  id,action=m.groups()
  with db() as c:
   r=c.execute('SELECT * FROM suggestions WHERE id=? AND user_id=?',(id,user['id'])).fetchone()
   if not r:return handler.send_json({'error':'Suggestion missing'},404)
   if action=='accept':
    c.execute('INSERT INTO events(user_id,title,category,starts_at,ends_at,location,notes,source,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(user['id'],r['title'],'Event',r['starts_at'],r['ends_at'],'',r['notes'],r['source'],iso(now())))
    eid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
    c.execute('INSERT OR IGNORE INTO imported_events VALUES(?,?,?,?)',(user['id'],r['source'],r['external_id'],eid))
   c.execute('DELETE FROM suggestions WHERE id=? AND user_id=?',(id,user['id']))
  return handler.send_json({'ok':True})
 return None
