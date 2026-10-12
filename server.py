#!/usr/bin/env python3
"""Deadline Domino: dependency-free SQLite-backed academic planner server."""
import os, json, sqlite3, secrets, hashlib, hmac, mimetypes, re, socket
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from http.cookies import SimpleCookie
import integrations

ROOT=Path(__file__).resolve().parent
DB=Path(os.environ.get('DD_DB',str(ROOT/'deadline_domino.sqlite3')))
HOST=os.environ.get('HOST','127.0.0.1'); PORT=int(os.environ.get('PORT','8080'))

def now():return datetime.now(timezone.utc)
def iso(dt):return dt.isoformat(timespec='seconds')
def conn():
 c=sqlite3.connect(DB, timeout=15);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');return c

def hash_password(password, salt=None):
 salt=salt or secrets.token_bytes(16)
 digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,250000)
 return salt.hex()+':'+digest.hex()
def verify_password(password, stored):
 try:
  s,d=stored.split(':');return hmac.compare_digest(hash_password(password,bytes.fromhex(s)).split(':')[1],d)
 except Exception:return False

def init_db():
 DB.parent.mkdir(parents=True,exist_ok=True)
 with conn() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password_hash TEXT NOT NULL,demo INTEGER DEFAULT 0);
 CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,csrf TEXT NOT NULL,expires_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));
 CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,title TEXT NOT NULL,category TEXT NOT NULL,starts_at TEXT NOT NULL,ends_at TEXT NOT NULL,location TEXT NOT NULL DEFAULT '',notes TEXT NOT NULL DEFAULT '',source TEXT NOT NULL DEFAULT 'Manual',created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));''')

 integrations.init(conn)

def parse_date(s):
 if not isinstance(s,str):raise ValueError('Invalid date')
 try:d=datetime.fromisoformat(s.replace('Z','+00:00'))
 except ValueError:raise ValueError('Enter a valid date and time')
 if d.tzinfo is None:d=d.replace(tzinfo=timezone.utc)
 return d.astimezone(timezone.utc)

def event_payload(data):
 title=str(data.get('title','')).strip()[:120]
 category=str(data.get('category','Class')).strip()
 if not title:raise ValueError('Event title is required')
 if category not in ('Exam','Assignment','Presentation','Class','Event','Other'):raise ValueError('Invalid category')
 start=parse_date(data.get('starts_at'));end=parse_date(data.get('ends_at'))
 if end<=start:raise ValueError('End must be later than start')
 if end-start>timedelta(days=7):raise ValueError('Event is too long')
 return title,category,iso(start),iso(end),str(data.get('location',''))[:160],str(data.get('notes',''))[:1200],str(data.get('source','Manual'))[:80]

class Handler(BaseHTTPRequestHandler):
 server_version='DeadlineDomino/1.0'
 def log_message(self,fmt,*args):pass
 def send_json(self,obj,status=200,cookie=None):
  raw=json.dumps(obj).encode();self.send_response(status)
  self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Content-Length',str(len(raw)))
  self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
  self.send_header('X-Frame-Options','DENY')
  if cookie:self.send_header('Set-Cookie',cookie)
  self.end_headers();self.wfile.write(raw)
 def read_body(self):
  length=int(self.headers.get('Content-Length','0'))
  if length>40000:raise ValueError('Request is too large')
  try:return json.loads(self.rfile.read(length) or b'{}')
  except Exception:raise ValueError('Invalid JSON')
 def authenticate(self):
  jar=SimpleCookie()
  try:jar.load(self.headers.get('Cookie',''))
  except Exception:return None
  if 'dd_session' not in jar:return None
  token=jar['dd_session'].value
  with conn() as c:
   row=c.execute('SELECT s.csrf,s.expires_at,u.id,u.email,u.name,u.demo FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
  if not row or row['expires_at']<=iso(now()):return None
  return dict(row)
 def safe_mutation(self,user):
  if not user or not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),user['csrf']):
   self.send_json({'error':'Session expired or security token missing'},403);return False
  return True
 def handle_api(self,method,path):
  if method=='POST' and path in ('/api/register','/api/login'):
   data=self.read_body();email=str(data.get('email','')).strip().lower();password=str(data.get('password',''))
   if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',email) or len(email)>240:raise ValueError('Enter a valid email')
   with conn() as c:
    if path=='/api/register':
     name=str(data.get('name','')).strip()[:80]
     if len(name)<2:raise ValueError('Enter your name')
     if len(password)<8:raise ValueError('Password must have at least 8 characters')
     try:c.execute('INSERT INTO users(email,name,password_hash) VALUES(?,?,?)',(email,name,hash_password(password)))
     except sqlite3.IntegrityError:return self.send_json({'error':'Email already registered'},409)
    user=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
    if path=='/api/login' and (not user or not verify_password(password,user['password_hash'])):
     return self.send_json({'error':'Incorrect email or password'},401)
    token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(24)
    c.execute('INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),user['id'],csrf,iso(now()+timedelta(days=7))))
   secure='; Secure' if self.headers.get('X-Forwarded-Proto')=='https' else ''
   return self.send_json({'user':{'id':user['id'],'email':user['email'],'name':user['name'],'demo':bool(user['demo'])},'csrf':csrf},cookie=f'dd_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800{secure}')
  user=self.authenticate()
  if method=='GET' and path=='/api/me':
   return self.send_json({'user':{k:user[k] for k in ('id','email','name','demo')} if user else None,'csrf':user['csrf'] if user else None})
  if not user:return self.send_json({'error':'Please log in'},401)
  if method=='GET' and path=='/api/events':
   with conn() as c:rows=[dict(r) for r in c.execute('SELECT id,title,category,starts_at,ends_at,location,notes,source FROM events WHERE user_id=? ORDER BY starts_at,id',(user['id'],))]
   return self.send_json({'events':rows})
  if method in ('POST','PUT','DELETE') and not self.safe_mutation(user):return
  if method=='POST' and path=='/api/logout':
   jar=SimpleCookie();jar.load(self.headers.get('Cookie',''))
   if 'dd_session' in jar:
    with conn() as c:c.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(jar['dd_session'].value.encode()).hexdigest(),))
   return self.send_json({'ok':True},cookie='dd_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
  if method=='POST' and path=='/api/events':
   fields=event_payload(self.read_body())
   with conn() as c:
    cur=c.execute('INSERT INTO events(user_id,title,category,starts_at,ends_at,location,notes,source,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(user['id'],*fields,iso(now())))
   return self.send_json({'id':cur.lastrowid},201)
  match=re.fullmatch(r'/api/events/(\d+)',path)
  if match and method in ('PUT','DELETE'):
   event_id=int(match.group(1))
   with conn() as c:
    existing=c.execute('SELECT id FROM events WHERE id=? AND user_id=?',(event_id,user['id'])).fetchone()
    if not existing:return self.send_json({'error':'Event not found'},404)
    if method=='DELETE':c.execute('DELETE FROM events WHERE id=? AND user_id=?',(event_id,user['id']))
    else:
     fields=event_payload(self.read_body())
     c.execute('UPDATE events SET title=?,category=?,starts_at=?,ends_at=?,location=?,notes=?,source=? WHERE id=? AND user_id=?',(*fields,event_id,user['id']))
   return self.send_json({'ok':True})
  if path.startswith('/api/integrations') or path.startswith('/api/suggestions'):
   return integrations.handle(self,method,path,user,conn)
  return self.send_json({'error':'Not found'},404)
 def run_method(self,method):
  path=urlsplit(self.path).path
  try:
   if method=='GET' and re.fullmatch(r'/oauth/(google|microsoft)/callback',path):return integrations.finish(self,path.split('/')[2],conn)
   if path.startswith('/api/'):return self.handle_api(method,path)
   if method!='GET':return self.send_json({'error':'Not found'},404)
   file=ROOT/'index.html' if path in ('/','/index.html') else None
   if not file:return self.send_error(404)
   raw=file.read_bytes();self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(raw)));self.send_header('X-Content-Type-Options','nosniff');self.send_header('Cache-Control','no-store, no-cache, must-revalidate');self.send_header('Pragma','no-cache');self.end_headers();self.wfile.write(raw)
  except ValueError as e:self.send_json({'error':str(e)},400)
  except Exception as e:
   print('Server error:',repr(e));self.send_json({'error':'Unexpected server error'},500)
 def do_GET(self):self.run_method('GET')
 def do_POST(self):self.run_method('POST')
 def do_PUT(self):self.run_method('PUT')
 def do_DELETE(self):self.run_method('DELETE')

def find_free_port(host, preferred_port):
 for port in [preferred_port] + [preferred_port + offset for offset in range(1, 20)]:
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
   sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   try:
    sock.bind((host, port));return port
   except OSError:
    continue
 raise OSError(f'No free port available near {preferred_port}')

if __name__=='__main__':
 init_db();
 port=find_free_port(HOST, PORT)
 if port != PORT:print(f'Port {PORT} is already in use; running at http://{HOST}:{port}',flush=True)
 else:print(f'Deadline Domino running at http://{HOST}:{port}',flush=True)
 ThreadingHTTPServer((HOST,port),Handler).serve_forever()
