import datetime as dt
from contextlib import contextmanager
import hashlib
import base64
import binascii
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import smtplib
import sqlite3
import ssl
import time
import meals
from email.message import EmailMessage
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).parent
DB = ROOT / 'school.db'
CONFIG = ROOT / 'config.json'
def load_environment():
    path=ROOT/'.env.local'
    allowed={'SMTP_HOST','SMTP_PORT','SMTP_USER','SMTP_PASSWORD','SMTP_FROM','PORT','HOST','COOKIE_SECURE','NEIS_API_KEY'}
    if path.exists():
        for line in path.read_text('utf-8-sig').splitlines():
            if not line.strip() or line.lstrip().startswith('#') or '=' not in line: continue
            key,value=line.split('=',1)
            if key.strip() in allowed: os.environ.setdefault(key.strip(),value.strip().strip('\"').strip("'"))
load_environment()
def config():
    cfg=json.loads(CONFIG.read_text('utf-8')) if CONFIG.exists() else {'domains':['smc.sen.hs.kr'], 'classes':[f'{g}학년 {c}반' for g in range(1,4) for c in range(1,11)]}
    cfg['classes']=[c for c in cfg['classes'] if c not in ['관리자','교사']]
    return cfg
@contextmanager
def connect():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
def init():
    with connect() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,name TEXT,class_name TEXT,password TEXT,role TEXT DEFAULT 'student');
        CREATE TABLE IF NOT EXISTS codes(email TEXT PRIMARY KEY,hash TEXT,expires REAL,attempts INTEGER,sent REAL);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER,expires REAL);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,title TEXT,date TEXT,description TEXT,scope TEXT,class_name TEXT,author INTEGER);
        CREATE TABLE IF NOT EXISTS rates(key TEXT PRIMARY KEY,count INTEGER,expires REAL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,admin INTEGER,action TEXT,created TEXT);''')
        columns={r['name'] for r in db.execute('PRAGMA table_info(users)')}
        if 'username' not in columns: db.execute('ALTER TABLE users ADD COLUMN username TEXT')
        if 'nickname' not in columns: db.execute('ALTER TABLE users ADD COLUMN nickname TEXT')
        if 'school_identity' not in columns:db.execute('ALTER TABLE users ADD COLUMN school_identity TEXT')
        identities={}
        for row in db.execute('SELECT id,email FROM users').fetchall():
            key=school_identity(row['email'])
            if key and key in identities:raise RuntimeError('동일 학교 식별자로 가입된 기존 계정이 있습니다. 관리자 확인 후 계정을 정리해 주세요.')
            if key:identities[key]=row['id']
            db.execute('UPDATE users SET school_identity=? WHERE id=?',(key,row['id']))
        db.execute('CREATE UNIQUE INDEX IF NOT EXISTS users_school_identity ON users(school_identity)')
        db.execute('CREATE UNIQUE INDEX IF NOT EXISTS users_username ON users(username)')
        db.execute('CREATE TABLE IF NOT EXISTS inquiries(id INTEGER PRIMARY KEY,user_id INTEGER,title TEXT,body TEXT,created TEXT,status TEXT)')
        db.execute('CREATE TABLE IF NOT EXISTS inquiry_attachments(id TEXT PRIMARY KEY,inquiry_id INTEGER,name TEXT,mime TEXT,data BLOB)')
        db.execute('CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY,user_id INTEGER,title TEXT,body TEXT,created TEXT,is_read INTEGER DEFAULT 0)')
        if 'email_status' not in {r['name'] for r in db.execute('PRAGMA table_info(notifications)')}:db.execute("ALTER TABLE notifications ADD COLUMN email_status TEXT DEFAULT 'not_sent'")
        if 'email_error' not in {r['name'] for r in db.execute('PRAGMA table_info(notifications)')}:db.execute("ALTER TABLE notifications ADD COLUMN email_error TEXT DEFAULT ''")
        db.execute('CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY,event_id INTEGER,user_id INTEGER,body TEXT,created TEXT)')
        if 'pinned' not in {r['name'] for r in db.execute('PRAGMA table_info(comments)')}:db.execute('ALTER TABLE comments ADD COLUMN pinned INTEGER DEFAULT 0')
        db.execute('CREATE TABLE IF NOT EXISTS comment_likes(comment_id INTEGER,user_id INTEGER,PRIMARY KEY(comment_id,user_id))')
        if 'updated_at' not in {r['name'] for r in db.execute('PRAGMA table_info(comments)')}:db.execute('ALTER TABLE comments ADD COLUMN updated_at TEXT')
        db.execute('CREATE TABLE IF NOT EXISTS reset_codes(user_id INTEGER PRIMARY KEY,email TEXT,hash TEXT,expires REAL,attempts INTEGER,sent REAL)')
        cols={r['name'] for r in db.execute('PRAGMA table_info(inquiries)')}
        if 'reply' not in cols: db.execute("ALTER TABLE inquiries ADD COLUMN reply TEXT DEFAULT ''")
        if 'replied_at' not in cols: db.execute('ALTER TABLE inquiries ADD COLUMN replied_at TEXT')
def password_hash(p):
    salt = secrets.token_hex(16)
    return salt + ':' + hashlib.scrypt(p.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1).hex()
def verify(p, stored):
    salt, digest = stored.split(':')
    return hmac.compare_digest(hashlib.scrypt(p.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1).hex(),digest)
def require(ok, message, status=400):
    if not ok: raise APIError(message,status)
class APIError(Exception):
    def __init__(self,message,status=400): self.message,self.status=message,status
def valid_email(email):
    require(bool(re.fullmatch(r'[A-Za-z0-9.!#$%&\'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+',email)) and email.rsplit('@',1)[-1] in config()['domains'],'허용된 학교 이메일을 입력하세요.')

def school_identity(email):
    local,_,domain=email.strip().lower().partition('@')
    if domain not in ['smc.sen.hs.kr','sonline20.sen.go.kr']:return None
    pattern=r'(\d{2}s\d{3})' if domain=='smc.sen.hs.kr' else r'(\d{2}s\d{3})[a-z]\d+'
    match=re.fullmatch(pattern,local)
    return match.group(1) if match else None

def check_school_identity(db,email,exclude_id=0):
    key=school_identity(email)
    if key:require(not db.execute('SELECT id FROM users WHERE school_identity=? AND id<>?',(key,exclude_id)).fetchone(),'같은 학교 식별자로 가입한 계정이 이미 있습니다. 기존 계정으로 로그인하거나 관리자에게 문의해 주세요.')
    return key
def send_mail(email,subject,body,reply_to=None,attachments=None):
    host = os.getenv('SMTP_HOST')
    require(host,'이메일 서버 설정이 필요합니다. 관리자에게 문의하세요.',503)
    msg = EmailMessage()
    msg['From']=os.getenv('SMTP_FROM',os.getenv('SMTP_USER',''))
    msg['To']=email
    msg['Subject']=subject
    if reply_to: msg['Reply-To']=reply_to
    msg.set_content(body)
    for attachment in attachments or []:
        maintype,subtype=attachment['mime'].split('/')
        msg.add_attachment(attachment['data'],maintype=maintype,subtype=subtype,filename=attachment['name'])
    try:
        port=int(os.getenv('SMTP_PORT','587'))
        cls=smtplib.SMTP_SSL if port==465 else smtplib.SMTP
        with cls(host,port,timeout=15) as smtp:
            if port!=465: smtp.starttls(context=ssl.create_default_context())
            if os.getenv('SMTP_USER'): smtp.login(os.environ['SMTP_USER'],os.environ['SMTP_PASSWORD'])
            refused=smtp.send_message(msg)
            if refused:raise APIError('수신 메일 서버가 이메일을 거절했습니다.',503)
    except smtplib.SMTPAuthenticationError:raise APIError('SMTP 로그인 실패: 발신 계정과 앱 비밀번호를 확인하세요.',503)
    except smtplib.SMTPRecipientsRefused:raise APIError('수신 주소가 거절되었습니다. 이메일 주소와 학교 수신 정책을 확인하세요.',503)
    except smtplib.SMTPDataError as error:raise APIError(f'SMTP 본문 전송 거절 (코드 {error.smtp_code}). 발송 한도를 확인하세요.',503)
    except APIError:raise
    except (OSError,smtplib.SMTPException):raise APIError('SMTP 연결 또는 전송에 실패했습니다. 네트워크와 SMTP 설정을 확인하세요.',503)
def send_code(email,code):
    send_mail(email,'세명 스쿨캘린더 이메일 인증',f'인증 코드: {code}\n10분 이내에 입력하세요. 요청하지 않았다면 무시하세요.')

def inquiry_images(items):
    require(isinstance(items,list) and len(items)<=3,'이미지는 최대 3장까지 첨부할 수 있습니다.')
    images=[]
    for item in items:
        require(isinstance(item,dict) and isinstance(item.get('data'),str),'이미지 데이터를 확인하세요.')
        require(len(item['data'])<=2_800_000,'이미지는 한 장당 2MB 이하여야 합니다.')
        try:data=base64.b64decode(item['data'],validate=True)
        except (ValueError,binascii.Error):raise APIError('이미지 데이터를 확인하세요.')
        require(0<len(data)<=2*1024*1024,'이미지는 한 장당 2MB 이하여야 합니다.')
        mime=None
        if len(data)>=24 and data.startswith(b'\x89PNG\r\n\x1a\n') and data[12:16]==b'IHDR':
            width=int.from_bytes(data[16:20],'big');height=int.from_bytes(data[20:24],'big')
            require(0<width<=10000 and 0<height<=10000 and width*height<=25_000_000,'이미지 해상도가 너무 큽니다.')
            mime='image/png'
        elif data.startswith(b'\xff\xd8\xff') and data.endswith(b'\xff\xd9'):mime='image/jpeg'
        elif data.startswith((b'GIF87a',b'GIF89a')) and len(data)>13:mime='image/gif'
        elif data.startswith(b'RIFF') and data[8:12]==b'WEBP':mime='image/webp'
        require(mime,'PNG, JPEG, GIF, WebP 이미지 파일만 사용할 수 있습니다.')
        extension={'image/png':'png','image/jpeg':'jpg','image/gif':'gif','image/webp':'webp'}[mime]
        images.append({'name':'첨부이미지-'+str(len(images)+1)+'.'+extension,'mime':mime,'data':data})
    return images

def deliver_notifications(db,recipients,title,body):
    jobs=[]
    created=dt.datetime.now(dt.UTC).isoformat()
    for user in recipients:
        cur=db.execute("INSERT INTO notifications(user_id,title,body,created,email_status) VALUES(?,?,?,?, 'pending')",(user['id'],title,body,created))
        jobs.append((cur.lastrowid,user['email']))
    db.commit()
    sent=0;failures=[]
    for notification_id,email in jobs:
        try:
            send_mail(email,'[세명 스쿨캘린더] '+title,body+'\n\n사이트 알림함에서도 확인할 수 있습니다.')
            status='sent';sent+=1;error=''
        except APIError as exc:
            status='failed';error=exc.message;failures.append({'email':email,'reason':error})
        db.execute('UPDATE notifications SET email_status=?,email_error=? WHERE id=?',(status,error,notification_id));db.commit()
    return {'ok':True,'recipients':len(jobs),'email_sent':sent,'email_failed':len(jobs)-sent,'failures':failures}
def identity(b):
    username=b['username'].strip().lower()
    require(bool(re.fullmatch(r'[a-z0-9_]{4,30}',username)),'아이디는 영문 소문자, 숫자, 밑줄로 4~30자여야 합니다.')
    return username,None
def reset_accounts():
    init()
    with connect() as db:
        for table in ['inquiry_attachments','reset_codes','comment_likes','comments','notifications','sessions','codes','rates','audit','inquiries','users']:db.execute(f'DELETE FROM {table}')
        db.execute('UPDATE events SET author=NULL')
        db.execute("INSERT INTO users(email,name,class_name,password,role,username,nickname) VALUES(?,?,?,?,?,?,?)",('semyeong.calendar@gmail.com','관리자',config()['classes'][0],password_hash('admin'),'admin','admin',None))
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def reply(self,data,status=200,cookie=None):
        raw=json.dumps(data,ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Cache-Control','no-store')
        if cookie: self.send_header('Set-Cookie',cookie)
        self.end_headers(); self.wfile.write(raw)
    def user(self,db):
        cookies=SimpleCookie(self.headers.get('Cookie',''))
        token=cookies.get('session')
        return db.execute('SELECT u.* FROM users u JOIN sessions s ON u.id=s.user_id WHERE s.token=? AND s.expires>?',(hashlib.sha256(token.value.encode()).hexdigest() if token else '',time.time())).fetchone()
    def auth(self,db):
        u=self.user(db); require(u is not None,'로그인이 필요합니다.',401); return u
    def admin(self,db,b):
        u=self.auth(db)
        require(u['role']=='admin','관리자 권한이 필요합니다.',403)
        self.rate(db,'admin:'+str(u['id']),10)
        require(verify(b.get('admin_password',''),u['password']),'관리자 비밀번호를 다시 확인하세요.',403)
        db.execute('DELETE FROM rates WHERE key=?',('admin:'+str(u['id']),))
        db.execute('INSERT INTO audit(admin,action,created) VALUES(?,?,?)',(u['id'],self.path,dt.datetime.now(dt.UTC).isoformat()))
        return u
    def rate(self,db,key,limit):
        row=db.execute('SELECT * FROM rates WHERE key=?',(key,)).fetchone()
        count=row['count']+1 if row and row['expires']>time.time() else 1
        expires=row['expires'] if row and row['expires']>time.time() else time.time()+600
        db.execute('INSERT OR REPLACE INTO rates VALUES(?,?,?)',(key,count,expires)); db.commit()
        require(count<=limit,'요청이 너무 많습니다. 10분 후 다시 시도하세요.',429)
    def do_GET(self):
        if urlparse(self.path).path=='/api/inquiry-image':
            try:
                with connect() as db:
                    u=self.auth(db)
                    key=parse_qs(urlparse(self.path).query).get('id',[''])[0]
                    attachment=db.execute('SELECT a.*,i.user_id FROM inquiry_attachments a JOIN inquiries i ON i.id=a.inquiry_id WHERE a.id=?',(key,)).fetchone()
                    require(attachment and (attachment['user_id']==u['id'] or u['role']=='admin'),'이미지를 찾을 수 없습니다.',404)
                    content=attachment['data'];mime=attachment['mime']
                self.send_response(200);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(len(content)));self.send_header('Cache-Control','private, no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'none'; frame-ancestors 'none'");self.end_headers();self.wfile.write(content)
            except APIError as error:self.reply({'error':error.message},error.status)
            return
        if self.path.startswith('/api/'):
            self.api('GET'); return
        name=urlparse(self.path).path
        files={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}
        if name not in files: self.send_error(404); return
        content=(ROOT/'static'/files[name]).read_bytes()
        self.send_response(200)
        self.send_header('Content-Type',{'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}[name])
        self.send_header('Content-Security-Policy',"default-src 'self'; img-src 'self' blob:; style-src 'self'; script-src 'self'; frame-ancestors 'none'")
        self.send_header('X-Content-Type-Options','nosniff')
        self.end_headers(); self.wfile.write(content)
    def do_POST(self): self.api('POST')
    def api(self,method):
        try:
            if method=='POST':
                require(self.headers.get('X-SMC-Request')=='1','잘못된 요청입니다.',403)
                limit=9_000_000 if urlparse(self.path).path=='/api/inquiry' else 65536
                require(0<=int(self.headers.get('Content-Length','0'))<=limit,'요청 크기가 너무 큽니다.')
                b=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))) or b'{}')
            else: b={}
            with connect() as db:
                result,cookie=self.route(db,method,urlparse(self.path).path,b)
            self.reply(result,cookie=cookie)
        except APIError as e: self.reply({'error':e.message},e.status)
        except (ValueError,KeyError,TypeError,sqlite3.IntegrityError): self.reply({'error':'입력 값을 확인하세요. 이미 등록된 이메일일 수도 있습니다.'},400)
        except Exception: self.reply({'error':'서버 처리 중 오류가 발생했습니다.'},500)
    def route(self,db,method,path,b):
        cookie=None
        if method=='GET' and path=='/api/meals':
            query=parse_qs(urlparse(self.path).query)
            date=query.get('month',query.get('date',['']))[0]
            try:return meals.get_meals(date),None
            except ValueError:raise APIError('조회 날짜는 YYYY-MM-DD, 월은 YYYY-MM 형식으로 입력하세요.')
            except meals.MealError as e:raise APIError(str(e),503)
        if method=='GET' and path=='/api/bootstrap':
            u=self.user(db)
            unread=db.execute('SELECT count(*) FROM notifications WHERE user_id=? AND is_read=0',(u['id'],)).fetchone()[0] if u else 0
            return {'user':{k:u[k] for k in ['id','email','name','class_name','role','username']} if u else None,'unread':unread,'capabilities':['bulk_notifications_v2'],**config()},None
        if method=='GET' and path=='/api/notifications':
            u=self.auth(db)
            return {'notifications':[dict(r) for r in db.execute('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC',(u['id'],))]},None
        if method=='GET' and path=='/api/comments':
            viewer=self.auth(db)
            event_id=parse_qs(urlparse(self.path).query).get('event_id',[''])[0]
            require(db.execute('SELECT id FROM events WHERE id=?',(event_id,)).fetchone(),'일정을 찾을 수 없습니다.',404)
            return {'comments':[dict(r) for r in db.execute('SELECT c.*,u.name,(SELECT count(*) FROM comment_likes l WHERE l.comment_id=c.id) AS likes,EXISTS(SELECT 1 FROM comment_likes l WHERE l.comment_id=c.id AND l.user_id=?) AS liked FROM comments c LEFT JOIN users u ON u.id=c.user_id WHERE c.event_id=? ORDER BY c.pinned DESC,c.id',(viewer['id'],event_id))]},None
        if method=='GET' and path=='/api/events':
            q=parse_qs(urlparse(self.path).query); scope=q.get('scope',['school'])[0]
            if scope=='class':
                cl=q.get('class',[''])[0]
                require(cl in config()['classes'],'학급을 선택하세요.')
                rows=db.execute("SELECT * FROM events WHERE scope='school' OR (scope='class' AND class_name=?) ORDER BY date",(cl,)).fetchall()
            else: rows=db.execute("SELECT * FROM events WHERE scope='school' ORDER BY date").fetchall()
            events=[]
            for row in rows:
                event=dict(row)
                best=db.execute('SELECT c.id,c.body,c.pinned,(SELECT count(*) FROM comment_likes l WHERE l.comment_id=c.id) AS likes FROM comments c WHERE event_id=? ORDER BY pinned DESC,likes DESC,c.id ASC LIMIT 1',(row['id'],)).fetchone()
                event['featured_comment']=dict(best) if best and (best['pinned'] or best['likes']>0) else None
                events.append(event)
            return {'events':events},None
        require(method=='POST','존재하지 않는 API입니다.',404)
        if path=='/api/username-check':
            self.rate(db,'username-check:'+self.client_address[0],120)
            username,_=identity(b)
            available=username!='admin' and not db.execute('SELECT id FROM users WHERE username=?',(username,)).fetchone()
            return {'available':bool(available)},None
        elif path=='/api/password/request':
            email=b['email'].strip().lower();valid_email(email)
            username=b['username'].strip().lower()
            self.rate(db,'reset-ip:'+self.client_address[0],10)
            self.rate(db,'reset-email:'+email,5)
            u=db.execute('SELECT id FROM users WHERE username=? AND email=?',(username,email)).fetchone()
            if u:
                old=db.execute('SELECT sent FROM reset_codes WHERE user_id=?',(u['id'],)).fetchone()
                require(not old or time.time()-old['sent']>=60,'재전송은 60초 후 가능합니다.',429)
                code=f'{secrets.randbelow(1000000):06d}'
                send_mail(email,'세명 스쿨캘린더 비밀번호 복구',f'비밀번호 복구 인증 코드: {code}\n10분 이내에 입력하세요. 요청하지 않았다면 무시하세요.')
                db.execute('INSERT OR REPLACE INTO reset_codes VALUES(?,?,?,?,?,?)',(u['id'],email,hashlib.sha256(code.encode()).hexdigest(),time.time()+600,0,time.time()))
            return {'ok':True,'message':'입력한 아이디와 학교 이메일이 일치하면 복구 코드를 발송합니다.'},None
        elif path=='/api/password/reset':
            self.rate(db,'reset-verify:'+self.client_address[0],20)
            email=b['email'].strip().lower();valid_email(email)
            require(8<=len(b['new_password'])<=128,'비밀번호는 8~128자로 입력하세요.')
            require(b['new_password']==b.get('password_confirm'),'비밀번호 확인이 일치하지 않습니다.')
            u=db.execute('SELECT id FROM users WHERE username=? AND email=?',(b['username'].strip().lower(),email)).fetchone()
            row=db.execute('SELECT * FROM reset_codes WHERE user_id=? AND email=?',(u['id'],email)).fetchone() if u else None
            require(row and row['expires']>time.time() and row['attempts']<5,'복구 코드가 만료되었거나 유효하지 않습니다. 다시 요청하세요.')
            db.execute('UPDATE reset_codes SET attempts=attempts+1 WHERE user_id=?',(u['id'],));db.commit()
            require(hmac.compare_digest(row['hash'],hashlib.sha256(str(b['code']).encode()).hexdigest()),'복구 인증 코드가 일치하지 않습니다.')
            db.execute('UPDATE users SET password=? WHERE id=?',(password_hash(b['new_password']),u['id']))
            db.execute('DELETE FROM reset_codes WHERE user_id=?',(u['id'],))
            db.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],))
            cookie='session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'
        elif path=='/api/send-code':
            email=b['email'].strip().lower(); valid_email(email)
            exclude_id=0
            if b.get('user_id'):
                self.admin(db,b)
                target=db.execute('SELECT id FROM users WHERE id=?',(b['user_id'],)).fetchone()
                require(target,'회원을 찾을 수 없습니다.',404);exclude_id=target['id']
            check_school_identity(db,email,exclude_id)
            self.rate(db,'send-ip:'+self.client_address[0],20)
            self.rate(db,'send-email:'+email,5)
            old=db.execute('SELECT * FROM codes WHERE email=?',(email,)).fetchone()
            require(not old or time.time()-old['sent']>=60,'재전송은 60초 후 가능합니다.',429)
            require(not db.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone(),'이미 가입된 이메일입니다.')
            code=f'{secrets.randbelow(1000000):06d}'; send_code(email,code)
            db.execute('INSERT OR REPLACE INTO codes VALUES(?,?,?,?,?)',(email,hashlib.sha256(code.encode()).hexdigest(),time.time()+600,0,time.time()))
        elif path=='/api/register':
            require(b.get('member_type','student')=='student','교사 계정은 관리자에게 문의해 주세요.')
            username,_=identity(b)
            require(username!='admin' and not db.execute('SELECT id FROM users WHERE username=?',(username,)).fetchone(),'이미 사용 중인 아이디입니다.')
            email=b['email'].strip().lower(); valid_email(email)
            school_key=check_school_identity(db,email)
            row=db.execute('SELECT * FROM codes WHERE email=?',(email,)).fetchone()
            require(row and row['expires']>time.time() and row['attempts']<5,'코드가 만료되었거나 시도 횟수를 초과했습니다. 다시 요청하세요.')
            db.execute('UPDATE codes SET attempts=attempts+1 WHERE email=?',(email,)); db.commit()
            require(hmac.compare_digest(row['hash'],hashlib.sha256(str(b['code']).encode()).hexdigest()),'인증 코드가 일치하지 않습니다.')
            require(b['class_name'] in config()['classes'],'학급을 선택하세요.')
            require(8<=len(b['password'])<=128,'비밀번호는 8~128자로 입력하세요.')
            require(b['password']==b.get('password_confirm'),'비밀번호 확인이 일치하지 않습니다.')
            require(1<=len(b['name'].strip())<=30,'이름은 1~30자로 입력하세요.')
            username,nickname=identity(b)
            require(username!='admin','사용할 수 없는 아이디입니다.')
            db.execute('INSERT INTO users(email,name,class_name,password,username,nickname,school_identity) VALUES(?,?,?,?,?,?,?)',(email,b['name'].strip(),b['class_name'],password_hash(b['password']),username,nickname,school_key))
            db.execute('DELETE FROM codes WHERE email=?',(email,))
        elif path=='/api/login':
            username=b['username'].strip().lower(); self.rate(db,'login:'+self.client_address[0]+':'+username,10)
            u=db.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
            require(u and verify(b['password'],u['password']),'아이디 또는 비밀번호가 잘못되었습니다.',401)
            db.execute('DELETE FROM rates WHERE key=?',('login:'+self.client_address[0]+':'+username,))
            token=secrets.token_urlsafe(32)
            db.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),u['id'],time.time()+86400))
            cookie=f'session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400'+ ('; Secure' if os.getenv('COOKIE_SECURE')=='1' else '')
        elif path=='/api/comment/save':
            u=self.auth(db);self.rate(db,'comment:'+str(u['id']),20)
            require(db.execute('SELECT id FROM events WHERE id=?',(b['event_id'],)).fetchone(),'일정을 찾을 수 없습니다.',404)
            body=b['body'].strip();require(1<=len(body)<=1000,'댓글은 1~1000자로 입력하세요.')
            db.execute('INSERT INTO comments(event_id,user_id,body,created) VALUES(?,?,?,?)',(b['event_id'],u['id'],body,dt.datetime.now(dt.UTC).isoformat()))
        elif path in ['/api/comment/like','/api/comment/pin']:
            u=self.auth(db)
            comment=db.execute('SELECT * FROM comments WHERE id=?',(b['id'],)).fetchone();require(comment,'댓글을 찾을 수 없습니다.',404)
            if path.endswith('like'):
                require(type(b.get('liked')) is bool,'좋아요 상태를 확인하세요.')
                if b['liked']:db.execute('INSERT OR IGNORE INTO comment_likes VALUES(?,?)',(comment['id'],u['id']))
                else:db.execute('DELETE FROM comment_likes WHERE comment_id=? AND user_id=?',(comment['id'],u['id']))
            else:
                require(u['role'] in ['admin','teacher'],'고정 권한이 없습니다.',403)
                if u['role']=='admin':self.admin(db,b)
                require(type(b.get('pinned')) is bool,'고정 상태를 확인하세요.')
                if b['pinned']:db.execute('UPDATE comments SET pinned=0 WHERE event_id=?',(comment['event_id'],))
                db.execute('UPDATE comments SET pinned=? WHERE id=?',(int(b['pinned']),comment['id']))
        elif path=='/api/comment/update':
            u=self.auth(db)
            comment=db.execute('SELECT * FROM comments WHERE id=?',(b['id'],)).fetchone()
            require(comment,'댓글을 찾을 수 없습니다.',404)
            require(comment['user_id']==u['id'],'본인이 작성한 댓글만 수정할 수 있습니다.',403)
            body=b['body'].strip();require(1<=len(body)<=1000,'댓글은 1~1000자로 입력하세요.')
            if body!=comment['body']:db.execute('UPDATE comments SET body=?,updated_at=? WHERE id=?',(body,dt.datetime.now(dt.UTC).isoformat(),comment['id']))
        elif path=='/api/comment/delete':
            u=self.auth(db);comment=db.execute('SELECT * FROM comments WHERE id=?',(b['id'],)).fetchone()
            require(comment,'댓글을 찾을 수 없습니다.',404)
            if u['role']=='admin':self.admin(db,b)
            else:require(comment['user_id']==u['id'] or u['role']=='teacher','댓글 삭제 권한이 없습니다.',403)
            db.execute('DELETE FROM comment_likes WHERE comment_id=?',(comment['id'],))
            db.execute('DELETE FROM comments WHERE id=?',(comment['id'],))
        elif path=='/api/profile/password':
            u=self.auth(db)
            self.rate(db,'password:'+str(u['id']),10)
            require(verify(b.get('current_password',''),u['password']),'현재 비밀번호가 일치하지 않습니다.',403)
            require(8<=len(b['new_password'])<=128,'비밀번호는 8~128자로 입력하세요.')
            require(b['new_password']==b.get('password_confirm'),'새 비밀번호 확인이 일치하지 않습니다.')
            db.execute('UPDATE users SET password=? WHERE id=?',(password_hash(b['new_password']),u['id']))
            db.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],))
            db.execute('DELETE FROM reset_codes WHERE user_id=?',(u['id'],))
            db.execute('DELETE FROM rates WHERE key=?',('password:'+str(u['id']),))
            cookie='session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'
        elif path=='/api/notifications/read':
            u=self.auth(db)
            if b.get('id'):db.execute('UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?',(b['id'],u['id']))
            else:db.execute('UPDATE notifications SET is_read=1 WHERE user_id=?',(u['id'],))
        elif path=='/api/inquiry':
            u=self.auth(db);self.rate(db,'inquiry:'+str(u['id']),5)
            title=b['title'].strip();body=b['body'].strip()
            require(1<=len(title)<=100 and 1<=len(body)<=4000,'문의 제목과 내용을 입력하세요. 제목 100자, 내용 4000자 이내입니다.')
            images=inquiry_images(b.get('images',[]))
            created=dt.datetime.now(dt.UTC).isoformat()
            cur=db.execute('INSERT INTO inquiries(user_id,title,body,created,status) VALUES(?,?,?,?,?)',(u['id'],title,body,created,'pending'))
            for image in images:db.execute('INSERT INTO inquiry_attachments VALUES(?,?,?,?,?)',(secrets.token_urlsafe(24),cur.lastrowid,image['name'],image['mime'],image['data']))
            db.commit()
            try:
                send_mail('semyeong.calendar@gmail.com','[스쿨캘린더 문의] '+title,f"아이디: {u['username']}\n실명: {u['name']}\n학급: {u['class_name']}\n이메일: {u['email']}\n\n{body}",u['email'],attachments=images)
            except APIError:
                db.execute("UPDATE inquiries SET status='failed' WHERE id=?",(cur.lastrowid,));db.commit()
                return {'ok':True,'warning':'문의는 관리자 페이지에 접수되었으나 이메일 전송에 실패했습니다.'},None
            db.execute("UPDATE inquiries SET status='sent' WHERE id=?",(cur.lastrowid,))
        elif path=='/api/logout':
            c=SimpleCookie(self.headers.get('Cookie','')); t=c.get('session')
            if t: db.execute('DELETE FROM sessions WHERE token=?',(hashlib.sha256(t.value.encode()).hexdigest(),))
            cookie='session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'
        elif path in ['/api/event/save','/api/event/delete']:
            u=self.auth(db); old=db.execute('SELECT * FROM events WHERE id=?',(b.get('id'),)).fetchone() if b.get('id') else None
            require(not b.get('id') or old,'일정을 찾을 수 없습니다.',404)
            scope=b.get('scope',old['scope'] if old else 'class')
            cl=b.get('class_name',u['class_name'])
            if u['role']=='admin': self.admin(db,b)
            elif u['role']!='teacher':
                require(scope=='class' and cl==u['class_name'],'소속 학급에만 등록할 수 있습니다.',403)
                require(not old or (old['scope']=='class' and old['class_name']==u['class_name'] and old['author']==u['id']),'작성한 일정만 수정·삭제할 수 있습니다.',403)
            if path.endswith('delete'):
                db.execute('DELETE FROM comment_likes WHERE comment_id IN (SELECT id FROM comments WHERE event_id=?)',(b['id'],))
                db.execute('DELETE FROM comments WHERE event_id=?',(b['id'],))
                db.execute('DELETE FROM events WHERE id=?',(b['id'],))
            else:
                require(scope in ['school','class'],'일정 구분을 확인하세요.')
                require(scope=='school' or cl in config()['classes'],'학급을 확인하세요.')
                dt.date.fromisoformat(b['date']); require(1<=len(b['title'].strip())<=100 and len(b.get('description',''))<=2000,'제목 또는 상세 내용 길이를 확인하세요.')
                values=(b['title'].strip(),b['date'],b.get('description',''),scope,cl if scope=='class' else None)
                if old: db.execute('UPDATE events SET title=?,date=?,description=?,scope=?,class_name=? WHERE id=?',(*values,old['id']))
                else: db.execute('INSERT INTO events(title,date,description,scope,class_name,author) VALUES(?,?,?,?,?,?)',(*values,u['id']))
        elif path.startswith('/api/admin/'):
            u=self.admin(db,b)
            if path=='/api/admin/users':
                where=[];args=[]
                if b.get('q'):
                    term='%'+b['q'].strip().replace('!','!!').replace('%','!%').replace('_','!_')+'%'
                    where.append("(name LIKE ? ESCAPE '!' OR username LIKE ? ESCAPE '!' OR email LIKE ? ESCAPE '!')");args.extend([term]*3)
                if b.get('class_name'):where.append('class_name=?');args.append(b['class_name'])
                clause=' WHERE '+' AND '.join(where) if where else ''
                total=db.execute('SELECT count(*) FROM users'+clause,args).fetchone()[0]
                paged='page' in b;page=max(1,int(b.get('page',1)));limit=30
                query='SELECT id,email,name,class_name,role,username FROM users'+clause+' ORDER BY name,id'
                if paged:query+=' LIMIT ? OFFSET ?';args.extend([limit,(page-1)*limit])
                return {'users':[dict(r) for r in db.execute(query,args)],'total':total,'page':page,'pages':max(1,(total+limit-1)//limit)},None
            if path=='/api/admin/inquiries':
                inquiries=[]
                for row in db.execute('SELECT i.*,u.name,u.email,u.class_name FROM inquiries i LEFT JOIN users u ON i.user_id=u.id ORDER BY i.id DESC').fetchall():
                    item=dict(row);item['images']=[dict(r) for r in db.execute('SELECT id,name,mime FROM inquiry_attachments WHERE inquiry_id=?',(row['id'],))];inquiries.append(item)
                return {'inquiries':inquiries},None
            if path=='/api/admin/email-history':
                return {'deliveries':[dict(r) for r in db.execute('SELECT n.id,n.title,n.created,n.email_status,n.email_error,u.name,u.email FROM notifications n JOIN users u ON u.id=n.user_id ORDER BY n.id DESC LIMIT 100')]},None
            if path=='/api/admin/email-retry':
                note=db.execute('SELECT n.*,u.email FROM notifications n JOIN users u ON u.id=n.user_id WHERE n.id=?',(b['id'],)).fetchone()
                require(note,'알림을 찾을 수 없습니다.',404)
                require(note['email_status']!='sent','이미 SMTP 접수된 이메일입니다. 중복 전송하지 않습니다.')
                try:
                    send_mail(note['email'],'[세명 스쿨캘린더] '+note['title'],note['body'])
                    status='sent';error=''
                except APIError as exc:status='failed';error=exc.message
                db.execute('UPDATE notifications SET email_status=?,email_error=? WHERE id=?',(status,error,note['id']))
                return {'ok':True,'email_status':status,'error':error},None
            if path=='/api/admin/reply':
                inquiry=db.execute('SELECT * FROM inquiries WHERE id=?',(b['id'],)).fetchone()
                require(inquiry,'문의를 찾을 수 없습니다.',404)
                body=b['body'].strip();require(1<=len(body)<=4000,'회신은 1~4000자로 입력하세요.')
                created=dt.datetime.now(dt.UTC).isoformat()
                db.execute('UPDATE inquiries SET reply=?,replied_at=? WHERE id=?',(body,created,inquiry['id']))
                recipient=db.execute('SELECT id,email FROM users WHERE id=?',(inquiry['user_id'],)).fetchone()
                require(recipient,'문의 작성자의 계정을 찾을 수 없습니다.',404)
                return deliver_notifications(db,[recipient],'문의 답변: '+inquiry['title'],body),None
            elif path=='/api/admin/notice':
                title=b['title'].strip();body=b['body'].strip()
                require(1<=len(title)<=100 and 1<=len(body)<=4000,'알림 제목과 내용을 확인하세요.')
                created=dt.datetime.now(dt.UTC).isoformat()
                if 'user_ids' in b:
                    require(isinstance(b['user_ids'],list) and 1<=len(b['user_ids'])<=5000,'수신자를 한 명 이상 선택하세요.')
                    ids=list(dict.fromkeys(int(value) for value in b['user_ids']))
                    require(all(value>0 for value in ids),'수신자를 확인하세요.')
                    recipients=[]
                    for offset in range(0,len(ids),500):
                        batch=ids[offset:offset+500]
                        recipients.extend(db.execute('SELECT id,email FROM users WHERE id IN ('+','.join('?' for _ in batch)+')',batch).fetchall())
                    require(len(recipients)==len(ids),'일부 수신 계정이 삭제되었습니다. 선택을 확인하세요.')
                elif b.get('user_id'):
                    recipient=db.execute('SELECT id,email FROM users WHERE id=?',(b['user_id'],)).fetchone()
                    require(recipient,'수신 회원을 찾을 수 없습니다.',404);recipients=[recipient]
                else:recipients=db.execute('SELECT id,email FROM users').fetchall()
                return deliver_notifications(db,recipients,title,body),None
            elif path=='/api/admin/user':
                require(b['class_name'] in config()['classes']+['관리자','교사'] and b['role'] in ['student','teacher','admin'],'학급 또는 권한을 확인하세요.')
                require(1<=len(b['name'].strip())<=30,'이름을 확인하세요.')
                old=db.execute('SELECT * FROM users WHERE id=?',(b['id'],)).fetchone(); require(old,'회원을 찾을 수 없습니다.',404)
                username,nickname=identity(b)
                require(username!='admin' or old['username']=='admin','사용할 수 없는 아이디입니다.')
                require(not(old['role']=='admin' and b['role']!='admin' and db.execute("SELECT count(*) FROM users WHERE role='admin'").fetchone()[0]<=1),'마지막 관리자 권한은 해제할 수 없습니다.')
                email=b['email'].strip().lower()
                school_key=check_school_identity(db,email,old['id'])
                if old['email']!=email:
                    valid_email(email)
                    code=db.execute('SELECT * FROM codes WHERE email=?',(email,)).fetchone()
                    require(code and code['expires']>time.time() and code['attempts']<5,'새 이메일 인증 코드를 먼저 요청하세요.')
                    db.execute('UPDATE codes SET attempts=attempts+1 WHERE email=?',(email,)); db.commit()
                    require(hmac.compare_digest(code['hash'],hashlib.sha256(str(b.get('code','')).encode()).hexdigest()),'새 이메일 인증 코드가 일치하지 않습니다.')
                    db.execute('DELETE FROM codes WHERE email=?',(email,))
                db.execute('UPDATE users SET email=?,name=?,class_name=?,role=?,username=?,nickname=?,school_identity=? WHERE id=?',(email,b['name'].strip(),b['class_name'],b['role'],username,nickname,school_key,b['id']))
                if b.get('password'):
                    require(8<=len(b['password'])<=128,'비밀번호는 8~128자로 입력하세요.')
                    db.execute('UPDATE users SET password=? WHERE id=?',(password_hash(b['password']),b['id']))
                db.execute('DELETE FROM sessions WHERE user_id=?',(b['id'],))
                db.execute('DELETE FROM reset_codes WHERE user_id=?',(b['id'],))
            elif path=='/api/admin/domains':
                domains=list(dict.fromkeys(x.strip().lower() for x in b['domains']))
                require(domains and all(re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*\.[a-z]{2,}',x) for x in domains),'도메인 형식을 확인하세요.')
                cfg=config(); cfg['domains']=domains
                CONFIG.write_text(json.dumps(cfg,ensure_ascii=False,indent=2),'utf-8')
            else: raise APIError('존재하지 않는 API입니다.',404)
        else: raise APIError('존재하지 않는 API입니다.',404)
        return {'ok':True},cookie
if __name__=='__main__':
    init()
    if '--create-admin' in __import__('sys').argv:
        import getpass
        email=input('검증된 관리자 학교 이메일: ').strip().lower(); valid_email(email)
        username=input('관리자 아이디: ').strip().lower()
        identity({'username':username,'nickname':'관리자'})
        pw=getpass.getpass('관리자 비밀번호 (8자 이상): '); require(8<=len(pw)<=128,'비밀번호 길이를 확인하세요.')
        with connect() as db: db.execute("INSERT INTO users(email,name,class_name,password,role,username,nickname) VALUES(?,?,?,?, 'admin',?,?)",(email,'관리자',config()['classes'][0],password_hash(pw),username,None))
        print('관리자 생성 완료')
    else:
        port=int(os.getenv('PORT','8000')); print(f'http://127.0.0.1:{port}',flush=True)
        HTTPServer((os.getenv('HOST','127.0.0.1'),port),Handler).serve_forever()
