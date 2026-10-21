import hashlib
from contextlib import closing
import io
import base64
import json
import re
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import server

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.old_db,self.old_cfg=server.DB,server.CONFIG
        server.DB=Path(self.tmp.name)/'test.sqlite3';server.CONFIG=Path(self.tmp.name)/'config.json'
        server.init();self.mail={}
        self.mock=patch.object(server,'send_code',side_effect=lambda email,code:self.mail.update({email:code}));self.mock.start()
    def tearDown(self):
        self.mock.stop()
        server.DB,server.CONFIG= self.old_db,self.old_cfg
        self.tmp.cleanup()
    def request(self,path,data=None,cookie=None,header=True):
        handler=object.__new__(server.Handler)
        headers={'Content-Type':'application/json'}
        if header:headers['X-SMC-Request']='1'
        if cookie:headers['Cookie']=cookie
        raw=json.dumps(data).encode() if data is not None else b''
        headers['Content-Length']=str(len(raw))
        handler.headers=headers;handler.path='/api/'+path
        handler.client_address=('127.0.0.1',0);handler.rfile=io.BytesIO(raw)
        output=[]
        handler.reply=lambda body,status=200,cookie=None:output.append((status,body,cookie))
        handler.api('POST' if data is not None else 'GET')
        return output[0]
    def student(self,email='a@smc.sen.hs.kr'):
        self.assertEqual(self.request('send-code',{'email':email})[0],200)
        username='user_'+email.split('@')[0]
        self.assertEqual(self.request('register',{'username':username,'nickname':'별명','email':email,'code':self.mail[email],'name':'학생','class_name':'1학년 1반','password':'test-password-123','password_confirm':'test-password-123'})[0],200)
        return self.request('login',{'username':username,'password':'test-password-123'})[2].split(';')[0]
    def admin(self):
        with server.connect() as db:db.execute("INSERT INTO users(email,name,class_name,password,role,username,nickname) VALUES(?,?,?,?,?,?,?)",('admin@smc.sen.hs.kr','관리자','1학년 1반',server.password_hash('admin-password-123'),'admin','admin','관리자'))
        return self.request('login',{'username':'admin','password':'admin-password-123'})[2].split(';')[0]
    def test_public_private_and_class_permissions(self):
        self.assertEqual(self.request('events')[0],200)
        self.assertEqual(self.request('events?scope=class&class=1%ED%95%99%EB%85%84%201%EB%B0%98')[0],200)
        cookie=self.student()
        event={'title':'수행평가','date':'2026-11-10','scope':'class','class_name':'1학년 2반'}
        self.assertEqual(self.request('event/save',event,cookie)[0],403)
        event['class_name']='1학년 1반';self.assertEqual(self.request('event/save',event,cookie)[0],200)
        self.assertEqual(len(self.request('events')[1]['events']),0)
        self.assertEqual(len(self.request('events?scope=class&class=1%ED%95%99%EB%85%84%201%EB%B0%98',cookie=cookie)[1]['events']),1)
        other=self.student('b@smc.sen.hs.kr');event['id']=1
        self.assertEqual(self.request('event/save',event,other)[0],403)
        event['scope']='school';self.assertEqual(self.request('event/save',event,cookie)[0],403)
    def test_code_validation_and_consumption(self):
        self.assertEqual(self.request('send-code',{'email':'x@smc.sen.hs.kr.evil.com'})[0],400)
        email='a@smc.sen.hs.kr';self.request('send-code',{'email':email})
        code=self.mail[email];bad='000000' if code!='000000' else '111111'
        b={'email':email,'code':bad,'name':'학생','class_name':'1학년 1반','password':'test-password-123'}
        for _ in range(5):self.assertEqual(self.request('register',b)[0],400)
        b['code']=code;self.assertEqual(self.request('register',b)[0],400)
        with server.connect() as db:db.execute('UPDATE codes SET attempts=0,expires=?',(time.time()-1,))
        self.assertEqual(self.request('register',b)[0],400)
    def test_admin_every_action_and_domains(self):
        cookie=self.admin();pw={'admin_password':'admin-password-123'}
        self.assertEqual(self.request('admin/users',{},cookie)[0],403)
        self.assertEqual(self.request('admin/users',pw,cookie)[0],200)
        self.assertEqual(self.request('admin/users',{},cookie)[0],403)
        self.assertNotIn('password',self.request('admin/users',pw,cookie)[1]['users'][0])
        self.assertEqual(self.request('admin/domains',{'domains':['smc.sen.hs.kr','new.school.kr'],**pw},cookie)[0],200)
        self.assertEqual(self.request('send-code',{'email':'x@new.school.kr'})[0],200)
        self.assertEqual(self.request('admin/domains',{'domains':['bad']},cookie)[0],403)
        event={'title':'학사일정','date':'2026-11-11','scope':'school',**pw}
        self.assertEqual(self.request('event/save',event,cookie)[0],200)
        self.assertEqual(len(self.request('events')[1]['events']),1)
    def test_csrf_and_session_revocation(self):
        cookie=self.student();admin=self.admin()
        self.assertEqual(self.request('logout',{},cookie,False)[0],403)
        status,body,_=self.request('admin/users',{'admin_password':'admin-password-123'},admin)
        student=next(u for u in body['users'] if u['role']=='student')
        self.assertEqual(self.request('admin/user',{**student,'class_name':'1학년 2반','admin_password':'admin-password-123'},admin)[0],200)
        self.assertIsNone(self.request('bootstrap',cookie=cookie)[1]['user'])
    def test_missing_smtp_does_not_allow_signup(self):
        self.mock.stop()
        with patch.dict(server.os.environ,{'SMTP_HOST':''}):
            self.assertEqual(self.request('send-code',{'email':'a@smc.sen.hs.kr'})[0],503)
        self.mock.start()
    def test_database_portability_and_code_reuse(self):
        cookie=self.student()
        self.request('event/save',{'title':'이전 확인','date':'2026-12-01','scope':'class','class_name':'1학년 1반'},cookie)
        target=Path(self.tmp.name)/'moved';target.mkdir()
        with server.connect() as source:
            with closing(server.sqlite3.connect(target/'school.db')) as destination:source.backup(destination)
        server.DB=target/'school.db'
        self.assertEqual(self.request('bootstrap',cookie=cookie)[1]['user']['name'],'학생')
        self.assertEqual(self.request('login',{'username':'user_a','password':'test-password-123'})[0],200)
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT title FROM events').fetchone()[0],'이전 확인')
            self.assertEqual(db.execute('SELECT count(*) FROM codes').fetchone()[0],0)
        self.assertEqual(self.request('register',{'email':'a@smc.sen.hs.kr','code':self.mail['a@smc.sen.hs.kr'],'name':'재사용','class_name':'1학년 1반','password':'test-password-123'})[0],400)
    def test_admin_email_change_requires_new_email_code(self):
        self.student();admin=self.admin()
        with server.connect() as db:student=dict(db.execute("SELECT id,email,name,class_name,role,username,nickname FROM users WHERE role='student'").fetchone())
        update={**student,'email':'new@smc.sen.hs.kr','admin_password':'admin-password-123'}
        self.assertEqual(self.request('admin/user',update,admin)[0],400)
        self.request('send-code',{'email':update['email']})
        update['code']=self.mail[update['email']]
        self.assertEqual(self.request('admin/user',update,admin)[0],200)
        self.assertEqual(self.request('login',{'username':update['username'],'password':'test-password-123'})[0],200)

    def test_profile_and_id_login(self):
        cookie=self.student()
        self.assertEqual(self.request('login',{'username':'a@smc.sen.hs.kr','password':'test-password-123'})[0],401)
        b={'current_password':'wrong','new_password':'changed-password','password_confirm':'changed-password'}
        self.assertEqual(self.request('profile/password',b,cookie)[0],403)
        b['current_password']='test-password-123';b['password_confirm']='wrong'
        self.assertEqual(self.request('profile/password',b,cookie)[0],400)
        b['password_confirm']=b['new_password']
        self.assertEqual(self.request('profile/password',b,cookie)[0],200)
        self.assertIsNone(self.request('bootstrap',cookie=cookie)[1]['user'])
        self.assertEqual(self.request('login',{'username':'user_a','password':'changed-password'})[0],200)
    def test_inquiries_send_to_admin_and_preserve_failure(self):
        cookie=self.student()
        with patch.object(server,'send_mail') as mail:
            self.assertEqual(self.request('inquiry',{'title':'학급 변경','body':'학급 수정 요청'},cookie)[0],200)
            self.assertEqual(mail.call_args.args[0],'semyeong.calendar@gmail.com')
            self.assertIn('user_a',mail.call_args.args[2])
            self.assertEqual(mail.call_args.args[3],'a@smc.sen.hs.kr')
        with patch.object(server,'send_mail',side_effect=server.APIError('전송 실패',503)):
            self.assertEqual(self.request('inquiry',{'title':'문의','body':'내용'},cookie)[0],200)
        with server.connect() as db:self.assertEqual([r['status'] for r in db.execute('SELECT status FROM inquiries ORDER BY id')],['sent','failed'])
        self.assertEqual(self.request('inquiry',{'title':'문의','body':'내용'})[0],401)
    def test_account_reset_preserves_events(self):
        cookie=self.student()
        self.request('event/save',{'title':'유지','date':'2026-12-01','scope':'class','class_name':'1학년 1반'},cookie)
        server.reset_accounts()
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM users').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0],1)
            self.assertIsNone(db.execute('SELECT author FROM events').fetchone()[0])
        self.assertIsNone(self.request('bootstrap',cookie=cookie)[1]['user'])
        self.assertEqual(self.request('login',{'username':'admin','password':'admin'})[0],200)
    def test_eight_character_password_and_teacher_signup(self):
        email='eight@smc.sen.hs.kr';self.request('send-code',{'email':email})
        b={'username':'eight','nickname':'별명','name':'학생','email':email,'code':self.mail[email],'class_name':'1학년 1반','password':'1234567','password_confirm':'12345678'}
        self.assertEqual(self.request('register',b)[0],400)
        b['password']='12345678';b['member_type']='teacher'
        self.assertEqual(self.request('register',b)[0],400)
        b['member_type']='student';b['class_name']='교사'
        self.assertEqual(self.request('register',b)[0],400)
        b['class_name']='1학년 1반'
        self.assertEqual(self.request('register',b)[0],200)
        self.assertEqual(self.request('login',{'username':'eight','password':'12345678'})[0],200)
    def test_special_classes_admin_only(self):
        cookie=self.student();admin=self.admin()
        self.assertNotIn('교사',self.request('bootstrap')[1]['classes'])
        self.assertEqual(self.request('events?scope=class&class=%EA%B5%90%EC%82%AC')[0],400)
        users=self.request('admin/users',{'admin_password':'admin-password-123'},admin)[1]['users']
        student=next(u for u in users if u['role']=='student')
        self.assertEqual(self.request('admin/user',{**student,'class_name':'교사','role':'teacher','admin_password':'admin-password-123'},admin)[0],200)
    def test_last_admin_cannot_become_teacher(self):
        admin=self.admin()
        u=self.request('admin/users',{'admin_password':'admin-password-123'},admin)[1]['users'][0]
        self.assertEqual(self.request('admin/user',{**u,'role':'teacher','admin_password':'admin-password-123'},admin)[0],400)
        self.assertEqual(self.request('admin/user',{**u,'role':'student','admin_password':'admin-password-123'},admin)[0],400)
    def test_school_identity_across_domains_allows_same_real_name(self):
        cfg=server.config();cfg['domains'].append('sonline20.sen.go.kr');server.CONFIG.write_text(json.dumps(cfg),'utf-8')
        first='24s209@smc.sen.hs.kr';second='24s209h0659@sonline20.sen.go.kr'
        for email in [first,second]:self.assertEqual(self.request('send-code',{'email':email})[0],200)
        base={'name':'동명이인','class_name':'1학년 1반','password':'password123','password_confirm':'password123'}
        self.assertEqual(self.request('register',{**base,'username':'first','email':first,'code':self.mail[first]})[0],200)
        self.assertEqual(self.request('register',{**base,'username':'second','email':second,'code':self.mail[second]})[0],400)
        self.assertEqual(self.request('send-code',{'email':second})[0],400)
        other='24s210h0659@sonline20.sen.go.kr'
        self.assertEqual(self.request('send-code',{'email':other})[0],200)
        self.assertEqual(self.request('register',{**base,'username':'other','email':other,'code':self.mail[other]})[0],200)
        with server.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM users WHERE name='동명이인'").fetchone()[0],2)
            with self.assertRaises(server.sqlite3.IntegrityError):db.execute("INSERT INTO users(email,username,school_identity) VALUES('duplicate@other.kr','duplicate','24s209')")
        self.assertIsNone(server.school_identity('24t209@smc.sen.hs.kr'))
    def test_username_availability_and_comment_edited_flag(self):
        self.assertTrue(self.request('username-check',{'username':'sonline20'})[1]['available'])
        self.assertFalse(self.request('username-check',{'username':'admin'})[1]['available'])
        self.assertEqual(self.request('username-check',{'username':'x'})[0],400)
        user=self.student()
        self.assertFalse(self.request('username-check',{'username':'user_a'})[1]['available'])
        self.request('event/save',{'title':'댓글','date':'2026-12-01','scope':'class','class_name':'1학년 1반'},user)
        self.request('comment/save',{'event_id':1,'body':'원문'},user)
        self.assertIsNone(self.request('comments?event_id=1',cookie=user)[1]['comments'][0]['updated_at'])
        self.request('comment/update',{'id':1,'body':'원문'},user)
        self.assertIsNone(self.request('comments?event_id=1',cookie=user)[1]['comments'][0]['updated_at'])
        self.request('comment/update',{'id':1,'body':'수정'},user)
        self.assertIsNotNone(self.request('comments?event_id=1',cookie=user)[1]['comments'][0]['updated_at'])
    def test_password_recovery_ownership_reuse_and_sessions(self):
        user=self.student()
        b={'username':'user_a','email':'a@smc.sen.hs.kr'}
        with patch.object(server,'send_mail') as mail:
            self.assertEqual(self.request('password/request',b)[0],200)
            code=re.search(r'\d{6}',mail.call_args.args[2]).group()
            self.assertEqual(mail.call_args.args[0],b['email'])
            self.assertEqual(self.request('password/request',b)[0],429)
        reset={**b,'code':code,'new_password':'recovered-123','password_confirm':'recovered-123'}
        self.assertEqual(self.request('password/reset',{**reset,'username':'user_b'})[0],400)
        self.assertEqual(self.request('password/reset',{**reset,'password_confirm':'wrong'})[0],400)
        self.assertEqual(self.request('password/reset',{**reset,'code':'x'})[0],400)
        self.assertEqual(self.request('password/reset',reset)[0],200)
        self.assertIsNone(self.request('bootstrap',cookie=user)[1]['user'])
        self.assertEqual(self.request('login',{'username':'user_a','password':'test-password-123'})[0],401)
        self.assertEqual(self.request('login',{'username':'user_a','password':'recovered-123'})[0],200)
        self.assertEqual(self.request('password/reset',reset)[0],400)
    def test_password_recovery_expiry_limits_and_no_account(self):
        self.student();b={'username':'user_a','email':'a@smc.sen.hs.kr'}
        with patch.object(server,'send_mail') as mail:
            self.assertEqual(self.request('password/request',{**b,'username':'missing'})[0],200)
            mail.assert_not_called()
            self.request('password/request',b)
            code=re.search(r'\d{6}',mail.call_args.args[2]).group()
        reset={**b,'code':code,'new_password':'recovered-123','password_confirm':'recovered-123'}
        with server.connect() as db:db.execute('UPDATE reset_codes SET expires=?',(time.time()-1,))
        self.assertEqual(self.request('password/reset',reset)[0],400)
        with server.connect() as db:db.execute('UPDATE reset_codes SET expires=?,attempts=0',(time.time()+600,))
        for _ in range(5):self.assertEqual(self.request('password/reset',{**reset,'code':'invalid'})[0],400)
        self.assertEqual(self.request('password/reset',reset)[0],400)
        self.assertEqual(self.request('password/request',{**b,'email':'a@example.com'})[0],400)
    def test_comment_update_owner_and_featured_content(self):
        owner=self.student();other=self.student('b@smc.sen.hs.kr');admin=self.admin()
        self.request('event/save',{'title':'댓글 수정','date':'2026-12-01','scope':'school','admin_password':'admin-password-123'},admin)
        self.request('comment/save',{'event_id':1,'body':'수정 전'},owner)
        self.request('comment/like',{'id':1,'liked':True},other)
        self.assertEqual(self.request('comment/update',{'id':1,'body':'수정 후'})[0],401)
        self.assertEqual(self.request('comment/update',{'id':1,'body':'수정 후'},other)[0],403)
        self.assertEqual(self.request('comment/update',{'id':1,'body':'수정 후'},admin)[0],403)
        self.assertEqual(self.request('comment/update',{'id':1,'body':'   '},owner)[0],400)
        self.assertEqual(self.request('comment/update',{'id':1,'body':'x'*1001},owner)[0],400)
        self.assertEqual(self.request('comment/update',{'id':1,'body':'수정 후'},owner)[0],200)
        featured=self.request('events')[1]['events'][0]['featured_comment']
        self.assertEqual(featured['body'],'수정 후');self.assertEqual(featured['likes'],1)
    def test_comment_likes_featured_and_pin_priority(self):
        user=self.student();other=self.student('b@smc.sen.hs.kr');admin=self.admin()
        self.request('event/save',{'title':'대표 댓글','date':'2026-12-01','scope':'school','admin_password':'admin-password-123'},admin)
        self.request('comment/save',{'event_id':1,'body':'첫 댓글'},user)
        self.request('comment/save',{'event_id':1,'body':'두 번째'},other)
        self.assertIsNone(self.request('events')[1]['events'][0]['featured_comment'])
        self.assertEqual(self.request('comment/like',{'id':1,'liked':True})[0],401)
        for _ in range(2):self.assertEqual(self.request('comment/like',{'id':1,'liked':True},user)[0],200)
        self.assertEqual(self.request('events')[1]['events'][0]['featured_comment']['likes'],1)
        self.assertEqual(self.request('comment/pin',{'id':2,'pinned':True},user)[0],403)
        self.assertEqual(self.request('comment/pin',{'id':2,'pinned':True},admin)[0],403)
        p={'admin_password':'admin-password-123'}
        self.assertEqual(self.request('comment/pin',{'id':2,'pinned':True,**p},admin)[0],200)
        featured=self.request('events')[1]['events'][0]['featured_comment']
        self.assertEqual(featured['id'],2);self.assertEqual(featured['pinned'],1)
        self.request('comment/pin',{'id':1,'pinned':True,**p},admin)
        with server.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM comments WHERE pinned=1').fetchone()[0],1)
        self.request('comment/pin',{'id':1,'pinned':False,**p},admin)
        self.assertEqual(self.request('events')[1]['events'][0]['featured_comment']['id'],1)
        self.request('comment/like',{'id':1,'liked':False},user)
        self.assertIsNone(self.request('events')[1]['events'][0]['featured_comment'])
    def test_comments_auth_ownership_and_event_deletion(self):
        user=self.student();other=self.student('b@smc.sen.hs.kr')
        self.request('event/save',{'title':'일정','date':'2026-12-01','scope':'class','class_name':'1학년 1반'},user)
        self.assertEqual(self.request('comment/save',{'event_id':1,'body':'댓글'})[0],401)
        self.assertEqual(self.request('comment/save',{'event_id':1,'body':'   '},user)[0],400)
        self.assertEqual(self.request('comment/save',{'event_id':99,'body':'댓글'},user)[0],404)
        self.assertEqual(self.request('comment/save',{'event_id':1,'body':'<script>text</script>'},user)[0],200)
        comments=self.request('comments?event_id=1',cookie=user)[1]['comments']
        self.assertEqual(comments[0]['name'],'학생')
        self.assertEqual(self.request('comment/delete',{'id':1},other)[0],403)
        self.assertEqual(self.request('comment/delete',{'id':1},user)[0],200)
        self.request('comment/save',{'event_id':1,'body':'다음 댓글'},user)
        self.request('event/delete',{'id':1},user)
        with server.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM comments').fetchone()[0],0)
    def test_teacher_can_manage_all_events_but_not_members(self):
        cookie=self.student()
        with server.connect() as db:db.execute("UPDATE users SET role='teacher',class_name='교사'")
        event={'title':'교사 일정','date':'2026-12-01','scope':'school'}
        self.assertEqual(self.request('event/save',event,cookie)[0],200)
        event.update(id=1,scope='class',class_name='2학년 2반')
        self.assertEqual(self.request('event/save',event,cookie)[0],200)
        self.assertEqual(self.request('event/delete',{'id':1},cookie)[0],200)
        self.assertEqual(self.request('admin/users',{'admin_password':'test-password-123'},cookie)[0],403)
    @patch.object(server,'send_mail')
    def test_reply_notifications_are_private(self,mail):
        cookie=self.student();other=self.student('b@smc.sen.hs.kr');admin=self.admin()
        with patch.object(server,'send_mail'):
            self.request('inquiry',{'title':'질문','body':'내용'},cookie)
        p={'admin_password':'admin-password-123'}
        self.assertEqual(self.request('admin/inquiries',p,admin)[0],200)
        self.assertEqual(self.request('admin/reply',{'id':1,'body':'답변',**p},admin)[0],200)
        self.assertEqual(len(self.request('notifications',cookie=cookie)[1]['notifications']),1)
        self.assertEqual(len(self.request('notifications',cookie=other)[1]['notifications']),0)
        self.request('notifications/read',{'id':1},other)
        self.assertEqual(self.request('bootstrap',cookie=cookie)[1]['unread'],1)
        self.request('notifications/read',{'id':1},cookie)
        self.assertEqual(self.request('bootstrap',cookie=cookie)[1]['unread'],0)
        self.assertEqual(self.request('admin/notice',{'title':'공지','body':'전체 알림',**p},admin)[0],200)
        self.assertEqual(len(self.request('notifications',cookie=other)[1]['notifications']),1)
        self.assertEqual(self.request('notifications')[0],401)
    def test_personal_notification_email_and_failure(self):
        student=self.student();other=self.student('b@smc.sen.hs.kr');admin=self.admin()
        with server.connect() as db:target=db.execute("SELECT id FROM users WHERE username='user_a'").fetchone()['id']
        b={'title':'개인 알림','body':'안내','user_id':target,'admin_password':'admin-password-123'}
        self.assertEqual(self.request('admin/notice',b,student)[0],403)
        with patch.object(server,'send_mail') as mail:
            status,result,_=self.request('admin/notice',b,admin)
            self.assertEqual(status,200);self.assertEqual(result['email_sent'],1)
            self.assertEqual(mail.call_args.args[0],'a@smc.sen.hs.kr')
            self.assertEqual(len(self.request('notifications',cookie=other)[1]['notifications']),0)
        with patch.object(server,'send_mail',side_effect=server.APIError('발송 실패',503)):
            status,result,_=self.request('admin/notice',b,admin)
            self.assertEqual(result['email_failed'],1)
        notes=self.request('notifications',cookie=student)[1]['notifications']
        self.assertEqual(len(notes),2);self.assertEqual(notes[0]['email_status'],'failed')
    def test_batch_notification_dedup_and_directory_search(self):
        a=self.student();b=self.student('b@smc.sen.hs.kr');admin=self.admin()
        with server.connect() as db:ids=[r['id'] for r in db.execute("SELECT id FROM users WHERE role='student'")]
        p={'admin_password':'admin-password-123'}
        result=self.request('admin/users',{'q':'user_a','class_name':'1학년 1반','page':1,**p},admin)[1]
        self.assertEqual(result['total'],1);self.assertEqual(result['users'][0]['username'],'user_a')
        self.assertEqual(self.request('admin/users',{'q':'user_%','page':1,**p},admin)[1]['total'],0)
        with patch.object(server,'send_mail') as mail:
            result=self.request('admin/notice',{'title':'단체','body':'내용','user_ids':[ids[0],ids[1],ids[0]],**p},admin)[1]
            self.assertEqual(result['recipients'],2);self.assertEqual(mail.call_count,2)
        self.assertEqual(len(self.request('notifications',cookie=a)[1]['notifications']),1)
        self.assertEqual(len(self.request('notifications',cookie=b)[1]['notifications']),1)
        self.assertEqual(len(self.request('notifications',cookie=admin)[1]['notifications']),0)
        self.assertEqual(self.request('admin/notice',{'title':'단체','body':'내용','user_ids':[],**p},admin)[0],400)
        self.assertEqual(self.request('admin/notice',{'title':'단체','body':'내용','user_ids':[ids[0],99999],**p},admin)[0],400)
    def test_email_retry_keeps_single_site_notification(self):
        student=self.student();admin=self.admin();p={'admin_password':'admin-password-123'}
        with server.connect() as db:
            target=db.execute("SELECT id FROM users WHERE username='user_a'").fetchone()['id']
            db.execute("INSERT INTO notifications(user_id,title,body,created,email_status) VALUES(?,?,?,?,?)",(target,'이전 알림','내용','2026-10-21','not_sent'))
        self.assertEqual(self.request('admin/email-history',p,student)[0],403)
        self.assertEqual(self.request('admin/email-history',p,admin)[1]['deliveries'][0]['email_status'],'not_sent')
        with patch.object(server,'send_mail') as mail:
            self.assertEqual(self.request('admin/email-retry',{'id':1,**p},admin)[1]['email_status'],'sent')
            self.assertEqual(mail.call_count,1)
            self.assertEqual(self.request('admin/email-retry',{'id':1,**p},admin)[0],400)
            self.assertEqual(mail.call_count,1)
        self.assertEqual(len(self.request('notifications',cookie=student)[1]['notifications']),1)
    def test_inquiry_image_storage_email_and_access(self):
        owner=self.student();other=self.student('b@smc.sen.hs.kr');admin=self.admin()
        png='iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jzQAAAABJRU5ErkJggg=='
        with patch.object(server,'send_mail') as mail:
            self.assertEqual(self.request('inquiry',{'title':'이미지 문의','body':'확인해 주세요','images':[{'data':png}]},owner)[0],200)
            self.assertEqual(mail.call_args.kwargs['attachments'][0]['mime'],'image/png')
        inquiry=self.request('admin/inquiries',{'admin_password':'admin-password-123'},admin)[1]['inquiries'][0]
        self.assertEqual(len(inquiry['images']),1)
        image_id=inquiry['images'][0]['id']
        def image_request(cookie):
            h=object.__new__(server.Handler);h.path='/api/inquiry-image?id='+image_id;h.headers={'Cookie':cookie or ''};h.wfile=io.BytesIO();result=[]
            h.send_response=lambda status:result.append(status);h.send_header=lambda *args:None;h.end_headers=lambda:None;h.reply=lambda body,status=200:result.append(status)
            h.do_GET();return result[0],h.wfile.getvalue()
        self.assertEqual(image_request(None)[0],401)
        self.assertEqual(image_request(other)[0],404)
        self.assertEqual(image_request(owner),(200,base64.b64decode(png)))
        self.assertEqual(image_request(admin)[0],200)
        with patch.object(server,'send_mail',side_effect=server.APIError('失敗',503)):
            self.assertEqual(self.request('inquiry',{'title':'이미지 보존','body':'내용','images':[{'data':png}]},owner)[0],200)
        with server.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM inquiry_attachments').fetchone()[0],2)
    def test_invalid_inquiry_images_rejected(self):
        user=self.student()
        for images in [[{'data':base64.b64encode(b'<svg onload=evil()>').decode()}],[{'data':'%%%'}],[{'data':'a'*2_800_001}],['bad'],[{}]*4]:
            self.assertEqual(self.request('inquiry',{'title':'문의','body':'내용','images':images},user)[0],400)

if __name__=='__main__':unittest.main()

