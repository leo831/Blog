import os
import jinja2
import webapp2
import cgi
import re
import datetime
import random
import hashlib
import hmac
from string import letters

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'template')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = 'udacityNanodegree'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

#function to create and validate cookies
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    #store cookies
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class BlogContent(db.Model):
    title = db.StringProperty(required = True)
    text = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class MainPage(Handler):
    def render_info(self, title="", text="", last_modified="", error="",username=""):
        content= db.GqlQuery("SELECT * FROM BlogContent ORDER BY created DESC ")

        if self.user:
            username = self.user.name

        self.render("index.html", content = content, username= username)

    #Delete all Content from detabase.
    #def get(self, params)
    #    results = content.fetch(100)
     #   db.delete(results)


    def get(self):
        self.render_info()


##### user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

# Combine random string with SHA256
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    # Create objects before uploading to database
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(), name=name, pw_hash=pw_hash, email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# Input Validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)



class Signup(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user donesn't already exists
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

class NewPost(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            return self.redirect('/')

    def post(self):
        title = self.request.get("title")
        text = self.request.get("text")

        if title and text:
            a = BlogContent(parent = blog_key(), title = title, text = text)
            a.put()

            self.redirect('/post/%s' % str(a.key().id()))

        else:
            error = "Please Enter both inputs"
            self.render("newpost.html",error=error, title=title, text=text)

class PostPage(Handler):
    def get(self, post_id):

        key = db.Key.from_path('BlogContent', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            username = self.user.name

            if not post:
                self.error(404)
                return
            else:
                self.render("post.html", post = post, username=username)
        else:
            self.render("post.html", post = post, username="")

class  DeletePost(Handler):
    def post(self, post_id):
        key = db.Key.from_path('BlogContent', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            post.delete()
            return self.redirect('/')
        else:
            return self.redirect('/')


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/post/([0-9]+)', PostPage),
    ('/post/([0-9]+)/delete', DeletePost),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/newpost', NewPost),], debug=True)