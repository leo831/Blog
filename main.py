import os
import jinja2
import webapp2
import cgi
import re
import datetime
import hashlib

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'template')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = 'udacityNanodegree'

#function to create and validate cookies
def make_secure_val(val):
    return '%s|%s' % (val, htmac.new(secret, val).hexdigest())

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
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    #store cookies
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s|%s; path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

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
    def render_info(self, title="", text="", last_modified="", error=""):
        content= db.GqlQuery("SELECT * FROM BlogContent ORDER BY created DESC ")

        self.render("index.html", content = content)

    #Delete all Content from detabase.
    #def get(self, params)
    #    results = content.fetch(100)
     #   db.delete(results)

    def get(self):
        self.render_info()

class NewPost(Handler):
    def get(self):
        self.render("newpost.html")

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

        if not post:
            self.error(404)
            return
        else:
            self.render("post.html", post = post)

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
    ('/signup', Signup),
    ('/newpost', NewPost),], debug=True)