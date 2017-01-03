import os
import jinja2
import webapp2
import cgi
import re

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'template')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

def blog_key(name= 'default'):
        return db.key.from_path('post', name)

class BlogContent(db.Model):


    title = db.StringProperty(required = True)
    text = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

class MainPage(Handler):
    def render_info(self, title="", text="", last_modified="", error=""):
        content= db.GqlQuery("SELECT * FROM BlogContent ORDER BY created DESC ")

        self.render("index.html", content = content)

    def get(self):
        self.render_info()


class NewPost(Handler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        title = self.request.get("title")
        text = self.request.get("text")

        if title and text:
            a = BlogContent(title = title, text = text)
            a.put()

            self.redirect('/post/%s' % str(a.key().id()))

        else:
            error = "Please Enter both inputs"
            self.render("newpost.html",error=error, title=title, text=text)

class PostPage(Handler):
    def get(self, post_id):
        key = db.key.from_path('BlogContent', int(post_id), parent = blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("post.html", content = content)


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/post/([0-9]+)', PostPage),
    ('/newpost', NewPost),], debug=True)