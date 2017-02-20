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
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
# Secret key
secret = 'udacityNanodegree'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# function to create and validate cookies
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # store cookies
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Get cookie for current user
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Delete user cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # Check if user is logged in
    # Check if cookies are the same for user and Hash
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# Class for post entities
class BlogContent(db.Model):
    title = db.StringProperty(required=True)
    text = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    username = db.StringProperty(required=True)
    likes = db.IntegerProperty()
    comments = db.IntegerProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


# section for main page
class MainPage(Handler):
    def render_info(self, title="", text="",
                    last_modified="", error="", username=""):
        # Get latest content for post
        content = db.GqlQuery("SELECT*FROM BlogContent ORDER BY created DESC")

        # get current user
        if self.user:
            username = self.user.name

        self.render("index.html", content=content, username=username)

    # Delete all Content from detabase
    # def get(self, params):
    # results = content.fetch(100)
    # db.delete(results)

    def get(self):
        self.render_info()


# user stuff
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


def users_key(group='default'):
    return db.Key.from_path('users', group)


# class for user entities
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
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(), name=name,
                    pw_hash=pw_hash, email=email)

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

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


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

        params = dict(username=self.username,
                      email=self.email)

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
        # make sure the user donesn't already exists
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


# Section for login
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
            self.render('login.html', error=msg)


# Handler for logout and clear cookie
class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')


# Handler for creating post
class NewPost(Handler):
    def get(self):
        if self.user:
            username = self.user.name
            self.render("newpost.html", username=username)
        else:
            return self.redirect('/')

    def post(self):
        if not self.user:
            return self.redirect('/login')

        # retrieve values from input form
        title = self.request.get("title")
        text = self.request.get("text")
        username = self.user.name

        # check if the there is content from post
        if title and text and self.user:
            a = BlogContent(parent=blog_key(), title=title,
                            text=text, username=username)
            a.put()
            self.redirect('/post/%s' % str(a.key().id()))
        else:
            error = "Please Enter both inputs"
            self.render("newpost.html", error=error, title=title, text=text)


# Handler for editing a post
class EditPost(Handler):
    def get(self, post_id):
        key = db.Key.from_path('BlogContent', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user.name == post.username:
            username = self.user.name
            if not post:
                self.error(404)
                return
            else:
                self.render("editpost.html", post=post, username=username)
        else:
            return self.redirect('/post/%s' % str(post.key().id()))

    def post(self, post_id):
        key = db.Key.from_path('BlogContent', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            title = self.request.get("title")
            text = self.request.get("text")
            username = self.user.name

            if title and text and self.user:
                if post.username == self.user.name:
                    post.title = title
                    post.text = text

                    post.put()

                    return self.redirect('/post/%s' % str(post.key().id()))

            else:
                error = "Please Enter both inputs"
                self.render("newpost.html", error=error, title=title, text=text)
        else:
            return self.redirect('/')


# Handler for render posts
class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('BlogContent', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            liked_post = False
            like_id = None

            try:
                # retreive likes
                likes = db.GqlQuery("SELECT * FROM Like WHERE"
                                    " post_id="+post_id)

                # retreive comments
                comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id = "
                                       + post_id +"ORDER BY created DESC")
            except Exception:
                pass

            if self.user:
                for like in likes:
                    if self.user.name == like.username:
                        liked_post = True
                        like_id = like.key().id()
                        break

                username = self.user.name
                self.render("post.html", post=post, username=username,
                            comments=comments, liked_post=liked_post,
                            like_id=like_id)
            else:
                self.render("post.html", post=post, comments=comments)

        else:
            self.error(404)
            return


# Handler for leteting post
class DeletePost(Handler):
    def post(self, post_id):
        key = db.Key.from_path('BlogContent', int(post_id), parent=blog_key())
        post = db.get(key)

        if post and self.user:
            if post.username == self.user.name:
                post.delete()
                return self.redirect('/')
            else:
                return self.redirect('/')
        else:
            return self.redirect('/')


# Class for comment entities
class Comment(db.Model):
    post_id = db.IntegerProperty(required=True)
    username = db.StringProperty(required=True)
    comment = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# Handler for adding comments
class AddComment(Handler):
    def post(self, post_id):

        key = db.Key.from_path('BlogContent', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and post:
            # retrieve input data
            addcomment = self.request.get("addcomment")
            username = self.user.name

            # check if there is content
            if addcomment and self.user:
                c = Comment(parent=blog_key(), comment=addcomment,
                            username=username, post_id=int(post_id))
                c.put()
                # counter for commets
                if post.comments is None:
                    post.comments = 1
                else:
                    post.comments = int(post.comments) + 1
                # Update comments count
                post.put()

                return self.redirect('/post/%s' % str(post.key().id()))

            else:
                return self.redirect('/')


# handler for deleting comments
class DeleteComment(Handler):
    def post(self, post_id):
        key = db.Key.from_path('BlogContent', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            commentId = self.request.get('commentId')
            # Retrieve current comment
            c_key = db.Key.from_path('Comment', int(commentId),
                                     parent=blog_key())
            comment = db.get(c_key)
            if comment:
                if commentId and self.user:
                    if comment.username:
                        comment.delete()

                        post.comments = int(post.comments) - 1
                        post.put()
                        return self.redirect('/post/'+post_id)
                    else:
                        return self.redirect('/post/'+post_id)
            else:
                return self.redirect('/')
        else:
            return self.redirect('/')


# Handler for editing comment
class EditComment(Handler):
    def post(self, post_id):
        key = db.Key.from_path('BlogContent', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            commentId = self.request.get("commentId")
            editcomment = self.request.get("text")
            if editcomment and commentId and self.user:

                key = db.Key.from_path('Comment', int(commentId),
                                       parent=blog_key())
                comment = db.get(key)

                if comment:
                    if comment.username == self.user.name:
                        comment.comment = editcomment
                        comment.put()
                        return self.redirect('/post/%s' % str(post.key().id()))

                else:
                    return self.redirect('/post/%s' % str(post.key().id()))
            else:
                return self.redirect('/')
        else:
            return self.redirect('/')


# class for likes enttities
class Like(db.Model):
    post_id = db.IntegerProperty(required=True)
    username = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# Handler for likepost
class LikePost(Handler):
    def post(self, post_id):
        # get current post
        key = db.Key.from_path('BlogContent', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            likepost = self.request.get("likePost")
            liked_post = False

            # Retrieve all likes belonging to a post
            likes = Like.all().filter('post_id =', int(post_id))

            # check is the user is logged
            if self.user:
                for like in likes:
                    if self.user.name == like.username:
                        liked_post = True
                        like_id = like.key().id
                        break

            if likepost and self.user:
                if post.username != self.user.name and liked_post is False:
                    like = Like(parent=blog_key(), username=self.user.name,
                                post_id=int(post_id))
                    like.put()

                    if post.likes is None:
                        post.likes = 1
                        post.put()
                        return self.redirect('/post/'+post_id)
                    else:
                        post.likes = int(post.likes) + 1
                        post.put()
                        return self.redirect('/post/'+post_id)
                else:
                    return self.redirect('/post/'+post_id)
        else:
            return self.redirect('/')


# Handler for unliking post
class UnlikePost(Handler):
    def post(self, post_id):
        key = db.Key.from_path('BlogContent', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            unlikePost = self.request.get('unlikePost')
            liked_post = False
            # Get all likes from post
            likes = Like.all().filter('post_id =', int(post_id))
            # Check if logged in user has like the post
            if self.user:
                for like in likes:
                    if self.user.name == like.username:
                        liked_post = True
                        like_Id = like.key().id()
                        break

            if unlikePost and self.user and liked_post is True:
                unlike_key = db.Key.from_path('Like', int(unlikePost),
                                              parent=blog_key())
                like = db.get(unlike_key)
                # Delete like and decrease likes counter
                like.delete()
                post.likes = int(post.likes) - 1
                post.put()
                return self.redirect('/post/'+post_id)
            else:
                return self.redirect('/post/'+post_id)
        else:
            return self.redirect('/')

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/post/([0-9]+)', PostPage),
    ('/post/([0-9]+)/delete', DeletePost),
    ('/post/([0-9]+)/edit', EditPost),
    ('/post/([0-9]+)/addComment', AddComment),
    ('/post/([0-9]+)/deleteComment', DeleteComment),
    ('/post/([0-9]+)/editComment', EditComment),
    ('/post/([0-9]+)/likepost', LikePost),
    ('/post/([0-9]+)/unlikePost', UnlikePost),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/newpost', NewPost), ], debug=True)