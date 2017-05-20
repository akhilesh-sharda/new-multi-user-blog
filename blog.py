import hashlib
from google.appengine.ext import db
import hmac
import jinja2
from string import letters
import re
import webapp2
import os


# Retrive Html from Template folder

template_dir = 'template'
jinja_env = \
    jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                       autoescape=True)

#  encrypting Passwords using this secret

SECRET = "helloworld!!"

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

# check for valid username


def valid_username(username):
    return username and USER_RE.match(username)


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        client_side = jinja_env.get_template(template)
        return client_side.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # show the number of likes on any post

    def liked(self, username, post_key):
        if username:
            user = db.GqlQuery(
                'SELECT * FROM User_db WHERE username = :user',
                user=username)
            user_value = user.get().key().id()
            like = Likes.all()
            like.ancestor(post_key)
            like.filter('user_value = ', user_value)
            like = like.get()
            if like:
                return like
            else:
                return False
        else:
            return False

    def fetch_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

# redirect to welcome page to welcome new users

    def SignIn(self, user):
        self.set_secure_cookie('username', user.username)
        self.redirect('/welcome')
# Set encrypted Cookie on User's browser

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' % (str(name), str(cookie_val)))

# check wheather user is is_user in or not

    def is_user(self):
        client_name = self.fetch_secure_cookie('username')
        if client_name:
            client = User_db.all().filter('username = ', client_name).get()
            if client:
                return client_name
            else:
                return False
        else:
            return False


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

# check for valid email


def valid_email(email):
    return not email or EMAIL_RE.match(email)

# User Database Model


class User_db(db.Model):
    email = db.EmailProperty(required=True)
    username = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    register_Date = db.DateTimeProperty(auto_now_add=True)

# Database


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    post_likes = db.IntegerProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)

# Likes Database Model


class Likes(db.Model):
    user_value = db.IntegerProperty(required=True)

# Comments Database Model


class Comments(db.Model):
    author = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

# get request BlogHandler for publishing main index page


class MainPage(BlogHandler):
    def get(self):
        posts = \
            db.GqlQuery('SELECT * FROM Post ORDER BY created DESC LIMIT 15')
        self.render('front.html', posts=posts, user=self.is_user())


def info(username="", password="", email="", upass=""):
    if username and password and email and upass:
        return False
    else:
        return True


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
    else:
        return False

# create a encrypted value to store in  cookie.


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())


def blog_key(name='default'):
    blog_pass_key = db.Key.from_path('blog', name)
    return blog_pass_key

# get request BlogHandler for publishing main welcome page


class Welcome(BlogHandler):
    def get(self):
        posts = \
            db.GqlQuery('SELECT * FROM Post ORDER BY created DESC LIMIT 15')
        self.render('welcome.html', posts=posts, user=self.is_user())


# create HashCode to encrypt password for  storing it Securely in database.


def hash_password(password):
    hass_pass = hashlib.sha256(password + SECRET).hexdigest()
    return hass_pass


class Like(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post_key_val = db.get(key)
        if not post_key_val:
            self.error(404)
            return
        client = self.is_user()
        if client:
            like = self.liked(client, key)
            if not like:
                client = db.GqlQuery(
                    'SELECT * FROM User_db WHERE username = :client',
                    client=client)
                client = client.get()
                user_value = client.key().id()
                if post_key_val.author == self.is_user():
                    self.redirect('/%s?error=ownPost' % post_id)
                else:
                    new_like = Likes(parent=key, user_value=user_value)
                    new_like.put()
                    post_key_val.post_likes += 1
                    post_key_val.put()
                    self.redirect('/%s' % post_id)
            elif like:
                like.delete()
                post_key_val.post_likes -= 1
                post_key_val.put()
                self.redirect('/%s' % post_id)
        else:
            self.redirect('/%s?error=notLogged' % post_id)


class CreatePost(BlogHandler):
    def get(self):
        if self.is_user():
            self.render('new.html', user=self.is_user())
        else:
            self.redirect('/SignIn')

    def post(self):
        content = self.request.get('content')
        subject = self.request.get('subject')
        if subject and content:
            if self.is_user():
                content = content.replace('\n', '<br>')
                p = Post(parent=blog_key(), subject=subject,
                         content=content, author=self.is_user(),
                         post_likes=0)
                p.put()
                self.redirect('/%s' % str(p.key().id()))
            else:
                self.redirect('/SignIn')
        else:
            self.render('new.html', user=self.is_user(),
                        error="Fields Can't Be Enpty")

# user can delete their post


class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        user = self.is_user()
        if post.author == user:
            if not post:
                self.redirect('/SignIn')
            else:
                self.render('post.html', post=post)
                post.delete()
                self.redirect('/')
        else:
            self.redirect('/%s?error=notPostOwner')


# user can edit there own post

class EditPost(BlogHandler):
    def get(self, post_id):
        client = self.is_user()
        if client and post:
            post_key = db.Key.from_path('Post', int(post_id),
                                        parent=blog_key())
            post = db.get(post_key)
            if not post:
                self.redirect(404)
                return
            if client != post.author:
                self.redirect('/%s?error=notPostOwner' % post_id)
            else:
                self.render('edit.html', user=self.is_user(), post=post)
        else:
            self.redirect('/SignIn')

    def post(self, post_id):
        content = self.request.get('content')
        subject = self.request.get('subject')
        client = self.is_user()
        if subject and content:
            if client:
                post_key = db.Key.from_path(
                    'Post', int(post_id),
                    parent=blog_key())
                post = db.get(post_key)
                if not post:
                    self.error(404)
                    return
                if client != post.author:
                    self.redirect('/%s?error=notPostOwner' % post_id)
                else:
                    post.subject = subject
                    post.content = content
                    content = content.replace('\n', '<br>')
                    post.put()
                    self.redirect('/%s' % post_id)
            else:
                self.redirect('/%s?error=notLogged' % post_key)
        else:
            self.render('new.html', user=self.is_user(),
                        error="Can't Be Enpty")

# user can edit their own comments


class EditComment(BlogHandler):
    def post(self, post_id, comment_id):
        client = self.is_user()
        if client:
            post_key = db.Key.from_path(
                'Post', int(post_id), parent=blog_key())
            post = db.get(post_key)
            if not post:
                self.error(404)
                return
            key = db.Key.from_path(
                'Comments', int(comment_id), parent=post_key)
            comment = db.get(key)
            if comment:
                if client == comment.author:
                    content = self.request.get('comment')
                    if content:
                        comment.content = content
                        comment.put()
                        self.redirect('/%s' % post_id)
                    else:
                        self.redirect('/%s?error=emptyCmnt' % post_id)
                else:
                    self.redirect('/%s?error=notCmntOwner' % post_id)
            else:
                self.redirect('/%S?error=noCmnt' % post_id)

    def get(self, post_id, comment_id):
        client = self.is_user()
        if client:
            post_key = db.Key.from_path(
                'Post', int(post_id), parent=blog_key())
            key = db.Key.from_path(
                'Comments', int(comment_id), parent=post_key)
            post = db.get(post_key)
            comment = db.get(key)
            if comment:
                if not post and comment:
                    self.error(404)
                    return
                if client == comment.author:
                    self.render('editcomment.html', client=client, comment=comment)
                else:
                    self.redirect('/%s?error=notCmntOwner' % post_id)
            else:
                self.redirect('/%s?error=noCmnt')


class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        user = self.is_user()
        if user:
            post_key = db.Key.from_path(
                'Post', int(post_id), parent=blog_key())
            post = db.get(post_key)
            if not post:
                self.error(404)
                return
            key = db.Key.from_path(
                'Comments', int(comment_id), parent=post_key)
            comment = db.get(key)
            if not comment:
                self.error(404)
                return
            if user == comment.author:
                comment.delete()
                self.redirect('/%s' % post_id)
            else:
                self.redirect('/%s?error=notCmntOwner' % post_id)
        else:
            self.redirect('/%s?error="notLogged"' % post_id)


# help user to create there own account
class SignUp(BlogHandler):
    def get(self):
        self.render('signup.html')

    def post(self):
        have_error = False
        upass = self.request.get('check')
        username = self.request.get('username')
        password = self.request.get('password')
        email = self.request.get('email')
        params = dict(username=username,
                      email=email, password=password, upass=upass)

        if info(
                username=username,
                password=password,
                email=email,
                upass=upass):
            params['error'] = 'All fields are required'
            have_error = True

        if User_db.all().filter('email = ', email).get():
            params['error'] = 'Email Already existing'
            have_error = True

        if not valid_username(username):
            params['error'] = "That's not a valid username."
            have_error = True

        if not valid_email(email):
            params['error'] = "That's not a valid email."
            have_error = True

        if not password == upass:
            params['error'] = 'Passwords do not match'
            have_error = True

        if User_db.all().filter('username = ', username).get():
            params['error'] = 'Username Already Taken'
            have_error = True
        if have_error:
            self.render('signup.html', **params)
        else:
            self.render('welcome.html', username=username)
            password = hash_password(password)
            p = User_db(email=email, username=username, password_hash=password)
            p.put()


# disconect user from their account safely


class SignOut(BlogHandler):
    def get(self):
        if self.is_user():
            self.set_secure_cookie('username', '')
            self.redirect('/SignIn')
        else:
            self.redirect('/SignIn')


class Blog(BlogHandler):
    # user can post comments on any post

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        user = self.is_user()
        content = self.request.get('comment')
        if user:
            if content:
                content = content.replace('\n', '<br>')
                comment = Comments(parent=key, author=user,
                                   content=content)
                comment.put()
                self.redirect('/%s' % str(post.key().id()))
            else:
                self.redirect('/%s?error=emptyCmnt'
                              % str(post.key().id()))
        else:
            self.redirect('/%s?error="notLogged"' % str(post.key().id()))

    # get request BlogHandler for publishing view post page

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        comments = Comments.all()
        comments.ancestor(key)
        comments.order('last_modified')
        username = self.is_user()
        like = self.liked(username, key)
        self.render('post.html', post=post, user=username,
                    comments=comments, like=like)


# allow user to open their created account


class SignIn(BlogHandler):
    def get(self):
        self.render('signin.html')

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        params = dict(username=username, password=password)
        if not username and password:
            params['error'] = 'Enter both password and username '
            have_error = True
        else:
            client = User_db.all().filter('username = ', username).get()
            if not client:
                params['error'] = 'User does not exsist !'
                have_error = True
            else:
                password = hash_password(password)
                if client.password_hash != password:
                    params['error'] = 'Password Incorrect !'
                    have_error = True
        if have_error:
            self.render('signin.html', **params)
        else:
            self.SignIn(client)


app = webapp2.WSGIApplication([
    ('/SignOut', SignOut),
    ('/like:(\d+)', Like),
    ('/?', MainPage),
    ('/delete:(\d+)', DeletePost),
    ('/SignUp', SignUp),
    ('/(\d+)', Blog),
    ('/welcome', Welcome),
    ('/edit:(\d+)', EditPost),
    ('/deletecomment:(\d+)/(\d+)', DeleteComment),
    ('/CreatePost', CreatePost),
    ('/editcomment:(\d+)&(\d+)', EditComment),
    ('/SignIn', SignIn),
], debug=True)
