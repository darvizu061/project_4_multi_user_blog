import os
import re
import random
import hashlib
import hmac
import webapp2
import jinja2
from string import letters
import model_user
import model_post
import model_likepost
import model_comment
from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = '9fj3n48cnoy437653829'


def make_pw_hash(password, username):
    return hashlib.sha256(password + username + secret).hexdigest()


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def error(self):
        self.render('error.html')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and model_user.User.by_id(uid)


class HomePage(Handler):
    def get(self):
        posts = model_post.Post.query()
        self.render('index.html', posts=posts)


class RegisterPage(Handler):
    def get(self):
        self.render('register.html')

    def post(self):
        name = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')

        if valid_username(name):
            if valid_password(password):
                if password == verify:
                    user = model_user.User.by_name(name)
                    if user:
                        if user.user_name == name:
                            error = "Username Already Taken"
                            self.render('register.html', error=error)
                    else:
                        password_hash = make_pw_hash(password, name)
                        user_id = model_user.User.register_user(name,
                                                                password_hash)
                        self.set_secure_cookie('user_id', str(user_id))
                        self.redirect('/account')
                else:
                    error = "Passwords Do Not match."
                    self.render('register.html', error=error)
            else:
                error = "Invalid Password"
                self.render('register.html', error=error)
        else:
            error = "Invalid Username"
            self.render('register.html', error=error)


class AccountPage(Handler):
    def get(self):
        self.render('account.html')


class LoginPage(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        name = self.request.get('username')
        password = self.request.get('password')
        password_hash = make_pw_hash(password, name)
        user = model_user.User.by_name_and_pw(
            name, password_hash)
        if user:
            self.set_secure_cookie('user_id',
                                   str(model_user.User.get_user_id(user)))
            self.redirect('/account')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class LogoutPage(Handler):
    def get(self):
        self.logout()
        self.redirect('/')


class PostPage(Handler):
    def get(self, post_id):
        post = model_post.Post.get_post(int(post_id))
        if not post:
            return self.error()
        comments = model_comment.Comment.by_post_id(post_id)
        like_text = 'Like'
        if self.user:
            user = self.user
            like = model_likepost.LikePost.by_post_and_author(post_id,
                                                              user.user_name)
            if like:
                like_text = 'Liked'
        self.render("viewpost.html",
                    post=post,
                    comments=comments,
                    like=like_text)


class AddPostPage(Handler):
    def get(self):
        if self.user:
            self.render("addpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/')

        user = self.user
        title = self.request.get('title')
        content = self.request.get('content')
        author = user.user_name
        post_id = model_post.Post.add_post(title=title,
                                           content=content,
                                           author=author)
        self.redirect('/post/' + str(post_id))


class EditPostPage(Handler):
    def get(self, post_id):
        post = Post.get_post(int(post_id))
        if not post:
            self.error()
            return
        self.render("addpost.html", post=post)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/')

        user = self.user
        title = self.request.get('title')
        content = self.request.get('content')
        author = user.user_name
        model_post.Post.edit_post(title=title,
                                  content=content,
                                  author=author,
                                  post_id=post_id)
        self.redirect('/post/' + str(post_id))


class DeletePost(Handler):
    def get(self):
        self.redirect('/')

    def post(self):
        if not self.user:
            return self.redirect('/')

        user = self.user
        post_id = self.request.get('postid')
        post = model_post.Post.get_post(post_id)

        if post.post_author == user.user_name:
            success = model_post.Post.delete_post(int(post_id))
            if success:
                self.render('index.html')
                self.redirect('/')
        else:
            self.error(401)
            return


class AddLike(Handler):
    def get(self, post_id):
        if not self.user:
            return self.redirect('/')

        user = self.user
        post = model_post.Post.get_post(post_id)
        if not post:
            return self.redirect('/')
        like = model_likepost.LikePost.by_post_and_author(post_id,
                                                          user.user_name)
        if like:
            model_likepost.LikePost.delete_like(like.key.id())
        else:
            if post.post_author == user.user_name:
                return self.redirect('/')
            else:
                model_likepost.LikePost.add_like(post_id, user.user_name)

        return self.redirect('/post/'+post_id)

        if post_id and content:
            model_comment.Comment.add_comment(post_id=post_id,
                                              text=content,
                                              author=user.user_name)

            return self.redirect('/post/'+post_id)
        else:
            return self.error()


class DeleteLike(Handler):
    def get(self):
        self.redirect('/')

    def post(self):
        if not self.user:
            return self.redirect('/')

        user = self.user
        post_id = self.request.get('postid')
        post = model_post.Post.get_post(post_id)

        if post.post_author == user.user_name:
            success = model_post.Post.delete_post(int(post_id))
            if success:
                self.render('index.html')
                self.redirect('/')
        else:
            self.error(401)
            return


class AddComment(Handler):
    def post(self):
        if not self.user:
            return self.redirect('/')

        user = self.user
        post_id = self.request.get('post_id')
        content = self.request.get('content')
        if post_id and content:
            model_comment.Comment.add_comment(post_id=post_id,
                                              text=content,
                                              author=user.user_name)

            return self.redirect('/post/'+post_id)
        else:
            return self.error()


class EditComment(Handler):
    def post(self):
        if not self.user:
            return self.redirect('/')

        user = self.user
        post_id = self.request.get('post_id')
        content = self.request.get('content')
        if post_id and content:
            model_comment.Comment.add_comment(post_id=post_id,
                                              text=content,
                                              author=user.user_name)
            return self.redirect('/post/'+post_id)
        else:
            return self.error()


class DeleteComment(Handler):
    def get(self):
        self.redirect('/')

    def post(self):
        if not self.user:
            return self.redirect('/')

        user = self.user
        comment_id = self.request.get('comment_id')
        comment = model_comment.Comment.get_comment(comment_id)

        if comment.comment_author == user.user_name:
            success = model_comment.Comment.delete_comment(int(comment_id))
            if success:
                return self.redirect('/')
        else:
            self.error(401)
            return

app = webapp2.WSGIApplication([
    ('/', HomePage),
    ('/register', RegisterPage),
    ('/login', LoginPage),
    ('/logout', LogoutPage),
    ('/account', AccountPage),
    ('/post/([0-9]+)', PostPage),
    ('/newpost', AddPostPage),
    ('/editpost/([0-9]+)', EditPostPage),
    ('/delete', DeletePost),
    ('/addlike/([0-9]+)', AddLike),
    ('/deletelike', DeleteLike),
    ('/addcomment', AddComment),
    ('/editcomment', EditComment),
    ('/deletecomment', DeleteComment),
], debug=True)
