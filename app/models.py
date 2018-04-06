from . import db
from werkzeug.security import  generate_password_hash,check_password_hash
from flask_login import UserMixin,AnonymousUserMixin
from . import login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app,request,url_for
from datetime import datetime
import hashlib
from markdown import markdown
import bleach
from app.exceptions import ValidationError

@login_manager.user_loader
def load_user(user_id):
    return  User.query.get(int(user_id))


class Permission:
    FOLLOW = 1
    COMMENT = 2
    WRITE_ARTICLES = 4
    MODERATE_COMMENTS = 8
    ADMINISTER = 16


class AnonymousUser(AnonymousUserMixin):
    def can(self,permissions):
        return False


    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean,default=False,index =True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return '<Role %r>' % self.name

    @staticmethod
    def insert_roles(default_role = 'User'):
        roles = {
            'User': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE_ARTICLES],
            'Moderator': [Permission.FOLLOW, Permission.COMMENT,
                          Permission.WRITE_ARTICLES, Permission.MODERATE_COMMENTS],
            'Administrator': [Permission.FOLLOW, Permission.COMMENT,
                          Permission.WRITE_ARTICLES, Permission.MODERATE_COMMENTS,Permission.ADMINISTER],
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permission()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()
    def add_permission(self,perm):
        if not self.has_permission(perm):
            self.permissions += perm
    def remove_permission(self,perm):
        if self.has_permission(perm):
            self.permissions -= perm
    def reset_permission(self):
        self.permissions = 0
    def has_permission(self,perm):
        return self.permissions & perm == perm


class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model,UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64),unique = True,index = True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    name = db.Column(db.String(64))  #  用戶真實姓名
    location = db.Column(db.String(64))  #  用戶的地址
    about_me = db.Column(db.Text())  #  自我介紹
    member_since = db.Column(db.DateTime,default = datetime.utcnow)
    last_seen = db.Column(db.DateTime(),default = datetime.utcnow)  #  最後登錄的時間
    confirmed = db.Column(db.Boolean,default = False)
    avatar_hash = db.Column(db.String(32))
    posts = db.relationship('Post',backref='author',lazy = 'dynamic')
    followed = db.relationship('Follow',
                               foreign_keys=[Follow.followed_id],
                               backref=db.backref('follower',lazy='joined'),
                               lazy='dynamic',cascade='all,delete-orphan'
                               )
    followers = db.relationship('Follow',foreign_keys=[Follow.follower_id],
                              backref =db.backref('followed',lazy='joined'),
                              lazy ='dynamic',
                              cascade ='all,delete-orphan')
    comments = db.relationship('Comment',backref='author',lazy='dynamic')

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
        db.session.commit()

    def __init__(self,**kwargs):
        super(User,self).__init__(**kwargs)
        if self.role is None:
            if self.email in current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(name = 'Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default = True).first()
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = self.gravatar_hash()
        self.follow(self)
    def __repr__(self):
        return '<User %r>' % self.username
    def can(self,permissions):
        return self.role is not None and self.role.has_permission(permissions)
    def is_administrator(self):
        return self.can(Permission.ADMINISTER)
    @property
    def password(self):
        raise AttributeError('password is not readable attribute')
    @password.setter
    def password(self,password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self,password):
        return  check_password_hash(self.password_hash,password)

    def generate_confirmation_token(self,expiration = 3600):
        s = Serializer(current_app.config['SECRET_KEY'],expiration)
        return s.dumps({'confirm':self.id})
    def confirm(self,token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('configm') != self.id:
            return False
        self.confirm = True
        db.session.add(self)
        db.session.commit()
        return True

    def gravatar_hash(self):
        return hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()

    def gravatar(self,size = 100, default = 'identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'https://www.gravatar.com/avtar'
        hash = self.gravatar_hash()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url = url,hash = hash,size= size,default=default,rating=rating
        )

    # create fake user for test
    @staticmethod
    def generate_fake(count = 100):
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py

        seed()
        for i in range(count):
            u = User(email = forgery_py.internet.email_address(),
                     username = forgery_py.internet.user_name(True),
                     password = forgery_py.lorem_ipsum.word(),
                     confirmed = True,
                     name = forgery_py.name.full_name(),
                     location = forgery_py.address.city(),
                     about_me = forgery_py.lorem_ipsum.sentence(),
                     member_since = forgery_py.date.date(True)
                     )
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    def follow(self,user):
        if not self.is_following(user):
            f = Follow(follower=self,followed=user)
            db.session.add(f)
            db.session.commit()

    def unfollow(self,user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    def is_following(self, user):
        return self.followed.filter_by(followed_id=user.id) is not None

    def is_followed_by(self,user):
        return self.followers.filter_by(follower_id=user.id) is not None

    @property
    def followed_posts(self):
        return Post.query.join(Follow,Follow.followed_id == Post.author_id).filter(Follow.follower_id==self.id)
    @staticmethod
    def add_self_follows():
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()


    def to_json(self):
        json_user= {
            'url': url_for('api.get_user',id=self.id),
            'username': self.username,
            'member_since': self.member_since,
            'last_seen': self.last_seen,
            'posts_url': url_for('api.get_user_posts',id=self.id),
            'followed_posts_url': url_for('api.get_user_followed_posts',id=self.id),
            'post_count': self.posts.count()
        }
        return json_user


    def generate_auth_token(self, expriation):
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=expriation)
        return s.dump({'id': self.id})


    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        return User.query.get(data['id'])


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer,primary_key= True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime,index=True,default= datetime.utcnow())
    author_id = db.Column(db.Integer,db.ForeignKey('users.id'))
    body_html = db.Column(db.Text)
    comments = db.relationship('Comment',backref='post',lazy='dynamic')

    @staticmethod
    def generate_fake(count = 100):
        from random import seed,randint
        import forgery_py

        seed()
        user_count = User.query.count()
        for i in range(count):
            u = User.query.offset(randint(0,user_count-1)).first()
            p = Post(body = forgery_py.lorem_ipsum.sentences(randint(1,3)),
                     timestamp = forgery_py.date.date(True),author = u)
            db.session.add(p)
            db.session.commit()

    @staticmethod
    def on_changed_body(target,value,oldvalue,initiator):
        allowd_tags = ['a','abbr','acronym','b','block','code',
                       'em','i','li','ol','pre','strong','ul',
                       'h1','h2','h3','p']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value,output_format='html'),tags=allowd_tags,strip=True
        ))


    def to_json(self):
        json_post = {
            'url': url_for('api.get_post',id=self.id),
            'body': self.body,
            'body_html': self.body_html,
            'timestamp': self.timestamp,
            'author_url': url_for('api.get_user',id = self.author_id),
            'comments_url': url_for('api.get_post_comments',id=self.id),
            'comment_count': self.comments.count()
        }
        return json_post

    @staticmethod
    def from_json(json_post):
        body= json_post.get('body')
        if body is None or body == '':
            raise ValidationError('Post does not have a body')
        return Post(body=body)
db.event.listen(Post.body,'set',Post.on_changed_body)


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer,primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime,index = True,default=datetime.utcnow)
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer,db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer,db.ForeignKey('posts.id'))

    @staticmethod
    def on_changed_body(target,value,oldvalue,initiator):
        allowed_tags = ['a','abbr','acronym','b','code','em','i'
                        'strong']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value,output_format='html'),
            tags = allowed_tags,strip=True
        ))


db.event.listen(Comment.body, 'set', Comment.on_changed_body)