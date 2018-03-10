from . import db
from werkzeug.security import  generate_password_hash,check_password_hash
from flask_login import UserMixin,AnonymousUserMixin
from . import login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    return  User.query.get(int(user_id))

class Permission:
    FOLLOW = 0X01
    COMMENT = 0X02
    WRITE_ARTICLES = 0X04
    MODERATE_COMMENTS = 0X08
    ADMINISTER = 0X80

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
    def insert_roles():
        roles = {
            'User': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE_ARTICLES,True],
            'Moderator': [Permission.FOLLOW, Permission.COMMENT,
                          Permission.WRITE_ARTICLES, Permission.MODERATE_COMMENTS,False],
            'Administrator': [Permission.ADMINISTER,False],
        }
        default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            # role.reset_permissions()
            # for perm in roles[r]:
            #     role.add_permission(perm)
            # role.default = (role.name == default_role)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

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

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
        db.session.commit()

    def __init__(self,**kwargs):
        super(User,self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions = Permission.ADMINISTER).first()
            if self.role is None:
                self.role = Role.query.filter_by(default = True).first()
    def __repr__(self):
        return '<User %r>' % self.username
    def can(self,permissions):
        return self.role is not None and \
               (self.role.permissions & permissions) == permissions
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

class Permission:
    FOLLOW = 0X01
    COMMENT = 0X02
    WRITE_ARTICLES = 0X04
    MODERATE_COMMENTS = 0X08
    ADMINISTER = 0X80