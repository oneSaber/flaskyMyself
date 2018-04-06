from flask_wtf import FlaskForm as Form
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, SelectField
from wtforms import ValidationError
from wtforms.validators import DataRequired,Length,Email, Regexp
from ..models import Role,User
from flask_pagedown.fields import PageDownField

class PostForm(Form):
    body = PageDownField("What's on your mind?",validators=[DataRequired()])
    submit = SubmitField('Submit')

class NameForm(Form):
    name = StringField('What is your name?',validators=[DataRequired()])
    submit = SubmitField('Submit')

class EditProfileForm(Form):
    name= StringField("Real naem",validators=[DataRequired(),Length(0,64)])
    location = StringField('Location',validators=[DataRequired(),Length(0,64)])
    about_me = TextAreaField('About Me')
    submit = SubmitField('Submit')

class EditProfileAdminForm(Form):
    email = StringField('Email',validators=[DataRequired(),Length(1,61),
                                            Email()])
    username = StringField('Username',validators=[DataRequired(),Length(1,64),
                                                  Regexp('^[A-Za-z][A-Za-z0-9.]*$',0,'Username'
                                                    "must have only letters,numbers,dots or underscores")])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role',coerce=int)
    name = StringField('Real name',validators=[Length(0,64)])
    location = StringField('Location',validators=[Length(0,64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm,self).__init__(*args, **kwargs)
        self.role.choices = [(role.id,role.name) for role in Role.query.order_by(Role.name).all()]
        self.user = user
    def validate_email(self,filed):
        if self.email.data !=self.user.email and User.query.filter_by(email = self.email.data).first():
            raise  ValidationError('Email already registered')
    def validate_username(self,filed):
        if self.username.data !=self.user.username and User.query.filter_by(username = self.username.data).first():
            raise ValidationError('Username already in use')
class PostForm(Form):
    body = TextAreaField("What's on your mind?",validators=[DataRequired()])
    submit = SubmitField('Submit')

class CommentForm(Form):
    body = StringField('',validators=[DataRequired()])
    submit = SubmitField('Submit')