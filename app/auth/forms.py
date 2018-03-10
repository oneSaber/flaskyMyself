from flask_wtf import FlaskForm as Form
from wtforms import StringField,PasswordField,BooleanField,SubmitField
from wtforms.validators import DataRequired,Length,Email,Regexp,EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(Form):
    email = StringField('Email',validators=[DataRequired(),Length(1,64),Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    remember_me = BooleanField('keep me logged in')
    submit = SubmitField('Log in')

class RegistrationForm(Form):
    email = StringField('Email',validators=[DataRequired(),Length(1,64),Email()])
    username = StringField('username',validators=[
        DataRequired(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,
                                            'Username must have only letters, number,dot or underscores')])
    password = PasswordField('password',validators=[DataRequired(),EqualTo('password2',message='Password must match')])
    password2 = PasswordField('Confirm password',validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self,field):
        if User.query.filter_by(email = field.data).first():
            raise  ValidationError('Email already registered')
    def validate_username(self,field):
        if User.query.filter_by(username = field.data).first():
            raise  ValidationError('Username alredy in use')

class PasswordChange(Form):
    old_password = StringField('old password',validators=[DataRequired()])
    new_password1 = StringField('new password',validators= [DataRequired(),EqualTo('new_password2',
                                                                                   message= 'Password must math')])
    new_password2 = StringField('Confirm password',validators=[DataRequired()])
    submit = SubmitField('Change')

class PasswordReset(Form):
     user_name = StringField('your username',validators=[DataRequired()])
     email = StringField('your email',validators=[DataRequired()])
     new_password = StringField('new password',validators=[DataRequired(),EqualTo('new_password2',
                                                                                  message='pasword must math')])
     new_password2 = StringField('Comfirm password',validators=[DataRequired()])
     submit = SubmitField('change')

class UsernameChange(Form):
    email = StringField('your email',validators=[DataRequired()])
    new_name = StringField('enter your new name',validators=[DataRequired()])
    password = StringField('enter password for commit')
    submit = SubmitField('Change')

class EmailChange(Form):
    username = StringField('your name ',validators=[DataRequired()])
    new_email = StringField('your new Email',validators=[DataRequired()])
    password = StringField('enter the password to commit',validators=[DataRequired()])
    submit = SubmitField('Change')