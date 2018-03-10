from flask import render_template,redirect,request,url_for,flash
from flask_login import login_user,login_required,logout_user,current_user
from . import auth
from ..models import User
from .forms import LoginForm,RegistrationForm,PasswordChange,PasswordReset,UsernameChange,EmailChange
from .. import db
from ..email import send_email

@auth.route('/login',methods = ['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user,form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password')
    return render_template('auth/login.html', form = form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('you have been logged out')
    return redirect(url_for('main.index'))

@auth.route('/registter',methods =['GET','POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email = form.email.data,
                    username = form.username.data,
                    password = form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email,'Confirm your Account',
                   'auth/email/confirm',user= user,token = token)
        flash('A confirmation email has sent to you by email')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html',form = form)

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account .Thanks!')
    else:
        flash('The confirmed link is invalid or has expried.')
    return redirect(url_for('main.index'))

@auth.before_app_request
def before_request():
    if current_user.is_authenticated \
        and not current_user.confirmed \
        and request.endpoint[:5] != 'auth.' \
        and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')

@auth.route('confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user,'Confirm Your Account','auth/email/confirm',user = current_user,token = token)
    flash('A new confirmation email has been sent to you by email')
    return redirect(url_for('main.index'))

@auth.route('/change-password',methods = ['POST','GET'])
@login_required
def change_password():
    form = PasswordChange()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.new_password1.data
            db.session.add(current_user)
            db.session.commit()
            flash('your password has changed')
            return  redirect(url_for('main.index'))
    return render_template('auth/Change_page.html',form = form,
                           username = current_user.username,page_name = 'Change Pass Word')

@auth.route('/reset-password',methods = ['POST','GET'])
def reset_password():
    form = PasswordReset()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.user_name.data).first()
        if user is not None:
            if user.email == form.email.data:
                user.password = form.new_password.data
                db.session.add(user)
                db.session.commit()
                flash('your password have change')
                return redirect(url_for('auth.login'))
            else:
                flash('you have not register')
                return redirect(url_for('auth.register'))
    return  render_template('auth/Change_page.html',form = form,page_name = 'Reset Password')

@auth.route('/change_email_request',methods = ['POST','GET'])
@login_required
def change_email_request():
    form = EmailChange()
    if form.validate_on_submit():
        if current_user.username == form.username.data:
            current_user.email = form.new_email.data
            db.session.add(current_user)
            db.session.commit()
            flash('your email has changed')
            return redirect(url_for('main.index'))
    return render_template('auth/Change_page.html', form=form,
                           username=current_user.username, page_name='Change Email')

@auth.route('/change_username_request',methods = ['POST','GET'])
@login_required
def change_username_request():
    form = UsernameChange()
    if form.validate_on_submit():
        if current_user.email == form.email.data:
            current_user.username = form.new_name.data
            db.session.add(current_user)
            db.session.commit()
            flash('your username has changed')
            return redirect(url_for('main.index'))
    return render_template('auth/Change_page.html', form=form,
                           username=current_user.username, page_name='Change Name')

@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
            and request.endpoint[:5] != 'auth.':
            return redirect(url_for('auth.unconfirmed'))
