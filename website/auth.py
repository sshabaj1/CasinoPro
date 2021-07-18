from operator import ipow
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User, Event
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from logzero import logger
import logzero
from datetime import datetime

logzero.logfile(datetime.now().strftime('%Y_%m_%d.log'))




auth = Blueprint('auth',__name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                logger.info('Logged in successfully')
                login_user(user, remember=True)
                return redirect(url_for('auth.button_request'))
            else:
                flash('Incorrect password, try again.', category='error') 
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", text = "Testing",user=current_user)



@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))




@auth.route('/my-profile')
@login_required

def my_profile():
    return render_template("profile.html", user=current_user)




@auth.route('/button-request', methods=[ 'POST'])
@login_required
def button_request():
    events = Event.query.all()
    
    if request.method == 'POST':
        user_id = current_user.id
        button_id = request.form.get('ButtonID')
        ip = request.remote_addr
        event = Event.query.filter_by(ip=ip,userid=user_id,button_id=button_id).first()
        if event:
            event.click_count +=1
            db.session.commit()
        else:
            new_event = Event(ip=ip,userid=user_id,button_id=button_id)
            db.session.add(new_event)
            db.session.commit()

        logger.info(current_user.id, button_id, ip)
    return render_template("profile.html", user=current_user, eventList=events)




@auth.route('/button-request')
def table():
    events = Event.query.all()
    return render_template("profile.html", eventList=events)






@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif len(last_name) < 2:
            flash('Last name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, last_name=last_name, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))



            
    return render_template("sign_up.html", user=current_user)