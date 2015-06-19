from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user

from . import auth
from bbteam import db
from bbteam.models import User
from .forms import SignUpForm


@auth.route("/signin", methods=["GET", "POST"])
def signin():
    form = SignUpForm()
    if form.validate_on_submit():
        user = User.get_by_username(form.username.data)
        if user is not None and user.check_password(form.password.data):
            login_user(user, form.remember_me.data)
            flash("Logged in successfully as {}.".format(user.username))
            return redirect(url_for('main.index', username=user.username))
        flash('Incorrect username or password.')
    return render_template("signin.html", form=form)

@auth.route("/signout")
def signout():
    logout_user()
    return redirect(url_for('main.index'))


@auth.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password = form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Welcome, {}! Please login.'.format(user.username))
        return redirect(url_for('.login'))
    return render_template("signup.html", form=form)
