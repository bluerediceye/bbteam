import urllib
import requests
from flask import render_template, flash, redirect, url_for, request, session, jsonify
from flask_login import login_user, logout_user

from . import auth
from bbteam import db
from bbteam.models import User
from .forms import SignUpForm, SignInForm
from bbteam.config import Config

@auth.route("/signin", methods=["GET", "POST"])
def signin():
    form = SignInForm()
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
    form = SignUpForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Welcome, {}! Please login.'.format(user.username))
        return redirect(url_for('auth.signin'))
    return render_template("signup.html", form=form)


@auth.route("/google_signin")
def google_signin():
    token_request_uri = "https://accounts.google.com/o/oauth2/auth"
    response_type = "code"
    client_id = Config.GOOGLE_CLIENT_ID
    redirect_uri = url_for('auth.google_authenticate', _external=True)
    scope = "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"
    state = SignUpForm().generate_csrf_token()
    session['state'] = state
    url = "{token_request_uri}?response_type={response_type}&client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&state={state}".format(
        token_request_uri=token_request_uri,
        response_type=response_type,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=urllib.quote(state)
    )
    return redirect(url, 302)


@auth.route("/google_authenticate")
def google_authenticate():
    if request.args.get('state') == session['state']:
        if 'error' in request.args or 'code' not in request.args:
            return redirect('{signinFailed}'.format(signinFailed=url_for('auth.signin')))

        access_token_uri = 'https://www.googleapis.com/oauth2/v3/token'
        redirect_uri = "http://127.0.0.1:5000/auth/google_authenticate"
        params = urllib.urlencode({
            'code': request.args.get('code'),
            'redirect_uri': redirect_uri,
            'client_id': Config.GOOGLE_CLIENT_ID,
            'client_secret': Config.GOOGLE_CLIENT_SECRET,
            'grant_type': 'authorization_code'
        })
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        resp = requests.post(access_token_uri, data=params, headers=headers)
        resp_data = resp.json()
        resp = requests.get("https://www.googleapis.com/oauth2/v1/userinfo?access_token={accessToken}".format(
            accessToken=resp_data['access_token']))
        # this gets the google profile!!
        google_profile = jsonify(content)
        # log the user in-->
        # HERE YOU LOG THE USER IN, OR ANYTHING ELSE YOU WANT
        # THEN REDIRECT TO PROTECTED PAGE
        return google_profile
