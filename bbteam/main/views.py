from flask import render_template, flash, request, url_for, redirect

from . import main
from bbteam import login_manager
from flask.ext.login import login_user
from bbteam.models import User
from .forms import MiniLoginForm


@login_manager.user_loader
def load_user(userid):
    return User.query.get(int(userid))


@main.route('/index')
@main.route('/')
def index():
    form = MiniLoginForm()
    if form.validate_on_submit():
        user = User.get_by_username(form.username.data)
        if user is not None and user.check_password(form.password.data):
            login_user(user, form.remember_me.data)
            flash("Logged in successfully as {}.".format(user.username))
            return redirect(request.args.get('next') or url_for('bookmarks.user',
                                                                username=user.username))
        flash('Incorrect username or password.')
    return render_template("index.html", form=form)


@main.app_errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@main.app_errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@main.app_errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@main.app_context_processor
def inject_tags():
    return dict()
