"""
Logic for dashboard related routes
"""
from flask import Blueprint, render_template, redirect, url_for
from flask_login import current_user
from .forms import LogUserForm
from ..data.database import db
from ..data.models import LogUser


blueprint = Blueprint('public', __name__)

@blueprint.route('/', methods=['GET'])
def index():
    if current_user.is_anonymous():
        return redirect(url_for('auth.login'))
    else:
        return redirect(url_for('auth.listuserzimbra'))

@blueprint.route('/loguserinput',methods=['GET', 'POST'])
def InsertLogUser():
    form = LogUserForm()
    if form.validate_on_submit():
        LogUser.create(**form.data)
    return render_template("public/LogUser.tmpl", form=form)

@blueprint.route('/loguserlist',methods=['GET'])
def ListuserLog():
    pole = db.session.query(LogUser).all()
    return render_template("public/listuser.tmpl",data = pole)