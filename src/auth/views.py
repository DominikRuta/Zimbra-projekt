#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
reload(sys)  # Reload does the trick!
sys.setdefaultencoding('UTF8')

from flask import (Blueprint, escape, flash, render_template,
                   redirect, request, url_for)
from flask_login import current_user, login_required, login_user, logout_user

from .forms import ResetPasswordForm, EmailForm, LoginForm,NewUserForm, EditUserForm, DomainForm,\
    NewAliasForm, ChangePasswordForm, DistListForm
from ..data.database import db
from ..data.models import User, UserPasswordToken
from ..data.util import generate_random_token
from ..decorators import reset_token_required
from ..emails import send_activation, send_password_reset
from ..extensions import login_manager
from ..data.zimbraadmin import zm
import json

blueprint = Blueprint('auth', __name__)


@blueprint.route('/activate', methods=['GET'])
def activate():
    " Activation link for email verification "
    userid = request.args.get('userid')
    activate_token = request.args.get('activate_token')

    user = db.session.query(User).get(int(userid)) if userid else None
    if user and user.is_verified():
        flash("Your account is already verified.", 'info')
    elif user and user.activate_token == activate_token:
        user.update(verified=True)
        flash("Thank you for verifying your email. Your account is now activated", 'info')
        return redirect(url_for('public.index'))
    else:
        flash("Invalid userid/token combination", 'warning')

    return redirect(url_for('public.index'))

@blueprint.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = EmailForm()
    if form.validate_on_submit():
        user = User.find_by_email(form.email.data)
        if user:
            reset_value = UserPasswordToken.get_or_create_token(user.id).value
            send_password_reset(user, reset_value)
            flash("Passowrd reset instructions have been sent to {}. Please check your inbox".format(user.email),
                  'info')
            return redirect(url_for("public.index"))
        else:
            flash("We couldn't find an account with that email. Please try again", 'warning')
    return render_template("auth/forgot_password.tmpl", form=form)

@login_manager.user_loader
def load_user(userid):  # pylint: disable=W0612
    "Register callback for loading users from session"
    return db.session.query(User).get(int(userid))

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = "postmaster@" + form.email.data
        if zm.getTokenUser(user=email,password=form.password.data) is not None:

            user=User.find_by_email(email)
            if not user:
                # Create the user. Try and use their name returned by Google,
                # but if it is not set, split the email address at the @.

                nickname = email.split('@')[0]
                user=User(username=nickname, email=email,password='sdjfsdhgfsjdgf')
                db.session.add(user)
                db.session.commit()
                user=User.find_by_email(form.email.data)
            zm.getToken()
            login_user(user, form.remember_me.data)
            #flash("Log in was successful", "info")
            return redirect(request.args.get('next') or url_for('auth.listuserzimbra'))
        else:
            flash("Špatná kombinace hesla/domény", "danger")
    return render_template("auth/login.tmpl", form=form)

@blueprint.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    flash("Úspěšně odhlášen", "info")
    return redirect(url_for('auth.login'))

@login_required
@blueprint.route('/resend_activation_email', methods=['GET'])
def resend_activation_email():
    if current_user.is_verified():
        flash("This account has already been activated.", 'warning')
    else:
        current_user.update(activate_token=generate_random_token())
        send_activation(current_user)
        flash('Activation email sent! Please check your inbox', 'info')

    return redirect(url_for('public.index'))

@blueprint.route('/reset_password', methods=['GET', 'POST'])
@reset_token_required
def reset_password(userid, user_token):
    user = db.session.query(User).get(userid)
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.update(password=form.password.data)
        user_token.update(used=True)
        flash("Password updated! Please log in to your account", "info")
        return redirect(url_for('public.index'))
    return render_template("auth/reset_password.tmpl", form=form)

######Sprava domen#####

#pridani domeny
@login_required
@blueprint.route('/zimbraadddomain', methods=['GET', 'POST'])
def adddomianzimbra():
    if current_user.email.split("@")[1] == "sspu-opava.local":
        form = DomainForm()
        if form.validate_on_submit():
            if zm.createDomain(name=form.domainname.data ):
                zm.createAccount(name="postmaster@"+form.domainname.data,
                             password=form.domainname.data.split(".")[0]+"123",
                             quota=1000,
                             displayname=form.domainname.data,
                             status="active")
                flash("Doména " + form.domainname.data +" byla úspěšně vytvořena", "info")
                return redirect(url_for('public.index'))
        return render_template("auth/zimbranewdomain.tmpl", form=form)
    else:
        return redirect(url_for('auth.listuserzimbra'))

#seznam domen
@login_required
@blueprint.route('/zimbralistdomains', methods=['GET', 'POST'])
def listdomainszimbra():
    if current_user.email.split("@")[1] == "sspu-opava.local":
        r = zm.getAllDomain()
        print r
        return render_template("auth/zimbralistdomians.tmpl", data=r)
    else:
        return redirect(url_for('auth.listuserzimbra'))

#smazani domeny
@login_required
@blueprint.route('/zimbradeletedomain/<id>', methods=['GET', 'POST'])
def deletedomainzimbra(id):
    if current_user.email.split("@")[1] == "sspu-opava.local":
        a = zm.getAllAccount()
        d = zm.getDomain(id=id)
        d = d['GetDomainResponse']['domain']['name']
        print d
        for i in a:
            if i[1].split("@")[1] == d:
                print i[1].split("@")[1]
                zm.deleteAccount(id=i[0])
        r = zm.deleteDomain(id=id)
        if(r):
            flash("Doména " + d +" byla smazána", "info")
        return redirect(url_for('auth.listdomainszimbra'))
    else:
        return redirect(url_for('auth.listuserzimbra'))


#####Sprava uzivatelu######

#pridani uzivatele
@login_required
@blueprint.route('/zimbraadduser', methods=['GET', 'POST'])
def adduserzimbra():
    form = NewUserForm()
    if form.validate_on_submit():
        if zm.createAccount(name=form.email.data+"@"+current_user.email.split("@")[1],
                             password=form.password.data,
                             quota=1000,
                             displayname=form.displayname.data,
                             status="active"):
            flash("Účet " + form.email.data+"@"+current_user.email.split("@")[1] +" byl úspěšně vytvořen", "info")
            return redirect(url_for('public.index'))
    return render_template("auth/zimbraaccountadd.tmpl", form=form)

#smazani uzivatele
@login_required
@blueprint.route('/zimbradeleteuser/<id>', methods=['GET', 'POST'])
def deleteuserzimbra(id):
    name=zm.getAccount(id=id)
    name=name['GetAccountResponse']['account']['name']
    r = zm.deleteAccount(id=id)
    if(r):
        flash("Účet " + name + " byl úspěšně smazán.", "info")
    return redirect(url_for('auth.listuserzimbra'))

#seznam uzivatelu
@login_required
@blueprint.route('/zimbralistusers', methods=['GET', 'POST'])
def listuserzimbra():
   # print current_user.email
    r = zm.getAllAccount()
    if not current_user.email.split("@")[1] == "sspu-opava.local":
        q = zm.getQuotaUsage(domain=current_user.email.split("@")[1])
    else:
        q = zm.getQuotaUsage(allServers=1)
    return render_template("auth/zimbralistaccounts.tmpl", data=r,q=q['GetQuotaUsageResponse']['account'])
#    return render_template("auth/zimbralistusers.tmpl", form=form)

#uprava uzivatele
@login_required
@blueprint.route('/zimbraedituser/<id>', methods=['GET', 'POST'])
def edituserzimbra(id):
    form = EditUserForm()
    r = zm.getAccount(id=id)
    for i in r['GetAccountResponse']['account']['a']:
        if i['n'] == "displayName":
            displayname = i['_content']
    if form.validate_on_submit():
        if zm.modifyAccount(id=id, displayname=form.displayname.data):
            for i in r['GetAccountResponse']['account']['a']:
                if i['n'] == "displayName":
                    print  i['_content']
            flash("Jméno bylo úspěšně změněno na: "+displayname,"info")
            return redirect(url_for('public.index'))
    return render_template("auth/zimbraeditaccount.tmpl", displayName=displayname, form=form, id=id)

#zmena hesla
@login_required
@blueprint.route('/zimbrachangepassword/<id>', methods=['GET', 'POST'])
def changepasswordzimbra(id):
    form = ChangePasswordForm()
    r = zm.getAccount(id=id)
    name=r['GetAccountResponse']['account']['name'].split("@")[0]
    if form.validate_on_submit():
        if zm.setPassword(id=id,password=form.password.data):
            flash("Heslo bylo úspěšně změněno","info")
            return redirect(url_for('auth.edituserzimbra', id=id))
    return render_template("auth/zimbrachangepassword.tmpl", name=name, form=form, id=id)

#pridani aliasu
@login_required
@blueprint.route('/zimbranewalias/<id>', methods=['GET', 'POST'])
def newaliaszimbra(id):
    form = NewAliasForm()
    r = zm.getAccount(id=id)
    for i in r['GetAccountResponse']['account']['a']:
        if i['n'] == "displayName":
            displayname = i['_content']
    r = r['GetAccountResponse']['account']['name']

    if form.validate_on_submit():
        if zm.addAccountAlias(id=id, alias=form.alias.data+"@"+r.split("@")[1]):
            flash("Nový alias " + form.alias.data+"@"+r.split("@")[1] +" uživatele " + r + " byl úspěšně vytvořen", "info")
            return redirect(url_for('auth.listaliaszimbra',id=id))
    return render_template("auth/zimbranewalias.tmpl", form=form,displayName= displayname)

#odstraneni aliasu
@login_required
@blueprint.route('/zimbraremovealias/<id>/<alias>', methods=['GET', 'POST'])
def removealiaszimbra(id,alias):
    r = zm.getAccount(id=id)
    if zm.removeAccountAlias(id=id, alias=alias):
        flash("Alias " + alias + " uživatele " + r['GetAccountResponse']['account']['name'] + " byl úspěšně smazán", "info")
    return redirect(url_for('auth.listaliaszimbra', id=id))

#seznam aliasu
@login_required
@blueprint.route('/zimbralistaliases/<id>', methods=['GET', 'POST'])
def listaliaszimbra(id):
    r = zm.getAccount(id=id)
    for i in r['GetAccountResponse']['account']['a']:
        if i['n'] == "displayName":
            displayname = i['_content']
    return render_template("auth/zimbralistaliases.tmpl", r=r['GetAccountResponse']['account']['a'], id=id,displayName= displayname)

####Distribution listy#####

#vytvoreni
@login_required
@blueprint.route('/zimbraadddls', methods=['GET', 'POST'])
def adddlzimbra():
        form = DistListForm()
        if form.validate_on_submit():
            if zm.createDistributionList(name=form.distlistname.data + "@" + current_user.email.split("@")[1], dynamic=0):
                flash("Distribuční list " + form.distlistname.data +" byl úspěšně vytvořen", "info")
                return redirect(url_for('auth.listdlszimbra'))
        return render_template("auth/zimbranewdls.tmpl", form=form)

@login_required
@blueprint.route('/zimbradeletedl/<id>', methods=['GET', 'POST'])
def deletedlzimbra(id):
        r = zm.getDistributionList(id=id)
        all = zm.getAllDistributionLists(name=current_user.email.split("@")[1])
        if zm.deleteDistributionList(id=id):
            flash("Distribuční list " + r['GetDistributionListResponse']['dl']['name'] +" byl úspěšně smazán", "info")
        return redirect(url_for('auth.listdlszimbra', data = all))


#seznam
@login_required
@blueprint.route('/zimbralistdls', methods=['GET', 'POST'])
def listdlszimbra():
        r = zm.getAllDistributionLists(name=current_user.email.split("@")[1])
        print r
        return render_template("auth/zimbralistdls.tmpl", name=r['GetAllDistributionListsResponse']['dl'][0]['name'],id=r['GetAllDistributionListsResponse']['dl'][1]['id'])