#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
from flask import request
from flask_login import current_user
from src.data.zimbraadmin import zm

reload(sys)  # Reload does the trick!
sys.setdefaultencoding('UTF8')
import re

from flask_wtf import Form
from wtforms.fields import BooleanField, TextField, PasswordField, SelectField
from wtforms.validators import EqualTo, Email, InputRequired, Length

from ..data.models import User
from ..fields import Predicate

def email_is_available(email):
    if not email:
        return True
    return not User.find_by_email(email)

def username_is_available(username):
    if not username:
        return True
    return not User.find_by_username(username)

def safe_characters(s):
    " Only letters (a-z) and  numbers are allowed for usernames and passwords. Based off Google username validator "
    if not s:
        return True
    return re.match(r'^[\w]+$', s) is not None

#Kontrola domen pri vytvareni nove
def check_domains(domainname):
    r = zm.getAllDomain()
    for n in r:
        print n[1]
        if n[1] == domainname:
            return False
    return domainname

def check_dls(distlistname):
        r = zm.getAllDistributionLists(name=current_user.email.split("@")[1])
        if 'dl' in r['GetAllDistributionListsResponse']:
            r = r['GetAllDistributionListsResponse']['dl']
            if type(r) == list:
                data = r
                for n in data:
                    if n['name'].split("@")[0] == distlistname:
                        return False
            else:
                print r['name']
                if r['name'].split("@")[0] == distlistname:
                        return False
        print distlistname
        return distlistname

#Kontrola aliasu pri vytvareni noveho
def check_aliases(alias):
    id=request.path.split("/")[2]
    r = zm.getAccount(id=id)
    for n in r['GetAccountResponse']['account']['a']:
        if n['n'] == "zimbraMailAlias":
            if n['_content'].split("@")[0] == alias:
                return False
    return alias
#Kontrola vsech aliasu pri vytvareni noveho mailu
def check_all_aliases(alias):
    a = zm.getAllAccount()
    for i in a:
        r = zm.getAccount(id=i[0])
        for n in r['GetAccountResponse']['account']['a']:
            if n['n'] == "zimbraMailAlias":
                if n['_content'].split("@")[0] == alias:
                    return False
    return alias
#Kontrola mailu pri vytvareni noveho
def newUser_email(mail):
    user=current_user.email.split("@")[1]
    print user
    r = zm.getAllAccount()
    print r
    for n in r:
            if n[1] == mail + "@" + user:
                return False
    return mail


def safe_characters_domain(s):
    " Only letters (a-z) and  numbers are allowed for usernames and passwords. Based off Google username validator "
    if not s:
        return True
    return re.match(r'^[\w.]+$', s) is not None
def domain_validate(s):
    if not s:
        return True
    return re.match(r'(\.|\/)(([A-Za-z\d]+|[A-Za-z\d][-])+[A-Za-z\d]+){1,63}\.([A-Za-z]{2,3}\.[A-Za-z]{2}|[A-Za-z]{2,6})', s) is not None


class EmailForm(Form):
    email = TextField('Email Address', validators=[
        Email(message="Please enter a valid email address"),
        InputRequired(message="You can't leave this empty")
    ])
class DomainForm(Form):
    email = TextField('Doména', validators=[
        #Predicate(domain_validate, message="Please use domain name"),
        InputRequired(message="Vyplňte prosím toto pole")
    ])
class LoginForm(DomainForm):
    password = PasswordField('Heslo', validators=[
        InputRequired(message="Vyplňte prosím toto pole")
    ])

    remember_me = BooleanField('Zůstat přihlášen')

class ResetPasswordForm(Form):
    password = PasswordField('New password', validators=[
        EqualTo('confirm', message='Passwords must match'),
        Predicate(safe_characters, message="Please use only letters (a-z) and numbers"),
        Length(min=6, max=30, message="Please use between 6 and 30 characters"),
        InputRequired(message="You can't leave this empty")
    ])

    confirm = PasswordField('Repeat password')


class RegistrationForm(Form):
    username = TextField('Choose your username', validators=[
        Predicate(safe_characters, message="Please use only letters (a-z) and numbers"),
        Predicate(username_is_available,
                  message="An account has already been registered with that username. Try another?"),
        Length(min=6, max=30, message="Please use between 6 and 30 characters"),
        InputRequired(message="You can't leave this empty")
    ])

    email = TextField('Your email address', validators=[
        Predicate(email_is_available, message="An account has already been reigstered with that email. Try another?"),
        Email(message="Please enter a valid email address"),
        InputRequired(message="You can't leave this empty")
    ])

    password = PasswordField('Create a password', validators=[
        Predicate(safe_characters, message="Please use only letters (a-z) and numbers"),
        Length(min=6, max=30, message="Please use between 6 and 30 characters"),
        InputRequired(message="You can't leave this empty")
    ])
#Formulář pro nového uživatele
class NewUserForm(Form):
    #Kontroluje pole pro email
    email = TextField('E-mailová adresa', validators=[
        #Funkce ošetří vstupy
        Predicate(safe_characters, message="Použijte pouze číslice a písmena (a-z) bez diaktritiky"),
        Predicate(newUser_email,"Tento mail je již zabraný. Zkuste prosím jiný"),
        Predicate(check_all_aliases,"Tento mail je již zabraný jako alias. Zkuste prosím jiný"),
        #Podmínka, která upozorní na to, že pole musí být vyplněno
        InputRequired(message="Vyplňte prosím toto pole")
    ])
    #Kontroluje pole pro jméno
    displayname = TextField('Jméno uživatele', validators=[
        InputRequired(message="Vyplňte prosím toto pole")
    ])

    domains = SelectField('Zvolte doménu nového uživatele',coerce=int)
    #Kontroluje pole pro heslo
    password = PasswordField('Heslo', validators=[
        Predicate(safe_characters, message="Použijte pouze číslice a písmena (a-z) bez diaktritiky"),
        #Podmínka nastavuje minimální a maximální délku hesla
        Length(min=6, max=30, message="Zvolte prosím heslo obsahující 6-30 znaků"),
        InputRequired(message="Vyplňte prosím toto pole")
    ])

class EditUserForm(Form):
    displayname = TextField('Zvolte název uživatele', validators=[
        #Predicate(email_is_available, message="An account has already been reigstered with that email. Try another?"),
        #Email(message="Please enter a valid email address"),
        #InputRequired(message="You can't leave this empty")
    ])

class ChangePasswordForm(Form):
    password = TextField('Zadejte nové heslo', validators=[
        Length(min=6, max=30, message="Zvolte prosím nové heslo obsahující 6-30 znaků"),
        Predicate(safe_characters, message="Použijte pouze číslice a písmena (a-z) bez diaktritiky"),
        InputRequired(message="Vyplňte prosím toto pole")
    ])

class DelUserForm(Form):
    email = TextField('Email address you want delete.', validators=[
        #Predicate(email_is_available, message="An account has already been reigstered with that email. Try another?"),
        #Email(message="Please enter a valid email address"),
        InputRequired(message="You can't leave this empty")
    ])


class NewAliasForm(Form):
        alias = TextField('Zadejte název nového aliasu', validators=[
        Length(min=3, max=10, message="Zvolte prosím název aliasu obsahující 3-10 znaků"),
        Predicate(safe_characters, message="Použijte pouze číslice a písmena (a-z) bez diaktritiky"),
        Predicate(check_aliases,"Tento alias je již zabraný. Zkuste prosím jiný"),
        Predicate(newUser_email,"Tento alias je již zabraný jako mail. Zkuste prosím jiný"),
        InputRequired(message="Vyplňte prosím toto pole")
    ])

###
class DomainForm(Form):
    domainname = TextField('Zadejte název nové domény', validators=[
        Predicate(safe_characters_domain, message="Použijte pouze číslice a písmena (a-z) bez diaktritiky"),
        Predicate(username_is_available,
                  message="Název domény je již obsazen. Zkuste prosím jiný."),
        Predicate(check_domains,"Tento název domény je již zabraný. Zkuste prosím jiný"),
        Length(min=3, max=30, message="Zvolte prosím název domény obsahující 3-30 znaků"),
        InputRequired(message="Vyplňte prosím toto pole")
    ])
###

class DistListForm(Form):
    distlistname = TextField('Zadejte název nového distribučního listu', validators=[
        Predicate(safe_characters, message="Použijte pouze číslice a písmena (a-z) bez diaktritiky"),
        Predicate(check_dls,message="Tento název je již zabraný. Zkuste prosím jiný"),
        Predicate(check_all_aliases,message="Tento název je již zabraný jako alias. Zkuste prosím jiný"),
        Predicate(newUser_email,"Tento název je již zabraný jako mail. Zkuste prosím jiný"),
        Length(min=3, max=20, message="Zvolte prosím název listu obsahující 3-20 znaků"),
        InputRequired(message="Vyplňte prosím toto pole")
    ])