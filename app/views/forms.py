from flask_wtf import FlaskForm
from wtforms import StringField,TextField,PasswordField,SubmitField, validators,HiddenField
from wtforms.validators import DataRequired
try:
    from urllib.parse import urlparse
except ImportError:
     from urlparse import urlparse, urljoin
from flask import request, url_for, redirect


class LoginForm(FlaskForm):
     email = TextField('Email')
     password = PasswordField('Password')
     submit = SubmitField("login")

class SignupForm(FlaskForm):
    email = TextField('Email', [validators.Length(min=4, max=100)])
    pin = TextField('pin' , [validators.Length(min=4, max=32)])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField("Create Wallet")
    confirmed=False


class SendCoinsForm(FlaskForm):
    ammount = TextField('ammount')
    address = TextField('address')
    submit = SubmitField("login")

class TransactionForm(FlaskForm):
    ammount = TextField('ammount')
    address = TextField('address')
    fee_per_kb = HiddenField() #the fee per kb
    password = PasswordField('password')
