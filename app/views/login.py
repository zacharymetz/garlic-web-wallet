from flask import request, g, Blueprint, render_template, url_for, redirect, make_response, session
from app.views.forms import SignupForm, LoginForm
from passlib.hash import sha256_crypt
from lib.addressgen.genaddress import new_grlc_wallet

import boto3


login = Blueprint('login', __name__)

#use dynamo table for backend for savings
client = boto3.resource('dynamodb')
table = client.Table('WalletAppDB')






#the route function tells the app which URL to bind to the function
@login.route("/login/",methods = ['GET', 'POST'])
def wallet_login(): # route is login
    form = LoginForm(request.form)
    error = None
    current_user = get_user()
    if current_user != False:


        return redirect(url_for('wallet.balance'))
    #just return the home page
    if request.method == "POST":
        print("logging in")
        response = table.get_item(Key={'email': form.email.data})
        print(response)
        if 'Item' in response.keys():
            #check password
            print("checking password")
            if sha256_crypt.verify(form.password.data,response['Item']['password']):
                session["account"] = form.email.data
                return redirect(url_for('wallet.balance'))
        error = "Username and passowrd do not match"

    return render_template("login/login.html",form=form,error=error,current_user=current_user)


@login.route("/logout/")
def wallet_logout():
    if get_user(): # if there is a User
        session.pop('account', None) #remove the session

    return redirect(url_for('login.wallet_login'))

@login.route("/signup/",methods = ['GET', 'POST'])
def signup_wapper():
    form = SignupForm(request.form)
    error = None
    current_user = get_user()
    if current_user != False:
        return redirect(url_for('wallet.balance'))

    if request.method == "POST":
        print(form.data.keys())
        if form.password.data == form.confirm.data and form.email.data != "" :
            print("form_validated")
            response = table.get_item(Key={'email': 'test_objec'})
            if 'item' not in response.keys(): #if the account does not exists
                # since there is not an account associated with it
                new_account = {
                'email' : form.email.data,
                'password' : sha256_crypt.encrypt(form.password.data),
                'wallet' : {
                    'GRLC' :{
                        "0": new_grlc_wallet()
                        }
                    }
                }
                table.put_item(Item=new_account)

                # this is how we log someone in
                session['account'] = new_account['email']

                return redirect(url_for('wallet.balance'))

            error = "Account already exists"

        if form.data.pin != "":
            error = error + "<p> Please enter an account PIN. </p>"
        if form.data.password != form.data.confirm:
            error = error + "<p> Please enter a valid email. </p>"

    return render_template("login/signup.html",error=error,form=form,current_user=current_user)

def get_user():
    """
    This mehtod will see if there is a user logged in
    """

    if 'account' in session.keys():
        print("there is an account")
        user = session['account']
        response = table.get_item(Key={'email':user})
        print(response)
        if 'Item' in response.keys():
            return response['Item']
    return False

def is_email(email):
    # split it at the @
    email = email.split('@')
    if len(email) == 2:
        # now we check to see if there is one period in the 2nd
        if email[1].count('.') == 1:
            return True

    return False
