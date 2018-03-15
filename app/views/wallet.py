from flask import request, g, Blueprint, render_template, session, redirect, url_for,jsonify
from app.views.login import get_user
from app.views.forms import SendCoinsForm
import requests,json

wallet = Blueprint('wallet', __name__)

#the route function tells the app which URL to bind to the function
@wallet.route("/wallet/")
def balance():
    current_user = get_user()
    error = None
    if current_user != False:
        #just return the home page
        return render_template("wallet/balance.html",current_user=current_user)
    return redirect(url_for('login.wallet_login'))

@wallet.route("/wallet/history/")
def history():
    current_user= get_user()
    error = None
    if current_user != False:
        #just return the home page
        return render_template("wallet/history.html",current_user=current_user)
    return redirect(url_for('login.wallet_login'))


@wallet.route("/wallet/send/",methods=["GET","POST"])
def send():
    form = SendCoinsForm(request.form)
    current_user= get_user()
    error = None
    if current_user != False:
        if request.method == "POST":
            error = "Your coins have been sent"
            form = SendCoinsForm()

        
        return render_template("wallet/send.html",current_user=current_user,form=form,error=error)

    return redirect(url_for('login.wallet_login'))


"""
Pretty much used to estimate the fee to make sure they can send the transactions
"""
@wallet.route("/wallet/transactiondetails/", methods=["POST"])
def transaction_details():
    transaction_detail = dict()
    current_user = get_user()
    if not current_user:
        return "Error no user logged in "
    # get the balance
    response = str(requests.get("https://garli.co.in/ext/getbalance/"+current_user["wallet"]["GRLC"]["0"]['address']).content)[2:-1]
    print(float(response))
    try:
        balance = float(response)
        ammount = request.form.get('ammount')
        # esitmate the fee
        fee = 0.005 # just a palce holder for now
        print(ammount)
        ammount = float(ammount) + fee
        if ammount <= balance:
            transaction_detail['is_possible'] = "True"
            transaction_detail['remaining'] = ammount - balance
            transaction_detail['ammount'] = ammount
            transaction_detail['fee'] = fee
        else:
            transaction_detail['is_possible'] = "False"
        print(transaction_detail)
        return jsonify(str(transaction_detail))


    except:
        transaction_detail['is_possible'] = "False"
        return jsonify(str(transaction_detail))
