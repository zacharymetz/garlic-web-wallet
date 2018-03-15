from flask import request, g, Blueprint, render_template, redirect, url_for
from app.views.login import get_user

home = Blueprint('home', __name__)

#the route function tells the app which URL to bind to the function

@home.route("/")
def wallet_login_alias():


    current_user = get_user()
    return render_template("home/index.html",current_user=current_user)



@home.route("/about")
def about():
    return render_template("home/about.html",x=True)
