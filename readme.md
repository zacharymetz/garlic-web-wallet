# Garlic Coin Web Wallet

to get working use the following commands

Before running make sure you have python3, pip, git and virtual environment installed
```
>> sudo apt-get update
>> sudo apt-get install python3 python-pip git
>> sudo pip install virtualenv
```

```
>> virtualenv -p python3 venv
>> source venv/bin/activate
```

Now we need to install all of the modules the app uses from requirements.txt
```
>> pip install --upgrade -r requirements.txt
```

Finally You can run the app
```
>> FLASK_APP=run.py flask run
```
