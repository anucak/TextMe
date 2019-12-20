from flask import Flask, render_template, request, make_response, redirect, url_for
from models import User, Message, db
from sqlalchemy import desc
import datetime
import uuid
import hashlib
import requests
import os


app = Flask(__name__)
db.create_all()


@app.route("/", methods=["GET"])
def index():
    session_token = request.cookies.get("session_token")

    user = db.query(User).filter_by(session_token=session_token, user_deleted=False).first()

    if not user:
        user = None

    return render_template("index.html", user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    elif request.method == "POST":
        username = request.form.get("user-name")
        email = request.form.get("user-email")
        password = request.form.get("user-password")
        password_repeat = request.form.get("user-repeat-password")
        info = request.form.get("user-about")

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        hashed_password_repeat = hashlib.sha256(password_repeat.encode()).hexdigest()

        # see if the user with the same email already exists
        user_email = db.query(User).filter_by(email=email).first()

        if not user_email:
            # check if there is a user with the same username
            user_username = db.query(User).filter_by(username=username).first()

            if not user_username:
                # check if the passwords match
                if hashed_password == hashed_password_repeat:

                    # create a User object
                    user = User(username=username, email=email, password=hashed_password, info=info)

                    # save the user object into a database
                    db.add(user)
                    db.commit()

                    # create a random session token for this user
                    session_token = str(uuid.uuid4())

                    # save token in DB
                    user.session_token = session_token
                    db.add(user)
                    db.commit()

                    # save user's session token into a cookie
                    response = make_response(redirect(url_for('index')))
                    response.set_cookie("session_token", session_token, httponly=True, samesite="Strict")

                    return response
                else:
                    alert1 = "Passwords don't match"
                    return render_template("register.html", alert1=alert1)
            else:
                alert2 = "That username is already taken"
                return render_template("register.html", alert2=alert2)
        else:
            alert3 = "User with the same email address already exists"
            return render_template("register.html", alert3=alert3)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    elif request.method == "POST":
        email = request.form.get("login-email")
        password = request.form.get("login-password")

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # check if there is a user with that email
        user = db.query(User).filter_by(email=email).first()

        if not user:
            alert1 = "User with that email address doesn't exist"
            return render_template("login.html", alert1=alert1)

        if hashed_password == user.password:
            # create a random session token for this user
            session_token = str(uuid.uuid4())

            # save token in DB
            user.session_token = session_token
            db.add(user)
            db.commit()

            # save user's session token into a cookie
            response = make_response(render_template("index.html", user=user))
            response.set_cookie("session_token", session_token, httponly=True, samesite="Strict")
            return response
        else:
            alert2 = "Wrong password, try again!"
            return render_template("login.html", alert2=alert2)


@app.route("/new", methods=["GET", "POST"])
def new_message():
    session_token = request.cookies.get("session_token")

    user = db.query(User).filter_by(session_token=session_token, user_deleted=False).first()

    if request.method == "GET":
        if user:
            # get username from url when needed
            user_reply = request.args.get("user_reply", None)
            return render_template("new_message.html", user=user, user_reply=user_reply)
        else:
            return redirect(url_for("index"))

    elif request.method == "POST":
        # get recipient username
        receiver_username = request.form.get("receiver-username")

        # check if that username exists
        receiver = db.query(User).filter_by(username=receiver_username, user_deleted=False).first()

        if not receiver:
            alert = "That username doesn't exist!"
            return render_template("new_message.html", user=user, alert=alert)

        # save the id of a recipient in order to display details about the recipient
        receiver_id = receiver.id

        # get message
        message = request.form.get("text")

        # add sender information
        sender_username = user.username
        sender_id = user.id

        # add date and time
        x = datetime.datetime.now()
        date = "{0}/{1}/{2}".format(x.strftime("%d"), x.strftime("%m"), x.strftime("%y"))
        time = "{0}:{1}".format(x.strftime("%H"), x.strftime("%M"))

        # add and save all data in Message model
        message = Message(sender_username=sender_username, sender_id=sender_id, receiver_username=receiver_username,
                          receiver_id=receiver_id, message=message, datetime=x, date=date, time=time)

        db.add(message)
        db.commit()

        return redirect(url_for("sent_messages"))


@app.route("/sent", methods=["GET"])
def sent_messages():
    session_token = request.cookies.get("session_token")

    user = db.query(User).filter_by(session_token=session_token, user_deleted=False).first()

    if user:
        # get all messages in descending order by datetime
        messages = db.query(Message).filter_by(sender_username=user.username).order_by(desc(Message.datetime)).all()

        return render_template("sent_messages.html", user=user, messages=messages)
    else:
        return redirect(url_for("index"))


@app.route("/received", methods=["GET", "POST"])
def received_messages():
    session_token = request.cookies.get("session_token")

    user = db.query(User).filter_by(session_token=session_token, user_deleted=False).first()

    if request.method == "GET":
        if user:
            receiver = user.username

            # get all messages sent to this user in descending order by datetime
            messages = db.query(Message).filter_by(receiver_username=receiver).order_by(desc(Message.datetime)).all()

            return render_template("inbox.html", user=user, messages=messages)
        else:
            return redirect(url_for("index"))

    elif request.method == "POST":
        # send recipient username to new message
        user_reply = request.form.get("user-reply")

        # check if recipient still exists
        user_reply_deleted_false = db.query(User).filter_by(username=user_reply, user_deleted=False).first()

        if user_reply_deleted_false:
            return redirect(url_for("new_message", user_reply=user_reply))
        else:
            return render_template("profile_deleted.html", user=user)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    session_token = request.cookies.get("session_token")

    user = db.query(User).filter_by(session_token=session_token, user_deleted=False).first()

    if request.method == "GET":
        if user:
            # count the number of sent and received messages
            messages_sent = db.query(Message).filter_by(sender_username=user.username).count()
            messages_received = db.query(Message).filter_by(receiver_username=user.username).count()

            return render_template("profile.html", user=user, messages_sent=messages_sent, messages_received=messages_received)
        else:
            return redirect(url_for("index"))

    elif request.method == "POST":
        # false delete user
        user.user_deleted = True
        db.add(user)
        db.commit()

        return redirect(url_for("index"))


@app.route("/profile/edit", methods=["GET", "POST"])
def edit_profile():
    session_token = request.cookies.get("session_token")

    user = db.query(User).filter_by(session_token=session_token, user_deleted=False).first()

    if request.method == "GET":
        if user:
            return render_template("edit_profile.html", user=user)
        else:
            return redirect(url_for("index"))

    elif request.method == "POST":
        new_username = request.form.get("new-username")
        new_email = request.form.get("new-email")
        current_password = request.form.get("current-password")
        new_password = request.form.get("new-password")
        info = request.form.get("info")

        # change password
        if current_password and new_password:
            current_password_hashed = hashlib.sha256(current_password.encode()).hexdigest()
            new_password_hashed = hashlib.sha256(new_password.encode()).hexdigest()

            if current_password_hashed == user.password:
                user.password = new_password_hashed
            else:
                alert1 = "Wrong password"
                return render_template("edit_profile.html", user=user, alert1=alert1)

        # change username
        if new_username:
            if new_username != user.username:
                # check if username already exists
                username = db.query(User).filter_by(username=new_username).first()

                if username:
                    alert2 = "That username already exists"
                    return render_template("edit_profile.html", user=user, alert2=alert2)
                else:
                    # change username in sent messages
                    messages_sent = db.query(Message).filter_by(sender_username=user.username).all()

                    for message_sent in messages_sent:
                        message_sent.sender_username = new_username
                        db.add(message_sent)
                        db.commit()

                    # change username in received messages
                    messages_received = db.query(Message).filter_by(receiver_username=user.username).all()

                    for message_received in messages_received:
                        message_received.receiver_username = new_username
                        db.add(message_received)
                        db.commit()

                    user.username = new_username

        # change email
        if new_email:
            if new_email != user.email:
                # check if email already exists
                email = db.query(User).filter_by(email=new_email).first()

                if email:
                    alert3 = "User with that email address already exists"
                    return render_template("edit_profile.html", user=user, alert3=alert3)
                else:
                    user.email = new_email

        # change info
        if info:
            user.info = info

        db.add(user)
        db.commit()

        return redirect(url_for("profile"))


@app.route("/logout", methods=["GET"])
def logout():
    session_token = request.cookies.get("session_token")

    user = db.query(User).filter_by(session_token=session_token, user_deleted=False).first()

    if user:
        response = make_response(render_template("index.html"))
        response.set_cookie("session_token", expires=0)

        return response
    else:
        return redirect(url_for("index"))


@app.route("/users", methods=["GET"])
def users():
    session_token = request.cookies.get("session_token")

    user = db.query(User).filter_by(session_token=session_token, user_deleted=False).first()

    if user:
        users = db.query(User).filter_by(user_deleted=False).all()

        return render_template("users.html", user=user, users=users)
    else:
        return redirect(url_for("index"))


@app.route("/users/<user_id>", methods=["GET", "POST"])
def user_details(user_id):
    session_token = request.cookies.get("session_token")

    user = db.query(User).filter_by(session_token=session_token, user_deleted=False).first()

    if request.method == "GET":
        if user:
            # get the user with that user id
            user_details = db.query(User).get(int(user_id))

            # check if the profile is still active
            if user_details.user_deleted == "1":
                return render_template("profile_deleted.html", user=user)
            else:
                return render_template("user_details.html", user=user, user_details=user_details)
        else:
            return redirect(url_for("index"))

    elif request.method == "POST":
        # send recipient username to new message
        user_reply = request.form.get("user-reply")
        return redirect(url_for("new_message", user_reply=user_reply))


@app.route("/weather", methods=["GET", "POST"])
def weather():
    session_token = request.cookies.get("session_token")

    user = db.query(User).filter_by(session_token=session_token, user_deleted=False).first()

    if user:
        if request.method == "GET":
            query = "Zagreb"

        elif request.method == "POST":
            query = str(request.form.get("city-name"))

        unit = "metric"
        api_key = os.getenv("OPEN_WEATHER_MAP_API_KEY")

        url = "http://api.openweathermap.org/data/2.5/weather?q={0}&units={1}&appid={2}".format(query, unit, api_key)
        data = requests.get(url=url)
        data = data.json()

        # turning timestamp into a date and time
        readable = datetime.datetime.fromtimestamp(data["dt"])

        date = "{0}.{1}.".format(readable.strftime("%d"), readable.strftime("%m"))
        time = "{0}:{1}".format(readable.strftime("%H"), readable.strftime("%M"))

        return render_template("weather.html", user=user, data=data, date=date, time=time)
    else:
        return redirect(url_for("index"))


if __name__ == '__main__':
    app.run()