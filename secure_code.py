from flask import Flask, request, redirect, render_template, session

app = Flask(__name__)
app.secret_key = 'your_secret_key'  
VALID_USERS = {
    "admin": "password",
    "user1": "123456",
    "user2": "password123"
}

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username in VALID_USERS and VALID_USERS[username] == password:
            session['username'] = username  # Store username in session
            return redirect("/dashboard")
        else:
            return render_template("login.html", error="Invalid username or password.")

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if 'username' in session:
        return render_template("dashboard.html", username=session['username'])
    else:
        return redirect("/")

@app.route("/logout")
def logout():
    session.pop('username', None)  # Remove username from session
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
