import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
from datetime import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = user_id = session["user_id"]
    cash_db = db.execute("SELECT cash FROM users WHERE id=?", user_id)
    if len(cash_db) > 0:
        cash = cash_db[0]["cash"]
    else:
        return apology("Invalid User", 400)
        
    transactions = db.execute("SELECT time, symbol, price, shares, total FROM transactions WHERE user_id=?", user_id)
    value_of_shares = db.execute("SELECT SUM(total) FROM transactions WHERE user_id=? GROUP BY symbol", user_id)
    total_value = 0
    for row in value_of_shares:
        total_value += row["SUM(total)"]
    total_value += cash
    return render_template("index.html", cash = cash, transactions = transactions, total_value = total_value, usd = usd)
    

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Must enter a symbol", 400)
        ticker = lookup(request.form.get("symbol"))
        if not ticker:
            return apology("Invalid symbol", 400)
        price = ticker["price"]
        try:
            shares = int(request.form.get("shares"))
        except (ValueError):
            return apology("share count must be a postitive integer")

        if shares <= 0:
            return apology("Non-positive share count", 400)
        else:
            user_id = session["user_id"]
            cash_db = db.execute("SELECT cash FROM users WHERE id=?", user_id)
            if len(cash_db) > 0:
                cash = cash_db[0]["cash"]
            
            value = price * shares
            
            if cash < value:
                return apology("Insufficient funds")
            
            new_cash = cash - value
            
            db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)
            

            db.execute("INSERT INTO transactions(user_id, symbol, price, shares, total, time) VALUES (?, ?, ?, ?, ?, ?)", user_id, symbol, price, shares, value, (datetime.now()))
            
            flash("Purchase Successful")    
             
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")



@app.route("/history")
@login_required
def history():
    user_id = session["user_id"]
    """Show history of transactions"""
    history = db.execute("SELECT * FROM transactions WHERE user_id=?", user_id)
    return render_template("history.html", history = history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/toreset", methods=["POST"])
def toreset():
        return render_template("reset.html")

@app.route("/reset")
def reset():
    if request.method == "POST":
        username = request.form.get("username")
        new_pass = request.form.get("password")
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) != 1:
            return apology("Username does not exist", 400)
        else:
            db.execute("UPDATE users SET hash = ? WHERE username = ?", generate_password_hash(new_pass), username)
        return redirect("/login")
    else:
        return render_template("reset.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        quote = lookup(request.form.get("symbol"))

        if not quote:
            return apology("Invalid symbol", 400)
        else:
            return render_template("quoted.html", quote=quote)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    #session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        
        if not request.form.get("username"):
            return apology("must provide username", 400)
        if request.form.get("username") == None:
            return apology("must enter in a username", 400)
        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirmed-password is the same
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 400)
        
        usernames_db = db.execute("SELECT username FROM users")
        for row in usernames_db:
            if request.form.get("username") == row["username"]:
                return apology("username already taken", 400)
        # Get username and hash password
        username = request.form.get("username")
        password_hash = generate_password_hash(request.form.get("password"))

        # Insert into database the password and username
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password_hash)

        # Remember which user has logged in
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Must enter a symbol", 400)
        user_id = session["user_id"]
        owned_db = db.execute("SELECT symbol FROM transactions WHERE user_id=?", user_id)
        if len(owned_db) < 1:
            return apology("User does not own this symbol", 400)
        quote = lookup(symbol)
        price = quote["price"]
        shares = int(request.form.get("shares"))
        if not price:
            return apology("Invalid symbol", 400)
        else:
            user_id = session["user_id"]
            cash_db = db.execute("SELECT cash FROM users WHERE id=?", user_id)
            if len(cash_db) > 0:
                    cash = cash_db[0]["cash"]
            
            shares_db = db.execute("SELECT SUM(shares) FROM transactions WHERE user_id=? AND symbol=? GROUP BY symbol", user_id, symbol)
            if len(shares_db) > 0:
                    real_shares = int(shares_db[0]["SUM(shares)"])
            if shares > real_shares:
                return apology("Insufficient Shares", 400)
            if shares <= 0:
                return apology("Non-positive share count", 400)
            else:
                value = price * shares
                
                new_cash = cash + value
                
                db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)
                
                db.execute("INSERT INTO transactions(user_id, symbol, price, shares, total, time) VALUES (?, ?, ?, ?, ?, ?)", user_id, symbol, price, (shares*-1), (value * -1), (datetime.now()))
                
                flash("Sold")    
                 
                return redirect("/")
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        user_id = session["user_id"]
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id=? GROUP BY symbol", user_id)
        symbols_list = []
        for row in symbols:
            symbols_list.append(row["symbol"])
        return render_template("sell.html", symbols = symbols_list)
