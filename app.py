import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, get_sold_shares, get_bought_shares

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
    # get all stock symbol relation with account id
    tx_records = db.execute("SELECT symbol, stock_name FROM tx where account_id = ? GROUP BY symbol", session["user_id"])

    # get current shares of all symbols
    data = []
    total_shares_value = 0
    for record in tx_records:
        shares_bought = get_bought_shares(db, session["user_id"], record["symbol"])

        # check how many shares were sold
        shares_sold = get_sold_shares(db, session["user_id"], record["symbol"])

        current_shares = shares_bought - shares_sold

        if current_shares <= 0:
            continue

        res = lookup(record["symbol"])

        data.append(
            {
                "symbol": record["symbol"],
                "name": record["stock_name"],
                "price": res["price"],
                "amount": current_shares,
                "total_amount": current_shares * res["price"]
            }
        )

        total_shares_value += current_shares * res["price"]

    # get all remaining cash from user
    curr_cash = int(db.execute("SELECT * FROM users where id = ?", session["user_id"])[0]["cash"])

    total_assets = curr_cash + total_shares_value

    return render_template("index.html", datas=data, total_assets=total_assets, user_cash=curr_cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "GET":
        return render_template("buy_form.html")

    if request.method == "POST":
        symbol = request.form["symbol"]
        amount = request.form["shares"]

        if not symbol or not symbol.isalpha():
            return apology("Error: Symbol field can't be empty", 400)

        res = lookup(symbol)

        if not res:
            return apology("Error: API not reachable", 400)

        if amount.isnumeric():
            amount = int(amount)
            if not amount or amount < 1:
                return apology("Error: Invalid amount", 400)
        else:
            return apology("Error: Invalid amount", 400)

        total_cash = int(db.execute("SELECT * FROM users where id = ?", session["user_id"])[0]["cash"])

        if total_cash <= 0:
            return apology("Error: Insufficent cash", 403)

        cash_needed = int(res["price"]) * amount

        remaning_cash = total_cash - cash_needed

        if remaning_cash < 0:
            return apology("Error: Not Enough Cash", 403)

        # update remaining cash
        db.execute("UPDATE users set cash = ? WHERE id = ?", remaning_cash, session["user_id"])

        # Create a new Transaction into TX table
        db.execute("INSERT INTO tx (price, account_id, symbol, stock_name, tx_date, amount, tx_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   res["price"],
                   session["user_id"],
                   res["symbol"],
                   res["name"],
                   str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                   amount,
                   "BUY"
                   )

        flash("Bought")
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    db_data = db.execute("SELECT * FROM tx WHERE account_id = ?", session["user_id"])

    return render_template("history.html", datas=db_data)


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
        session["username"] = rows[0]["username"]

        flash("Logged in as " + session["username"])
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


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
    if request.method == "GET":
        # Render form for lookup of a the specific stock
        return render_template("quote.html")

    if request.method == "POST":
        # recevive stock info from API
        symbol = request.form["symbol"]

        if not symbol or not symbol.isalpha():
            return apology("Error: Invalid ticker Symbol", 400)

        res = lookup(symbol)

        if not res:
            return apology("Error: Unable to contact API", 400)

        return render_template("quoted.html", data=res)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    if request.method == "POST":
        # Register a new user
        # First check if username and password are empty or not
        if not request.form["username"] or not request.form["password"]:
            return apology("Error: Empty Username or Password", 400)

        # Check if password match
        if request.form["password"] != request.form["confirmation"]:
            return apology("Error: Passwords don't match", 400)

        # Check if username already exists in db or not
        row = db.execute("SELECT * FROM users WHERE username = ?", request.form["username"])
        if len(row) > 0:
            return apology("Error: Username already exists", 400)

        # Insert new user into database
        db.execute("INSERT into users (username, hash) values (?, ?)",
                   request.form["username"], generate_password_hash(request.form["password"]))

        # login the user
        row = db.execute("SELECT * FROM users WHERE username = ?",
                         request.form.get("username"))
        session["user_id"] = row[0]["id"]
        session["username"] = row[0]["username"]

        flash("Registered")

        # redirect
        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        data = db.execute("SELECT * FROM tx WHERE account_id = ? GROUP BY symbol", session["user_id"])
        return render_template("sell_form.html", datas=data)

    if request.method == "POST":
        symbol = request.form["symbol"]
        form_shares = request.form["shares"]

        if not form_shares:
            return apology("Error: shares field can't be empty", 403)

        # Somehow Error Here
        if not symbol:
            return apology("Error: Symbol field can't be empty", 403)

        if not form_shares.isnumeric():
            return apology("Error: Invalid datatype", 403)

        form_shares = int(form_shares)

        # check how many shares the user owns of
        # that selected symbol
        # check how many shares were bought before

        shares_bought = get_bought_shares(db, session["user_id"], symbol)

        # check how many shares were sold
        shares_sold = get_sold_shares(db, session["user_id"], symbol)

        # calculate remaining shares that can be sold
        curr_shares = shares_bought - shares_sold

        # throw an error if curr_shares is <= 0
        if curr_shares <= 0 or curr_shares < form_shares:
            return apology("Error: Sorry you don't own enough shares")

        # get current share price
        res = lookup(symbol)
        if not res:
            return apology("AGHHHHHHHHHHHHH", 403)

        cash_from_shares_sold = res["price"] * form_shares

        # get current cash from user db
        curr_cash = int(db.execute("SELECT * FROM users where id = ?", session["user_id"])[0]["cash"])

        curr_cash += cash_from_shares_sold

        # add a SELL entry to TX Table
        db.execute("INSERT INTO tx (price, account_id, symbol, stock_name, tx_date, amount, tx_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   res["price"],
                   session["user_id"],
                   res["symbol"],
                   res["name"],
                   str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                   form_shares,
                   "SELL"
                   )

        # UPDATE USER CASH
        db.execute("UPDATE users SET cash = ? WHERE id = ?", curr_cash, session["user_id"])
        flash("Shares Sold")

        return redirect("/")