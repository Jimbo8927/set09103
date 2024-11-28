from flask import Flask, render_template, g, session, request, url_for, redirect, flash
from functools import wraps
import sqlite3, configparser, secrets, bcrypt

app = Flask(__name__)

def init(app):
    config = configparser.ConfigParser()
    try:
        print("INIT FUNCTION")
        config_location = "etc/defaults.cfg"
        config.read(config_location)

        app.config['DEBUG'] = config.get("config", "debug")
        app.config['ip_address'] = config.get("config", "ip_address")
        app.config['port'] = config.get("config", "port")
        app.config['url'] = config.get("config", "url")
        app.config['db_location'] = config.get("config", "db_location")
        app.secret_key = config.get("config", "secret_key")
    except:
        print("Cound not read configs from: ", config_location)

init(app)

print(app.secret_key)

db_location = 'var/quizzle.db'

def get_db():
    db = getattr(g, 'db', None)
    if db is None:
        db = sqlite3.connect(db_location)
        g.db = db
    return db

@app.teardown_appcontext
def close_db_connection(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('quizzleSchema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def requires_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        status = session.get('logged-in', False)
        if not status:
            flash("Please log in to view this page")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def requires_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'account_type' not in session or session['account_type'] != 'admin':
            flash("You don't have permission to view this page")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/log-in', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        db = get_db()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()

        try:
            cursor.execute("SELECT admin_id AS id, username, password, account_type FROM admins WHERE username = ? UNION ALL SELECT user_id AS id, username, password, account_type FROM users WHERE username = ?", (username, username))

            record = cursor.fetchone()

            if record:
                if bcrypt.checkpw(password.encode('utf-8'), record['password']):
                    session['id'] = record['id']
                    session['username'] = record['username']
                    session['account_type'] = record['account_type']
                    session['logged-in'] = True

                    return redirect(url_for('home'))
            raise valueError("Wrong credentials")

        except:
            errorMessage = "Log in credentials are incorrect, please check your log in details and try again"
            return render_template('log-in.html', error=errorMessage)
    else:
        return render_template('log-in.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/sign-up', methods =['GET', 'POST'])
def signup():
    if request.method == 'POST':

        name = request.form['fname']
        surname = request.form['surname']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        passhash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        db = get_db()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        try:
            cursor.execute("SELECT username, email_address FROM admins WHERE username = ? OR email_address = ? UNION ALL SELECT username, email_address FROM users WHERE username = ? OR email_address = ?", (username, email, username, email))
            record = cursor.fetchone()

            if record:
                if record['username'] == username and record['email_address'] == email:
                    errorMessage = "username and email are in use, sign in to your account"
                    return render_template('sign-up.html', error=errorMessage)
                elif record['username'] == username:
                    errorMessage = "username is in use, please choose another"
                    return render_template('sign-up.html', error=errorMessage)
                elif  record['email_address'] == email:
                    errorMessage = "email is in use, sign in to your account"
                    return render_template('sign-up.html', error=errorMessage)



            cursor.execute("INSERT INTO users (first_name, surname, email_address, username, password, account_type) VALUES (?, ?, ?, ?, ?, ?)", (name, surname, email, username, passhash, 'user'))

            db.commit()
            flash("Account created successfully, please log in")
            return redirect(url_for('login'))
        except:
            return render_template('sign-up.html', error="An Error Occured, Account Wasn't Created")
    else:
        return render_template('sign-up.html')

@app.route('/profile')
@requires_login
def profile():
    db = get_db()
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    try:
        username = session['username']
        cursor.execute("SELECT first_name, surname, username, email_address FROM admins WHERE username = ? UNION ALL SELECT first_name, surname, username, email_address FROM users WHERE username = ?", (username, username))
        record = cursor.fetchone()

        if record is None:
            raise valueError("no details were retrieved")

        return render_template('profile.html', fname = record['first_name'], surname = record['surname'], username = record['username'], email = record['email_address'])
    except:
        flash("Sorry couldn't retrieve your details at this time, try again later")
        return redirect(url_for('home'))

@app.route('/profile/edit-account-details', methods =['GET', 'POST'])
@requires_login
def editDetails():
    if request.method == 'POST':

        id = session['id']
        sessionUsername = session['username']
        accountType = session['account_type']
        name = request.form['fname']
        surname = request.form['surname']
        username = request.form['username']
        email = request.form['email']

        db = get_db()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        try:
            cursor.execute("SELECT username, email_address FROM admins WHERE (username = ? or email = ?) AND admin_id != ? AND account_type != ? UNION ALL SELECT username, email_address FROM users WHERE (username = ? OR email = ?) AND user_id != ? AND account_type != ?)", (username, email, id, accountType, username, email, id, accountType))
            record = cursor.fetchone()

           # if record:
             #   if record['username'] == username and record['email_address'] == email:
             #       flash("username is in use, please choose another")
             #       return redirect(url_for('editDetails'))
             #   elif record['username'] == username:
             #       flash("username is in use, please choose another")
             #       return redirect(url_for('editDetails'))
             #   elif  record['email_address'] == email:
             #       flash("username is in use, please choose another")
             #       return redirect(url_for('editDetails'))



            #cursor.execute("UPDATE users SET first_name = ?, surname = ?, email_address = ?, username = ? WHERE username = ?", (name, surname, email, username, sessionUsername))
            #session['username'] = username
            #db.commit()

            flash("Account updated successfully")
            return redirect(url_for('profile'))
        except:
            return render_template('home.html', error="An Error Occured, Account Wasn't Updated")
    else:
        db = get_db()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()

        try:
            username = session['username']
            cursor.execute("SELECT first_name, surname, username, email_address FROM admins WHERE username = ? UNION ALL SELECT first_name, surname, username, email_address FROM users WHERE username = ?", (username, username))
            record = cursor.fetchone()

            if record is None:
                raise valueError("no details were retrieved")

            return render_template('edit-details.html', fname = record['first_name'], surname = record['surname'], username = record['username'], email = record['email_address'])
        except:
            flash("Sorry couldn't display this page at this time, please try again later")
            return redirect(url_for('profile'))

@app.route('/add-admin', methods =['GET', 'POST'])
@requires_admin
def addAdmin():
    if request.method == 'POST':

        name = request.form['fname']
        surname = request.form['surname']
        username = request.form['username']
        email = request.form['email']

        password = secrets.token_urlsafe(8)
        passhash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        db = get_db()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        try:
            cursor.execute("SELECT username, email_address FROM admins WHERE username = ? OR email_address = ? UNION ALL SELECT username, email_address FROM users WHERE username = ? OR email_address = ?", (username, email, username, email))
            record = cursor.fetchone()

            if record:
                if record['username'] == username and record['email_address'] == email:
                    errorMessage = "username and email are in use, sign in to your account"
                    return render_template('add-admin.html', error=errorMessage)
                elif record['username'] == username:
                    errorMessage = "username is in use, please choose another"
                    return render_template('add-admin.html', error=errorMessage)
                elif  record['email_address'] == email:
                    errorMessage = "email is in use, sign in to your account"
                    return render_template('add-admin.html', error=errorMessage)



            cursor.execute("INSERT INTO admins (first_name, surname, email_address, username, password, account_type) VALUES (?, ?, ?, ?, ?, ?)", (name, surname, email, username, passhash, 'admin'))

            db.commit()

            return render_template('added-admin-account.html', name = name, surname = surname, username = username, email = email, password = password)
        except:
            return render_template('add-admin.html', error="An Error Occured, Account Wasn't Created")
    else:
        return render_template('add-admin.html')

@app.route('/config')
def config():
    s = []
    s.append('debug: '+str(app.config['DEBUG']))
    s.append('port: '+app.config['port'])
    s.append('url: '+app.config['url'])
    s.append('ip_address: '+app.config['ip_address'])
    s.append('db_location: '+app.config['db_location'])
    s.append('secret_key: '+app.config['secret_key'])
    return ', '.join(s)

if __name__ == "__main__":
    init(app)
    app.run(host=app.config['ip_address'], port=int(app.config['port']))
