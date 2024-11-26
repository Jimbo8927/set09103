from flask import Flask, render_template, g, session, request
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
        app.config['secret_key'] = config.get("config", "secret_key")
    except:
        print("Cound not read configs from: ", config_location)
        

init(app)

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

@app.route('/')
def basicTemplate():
    return render_template('home.html')

@app.route('/log-in')
def login():
    return render_template('log-in.html')

@app.route('/sign-up')
def signup():
    return render_template('sign-up.html')

@app.route('/add-admin', methods =['GET', 'POST'])
def addAdmin():
    if request.method == 'POST':

        name = request.form['fname']
        surname = request.form['surname']
        username = request.form['username']
        email = request.form['email']

        password = secrets.token_urlsafe(8)
        passhash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        db = get_db()
        try:
            db.cursor.execute("SELECT username, email_address FROM users WHERE username == username OR email == email_address  UNION ALL SELECT username, email_address FROM admins WHERE username == username OR email == email_address")

            db.row_factory = sqlitee3.Row

            if r['username'] == username and r['email'] == email:
                errorMessage = "username and email are in use, sign in to your account"
            elif r['username'] == username:
                errorMessage = "username is in use, please choose another"
            elif  r['email'] == email:
                errorMessage = "email is in use, sign in to your account"

            return render_template('add-admin.html', error=errorMessage)
        except:

            try:
                db.cursor().execute("INSERT INTO admins (first_name, surname, email_address, username, password, account_type) VALUES (?, ?, ?, ?, ?, ?)", (name, surname, email, username, passhash, 'admin'))

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
    return ', '.join(s)

if __name__ == "__main__":
    init(app)
    app.run(host=app.config['ip_address'], port=int(app.config['port']))
