from flask import Flask, render_template, g
import sqlite3, configparser

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
    except:
        print("Cound not read configs from: " config_location)
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
