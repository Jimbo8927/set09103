from flask import Flask, render_template, g
import sqlite3

app = Flask(__name__)
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
		with app.open_resource("quizzleSchema.sql", mode='r') as f:
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

@app.route

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
