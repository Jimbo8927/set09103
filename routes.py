from flask import Flask, render_template
app = Flask(__name__)

@app.route('/')
def basicTemplate():
    return render_template('home.html')

@app.route('/log-in')
def login():
	return render_template('log-in.html')

@app.route('/sign-up')
def signup():
        return render_template('sign-up.html')

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
