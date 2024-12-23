# imports flask and libraries
from flask import Flask, render_template, g, session, request, url_for, redirect, flash
# imports wraps from functools
from functools import wraps
# imports sqlite3, configparser, secrets and bcrypt
import sqlite3, configparser, secrets, bcrypt, json

app = Flask(__name__)

# initialises app by reading values from the configuration file
# displays error message if all values cannot be read in
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

# calls the above init function
init(app)

#sets database location
db_location = 'var/quizzle.db'

# connects to the database for quizzle using the db_locaton variable
def get_db():
    db = getattr(g, 'db', None)
    if db is None:
        db = sqlite3.connect(db_location)
        g.db = db
    return db

# decorator calls function automatically, doesn't need called
# closes the connection to the database
@app.teardown_appcontext
def close_db_connection(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()

# Initialises database when called based on the schema withing the .sql file
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('quizzleSchema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# decorator function requires log_login, checks if the user is logged in
# if the user is logged in the original function is called
# if the user is not logged in the user is redirected to the log in page, and asked to log in
def requires_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        status = session.get('logged-in', False)
        if not status:
            flash("Please log in to view this page")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# decorator function requires requires_admin, checks if the user is an admin
# if the user is an admin the original function is called
# if the user is not an admin the user is redirected to the home page, and
# instructed they do not have permission to view this page
def requires_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'account_type' not in session or session['account_type'] != 'admin':
            flash("You don't have permission to view this page")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated

# home/default route, navigates here unless another path is specified
@app.route('/')
def home():
    return render_template('home.html')

# login - makes use of post and get methods
# login returns the log-in.html file to be displayed to the user
# When a user attempts to login a post request is made, the username and password input in the log in form is used to check for a match in the database where both username and password match
# If there is a match session variabes are set accordingly and the user is navigated to the home page.
@app.route('/log-in', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        db = get_db()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()

        query = """
                SELECT admin_id AS id, username, password, account_type
                FROM admins
                WHERE username = ?
                UNION ALL
                SELECT user_id AS id, username, password, account_type
                FROM users
                WHERE username = ?

                """

        try:
            cursor.execute(query, (username, username))

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

# logout
# log out clears session variables and return the user to the log in screen
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# sign up, makes use of GET and POST methods
# sign up returns the sign-up.html page to the user, contains error message if the user tries to make an account and an error occurs
# Takes the information submitted in the sign-up form and creates a new user account, password is hashed using bcrypt before being stored
# before creating an account a check is made to ensure that the username or email address isn't linked to another account
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

        checkQuery = """
                SELECT username, email_address
                FROM admins
                WHERE username = ? OR email_address = ?
                UNION ALL SELECT username, email_address
                FROM users
                WHERE username = ? OR email_address = ?
                """

        try:
            cursor.execute(checkQuery, (username, email, username, email))
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

            insertQuery = """
                          INSERT INTO users (first_name, surname, email_address, username, password, account_type)
                          VALUES (?, ?, ?, ?, ?, ?)

                          """

            cursor.execute(insertQuery, (name, surname, email, username, passhash, 'user'))

            db.commit()
            flash("Account created successfully, please log in")
            return redirect(url_for('login'))
        except:
            return render_template('sign-up.html', error="An Error Occured, Account Wasn't Created")
    else:
        return render_template('sign-up.html')

# profile, uses the GET method
# returns the profile.html to display the current users details
# using session username to select the correct user
# return an error if the users details are not retrieved
# uses decorator fuction requires_login to ensure a user is logged in before attempting to retrieve details
@app.route('/profile')
@requires_login
def profile():
    db = get_db()
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    try:
        username = session['username']

        query = """
                SELECT first_name, surname, username, email_address
                FROM admins WHERE username = ?
                UNION ALL SELECT first_name, surname, username, email_address
                FROM users WHERE username = ?
                """
        cursor.execute(query, (username, username))
        record = cursor.fetchone()

        if record is None:
            raise valueError("no details were retrieved")

        return render_template('profile.html', fname = record['first_name'], surname = record['surname'], username = record['username'], email = record['email_address'])
    except:
        flash("Sorry couldn't retrieve your details at this time, try again later")
        return redirect(url_for('home'))

# edit details, makes use of GET and POST methods
# retrieves the users details from the database and sends them to the edit page
# when a user attempts to update their details, the data from the form submission is retrieved and used to update the users data within the database then returns the user to the profile page
# before updating the users account a check is made to ensure that the username or email address isn't linked to another account
# uses decorator fuction requires_login to ensure a user is logged in before attempting to retrieve details
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
            checkQuery = """
                         SELECT username, email_address
                         FROM admins
                         WHERE (username = ? OR email_address = ?) AND NOT (admin_id = ? AND account_type = ?)
                         UNION ALL
                         SELECT username, email_address
                         FROM users
                         WHERE (username = ? OR email_address = ?) AND NOT (user_id = ? AND account_type = ?)
                         """
            cursor.execute(checkQuery, (username, email, id, accountType, username, email,  id, accountType))
            record = cursor.fetchone()

            if record:
                if record['username'] == username and record['email_address'] == email:
                    flash("username and email are in use, please sign in")
                    return redirect(url_for('editDetails'))
                elif record['username'] == username:
                    flash("username is in use, please choose another")
                    return redirect(url_for('editDetails'))
                elif  record['email_address'] == email:
                    flash("Email is in use, please choose another")
                    return redirect(url_for('editDetails'))

            updateQuery = """
                          UPDATE users
                          SET first_name = ?, surname = ?, email_address = ?, username = ?
                          WHERE username = ?
                          """

            cursor.execute(updateQuery, (name, surname, email, username, sessionUsername))
            db.commit()
            session['username'] = username

            flash("Account updated successfully")
            return redirect(url_for('profile'))
        except Exception as e:
           return render_template('home.html', error="An Error Occured, Account Wasn't Updated")
    else:
        db = get_db()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()

        try:
            username = session['username']

            detailsQuery = """
                           SELECT first_name, surname, username, email_address
                           FROM admins
                           WHERE username = ?
                           UNION ALL
                           SELECT first_name, surname, username, email_address
                           FROM users
                           WHERE username = ?
                           """

            cursor.execute(detailsQuery, (username, username))
            record = cursor.fetchone()

            if record is None:
                raise valueError("no details were retrieved")

            return render_template('edit-details.html', fname = record['first_name'], surname = record['surname'], username = record['username'], email = record['email_address'])
        except:
            flash("Sorry couldn't display this page at this time, please try again later")
            return redirect(url_for('profile'))

# edit password user - allows a user to change their password, uses POST and GET methods
# returns the pass-update-a upon initial load of the route
# password is hashed using bcrypt before being stored
# message is flashed indicationg whether the password is updated or not, and user is returned to thier profile page
@app.route('/profile/edit-account-details/edit-password', methods =['GET', 'POST'])
@requires_login
def editPasswordU():
    if request.method == 'POST':

        try:
            password = request.form['password']
            username = session['username']
            passHash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            db = get_db()
            cursor = db.cursor()

            updateQuery = """
                          UPDATE users
                          SET password = ?
                          WHERE username = ?
                          """

            cursor.execute(updateQuery, (passHash, username))
            db.commit()

            flash("Password updated sucsessfully")
            return redirect(url_for('profile'))
        except:
            flash("Password couldn't be updated at this time, please try again later")
            return redirect(url_for('profile'))
    else:
        return render_template('pass-update-u.html')

# edit password admin - allows admin to change their password, uses POST and GET methods
# returns the pass-update-u upon initial load of the route
# password is hashed using bcrypt before being stored
# message is flashed and user is returned to thier profile page if the password can't be changed and updated successfully
# otherwise they are directed to a new page to view their new password.
@app.route('/profile/edit-account-details/update-password', methods =['GET', 'POST'])
@requires_login
@requires_admin
def editPasswordA():
    if request.method == 'POST':

        try:
            password = secrets.token_urlsafe(8)
            username = session['username']
            passHash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            db = get_db()
            cursor = db.cursor()

            updateQuery = """
                          UPDATE admins
                          SET password = ?
                          WHERE username = ?
                          """

            cursor.execute(updateQuery, (passHash, username))
            db.commit()

            return render_template('passUpdated.html', passMessage1="Password updated successfully, ensure you have taken not of your new password", passMessage2="Your New Password is: " + password)
        except:
            flash("Password couldn't be updated at this time, please try again later")
            return redirect(url_for('profile'))
    else:
        return render_template('pass-update-a.html')


# add-admin allows an admin to create an admin account, makes use of GET and POST methods
# returns the add-admin.html page, if an admin tries to make an admin account, a check is made to ensure the username or email isn't in use by another account
# upon account creation the admin is redirected to a page that displays the details of the newly created account, including the password which is only ever seen or accessible from this page
# uses secrets.token_urlsafe to generate a new random password for the admin account
# uses bcrypt to hash the password before storing it
# uses decorator fuction requires_admin to ensure an admin is logged in before allowing the admin to create another admin account
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

            checkQuery = """
                         SELECT username, email_address
                         FROM admins
                         WHERE username = ? OR email_address = ?
                         UNION ALL
                         SELECT username, email_address
                         FROM users
                         WHERE username = ? OR email_address = ?
                         """
            cursor.execute(checkQuery, (username, email, username, email))
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

            insertQuery = """
                          INSERT INTO admins (first_name, surname, email_address, username, password, account_type)
                          VALUES (?, ?, ?, ?, ?, ?)
                          """

            cursor.execute(insertQuery, (name, surname, email, username, passhash, 'admin'))

            db.commit()

            return render_template('added-admin-account.html', name = name, surname = surname, username = username, email = email, password = password)
        except:
            return render_template('add-admin.html', error="An Error Occured, Account Wasn't Created")
    else:
        return render_template('add-admin.html')

# delete personal account, uses GET and POST methods
# allows users and admins to delete their accounts
@app.route('/delete-account', methods =['GET','POST'])
@requires_login
def deleteAccount():
    if request.method == 'POST':

        try:

            id = session['id']

            db = get_db()
            cursor = db.cursor()

            if session['account_type'] and session['account_type'] == 'user':
                deleteQuery = """
                              DELETE FROM users
                              WHERE user_id = ?
                              """
            elif session['account_type'] and session['account_type'] == 'admin':
                deleteQuery = """
                              DELETE FROM admins
                              WHERE admin_id = ?
                              """
            else:
                raise valueError("account type invalid")

            cursor.execute(deleteQuery, (id,))
            db.commit()

            session.clear()

            flash('account deleted')
            return redirect(url_for('home'))
        except:
            flash("account couldn't be deleted at this time")
            return redirect(url_for('home'))
    else:
        return render_template('delete-account.html')

#delete account as admin
@app.route('/delete-account-asAdmin', methods =['GET','POST'])
@requires_admin
def deleteAccountAsAdmin():
    if request.method == 'POST':

        username = request.args.get('username')
        accType = request.args.get('accType')

        db = get_db()
        cursor = db.cursor()

        if accType and accType == 'user':
            deleteQuery = """
                          DELETE FROM users
                          WHERE username = ?
                          """
        elif accType and accType == 'admin':
            deleteQuery = """
                          DELETE FROM admins
                          WHERE username = ?
                          """
        else:
           raise valueError("account type invalid")

        cursor.execute(deleteQuery, (username,))
        db.commit()

        flash('account deleted')

        if accType and accType == 'user':
            return redirect(url_for('listUser'))
        elif accType and accType == 'admin':
            return redirect(url_for('listAdmin'))
    else:
        username = request.args.get('username')
        accType = request.args.get('accType')

        return render_template('delete-account.html', delUsername = username, delAccType = accType)

# list users - returns list-user.html with a list of users to the admin
# uses decorator fuction requires_admin to ensure an admin is logged in before listing users
@app.route('/list-users', methods =['GET','POST'])
@requires_admin
def listUser():
    if request.method == 'POST':

        username = request.form['username']
        accType = request.form['accType']

        return redirect(url_for('deleteAccountAsAdmin', username = username, accType = accType))

    else:
        db = get_db()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()

        try:
            listQuery = """
                        SELECT first_name, surname, username, email_address, account_type
                        FROM users
                        """
            cursor.execute(listQuery)
            record = cursor.fetchall()

            title = "User Accounts"

            return render_template('list-users.html', title = title, users = record)
        except:
            flash("Couldn't retrieve user data")
            return redirect(url_for('home'))

# list admins - returns list-user.html with a list of admins to the admin
# uses decorator fuction requires_admin to ensure an admin is logged in before listing users
@app.route('/list-admin', methods =['GET','POST'])
@requires_admin
def listAdmin():

    if request.method == 'POST':

        username = request.form['username']
        accType = request.form['accType']

        return redirect(url_for('deleteAccountAsAdmin', username = username, accType = accType))

    else:
        db = get_db()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()

        try:
            listQuery = """
                        SELECT first_name, surname, username, email_address, account_type
                        FROM admins
                        """
            cursor.execute(listQuery)
            record = cursor.fetchall()

            title = "Admin Accounts"

            return render_template('list-users.html', title = title, users = record)
        except:
            flash("Couldn't retrieve user data")
            return redirect(url_for('home'))


# create quiz - creates a quiz based on dat apassed back from input fields
#
@app.route('/create-quiz', methods =['GET','POST'])
@requires_admin
def createQuiz():
    if request.method == "POST":
        try:

            db = get_db()
            db.row_factory = sqlite3.Row
            cursor = db.cursor()

            # sets numQuestions to the amount of questions returned from the form
            numQuestions = request.form['numQuestions']


            quizName = request.form['quiz-name']
            creatorID = session['id']


            quizNameInsertQuery = """
                                  INSERT INTO quizzes (admin_id, title)
                                  VALUES (?, ?)
                                  """

            cursor.execute(quizNameInsertQuery, (creatorID, quizName))

            # selects the last inserted rows id
            quizIdQuery = """
                      SELECT last_insert_rowid()
                      """

            cursor.execute(quizIdQuery)

            getQuizID = cursor.fetchone()

            # sets the last inserted rows id based on returned column
            quizId = getQuizID['last_insert_rowid()']

            # loops through the questions returned getting their values from request.form and inserts
            # their questions and all 4 answers into their respective databases
            for count in range(int(numQuestions)):
                question = request.form['question'+str(count+1)]
                answerOne = request.form['answerOneQ'+str(count+1)]
                answerTwo = request.form['answerTwoQ'+str(count+1)]
                answerThree = request.form['answerThreeQ'+str(count+1)]
                answerFour = request.form['answerFourQ'+str(count+1)]

                questionInseryQuery = """
                                      INSERT INTO questions (quiz_id, question)
                                      VALUES(?, ?)
                                      """
                cursor.execute(questionInseryQuery, (quizId, question))

                questionIdQuery = """
                      SELECT last_insert_rowid()
                      """

                cursor.execute(questionIdQuery)
                getQuestionID = cursor.fetchone()

                questionId = getQuestionID['last_insert_rowid()']

                answerQuery = """
                              INSERT INTO answers (question_id, answer, is_correct)
                              VALUES (?, ?, ?)
                              """
                cursor.execute(answerQuery, (questionId, answerOne, False))

                cursor.execute(answerQuery, (questionId, answerTwo, False))

                cursor.execute(answerQuery, (questionId, answerThree, False))

                cursor.execute(answerQuery, (questionId, answerFour, True))


            db.commit()
            flash("Quiz Added Successfully")
            return redirect(url_for("quizList"))

        except Exception as e:
            # returns user to create quiz if their is an error during insertion
            flash("Couldn't create a quiz at this time, try again later")
            return redirect(url_for("createQuiz"))
    else:
        return render_template("create-quiz-Q-A.html")

# quiz list - lists all current quizes
# queries the quizzes database table returning the title and id of each quiz available
# redirects the user to the home page, returning an error message if the list cannot be returned
@app.route('/quiz-list', methods =['GET','POST'])
@requires_login
def quizList():

    if request.method == "POST":

        quizId = request.form["quizId"]

        if 'start' in request.form:
            return redirect(url_for("startQuiz", quizId = quizId))
        elif 'leaderboard' in request.form:
            return redirect(url_for("leaderboard", quizId = quizId))
        elif 'delete' in request.form:
            return redirect(url_for("deleteQuiz", quizId = quizId))

    else:
        try:
            db = get_db()
            db.row_factory = sqlite3.Row
            cursor = db.cursor()

            quizQuery = """
                        SELECT quiz_id, title
                        FROM quizzes
                        """

            cursor.execute(quizQuery)
            quiz = cursor.fetchall()


            return render_template("quiz-list.html", quizes = quiz)
        except:
            flash("Couldn't display the quizes at this time, please try again later")
            return redirect(url_for("home"))

# startQuiz - is a page where a user chooses to start the quiz or return to the quiz list
# if the user chooses to start the quiz the database is querried returning the quiz chosen in the quiz list
# both questions and answers are retruned in a randomised order and added to a dictionary
# ensuring that each time a quiz is taken, the order for answers and question are different
@app.route('/quiz', methods =['GET','POST'])
@requires_login
def startQuiz():

    if request.method == "POST":

        # checks if quiz is returned through the form submission
        # redirects user to take quiz if quiz is available
        if "quiz" in request.form:
            quiz = request.form["quiz"]
            return redirect(url_for('takeQuiz', quiz = quiz))
        else:
            # redirects user to the home route if quiz isn't available
            flash("Sorry, couldn't continue with the quiz. Please try again later.")
            return redirect(url_for("home"))

    else:
        try:
            quizId = request.args["quizId"]

            # retrieves the full quiz information, title, questions and answers
            db = get_db()
            db.row_factory = sqlite3.Row
            cursor = db.cursor()

            quizQuery = """
                        SELECT quizzes.title, questions.question_id, questions.question, answers.answer, answers.is_correct
                        FROM quizzes
                        JOIN questions
                        ON quizzes.quiz_id = questions.quiz_id
                        JOIN answers
                        ON questions.question_id = answers.question_id
                        WHERE quizzes.quiz_id = ?
                        ORDER BY RANDOM()
                        """


            cursor.execute(quizQuery, (quizId,))
            quiz = cursor.fetchall()

            # creates a dictionary to store the quiz
            qDict = {}
            count = 1

            # loops through each row returned through the query
            for row in quiz:
                # checks if title is in the dictionary and adds the title
                # and an empty quetion dict
                if "title" not in qDict:
                    qDict.update({"title": row["title"]})
                    qDict.update({"questions": {}})

                questionId = row["question_id"]
                questionInDict = False
                # loops through each question in qDict
                for question in qDict["questions"].values():

                    # if the question id within qdict matches the id from the current row
                    # updates questions answers setting the question as the key
                    # and the value as is_correct to trach which answer is true
                    # sets questionInDict to true
                    if question["qId"] == questionId:
                        question["answers"].update({row["answer"]: row["is_correct"]})
                        questionInDict = True

                # if the question is not in the dictionary a new quetion entry is created and updated
                # with the question id, question text and current answer on the row
                if not questionInDict:
                    qDict["questions"].update({
                        count: {
                               "qId": row["question_id"],
                               "question": row["question"],
                               "answers": {row["answer"]: row["is_correct"]}
                               }})
                    count += 1

            # sets title to title of retrieved quiz
            # sest quiz to qDict converted to json for being moved around and keeping
            # its format
            title = row["title"]
            quiz = json.dumps(qDict)

            return render_template('quizStart.html', title=title, quiz=quiz)
        except Exception as e:
            flash("Sorry, couldn't continue with the quiz. Please try again later.")
            return redirect(url_for("home"))

# take quiz - allows users to take a quiz making use of the quiz created in the startQuiz route
# moves through questions updating the users score as they answer, once the quiz is finished
# users are naviagted to their results which displays their score with a message based on their score
@app.route('/quiz/question', methods =['GET','POST'])
@requires_login
def takeQuiz():

    if "qNum" in session and request.method == "POST":
        try:
            # checks to see if quiz is within request.form
            # converst the quiz back from json to be used within the quiz
            if "quiz" in request.form:
                quizJson = request.form["quiz"]
                quiz = json.loads(quizJson)

            else:
                # redirects user back to home page with error message if the quiz isn't avalable
                flash("Sorry, couldn't continue with the quiz. Please try again later.")
                return redirect(url_for("home"))

            # converts session["qNumb"] to an int to allow adding 1, to select question 2
            # converts it back to ensure it has teh same datatype as the dictionary key
            qNumb = int(session["qNum"])
            qNumb += 1
            session["qNum"] = str(qNumb)

            # checks if 1 is returned from form on each post request
            # if 1 is returned, the user has selected the correct answer
            # quizScore is increased by 1
            if request.form["answer"] == "1":
                quizScore = int(session["quizScore"])
                quizScore += 1
                session["quizScore"] = quizScore

            # gets the number of questions in the quiz for displayin the users score
            numQuestions = len(quiz["questions"])

            # checks if question number is higher than the number of questions
            # if higher, renders template to display the users score
            # otherwise keeps cycling through the questions
            if qNumb > numQuestions:
                return render_template("quiz-score.html", score = int(session["quizScore"]), numQuestions = numQuestions)
            else:
                question = quiz["questions"][session["qNum"]]
                return render_template('questionPage.html', quizJson = quizJson, quiz = quiz, question = question)

        except Exception as e:

            flash("Sorry, couldn't continue with the quiz. Please try again later.")
            return redirect(url_for("home"))

    else:

        # checks to see if quiz is with request.args
        # converst the quiz back from json to be used within the quiz
        if "quiz" in request.args:
            quizJson = request.args["quiz"]
            quiz = json.loads(quizJson)


        else:
            flash("Sorry, couldn't continue with the quiz. Please try again later.")
            return redirect(url_for("home"))

        # sets session variables for taking a quiz
        session["qNum"] = "1"
        session["quizScore"] = 0

        # sets question to the first question in the quiz
        question = quiz["questions"][session["qNum"]]
        return render_template('questionPage.html', quizJson = quizJson, quiz = quiz, question = question)


# delete quiz
@app.route('/delete-quiz', methods =['GET','POST'])
@requires_admin
def deleteQuiz():
    if request.method == "POST":
        try:

            quizId = request.args["quizId"]

            db = get_db()
            db.row_factory = sqlite3.Row
            cursor = db.cursor()

            # selects ID's for deleting a quiz
            quizQuery = """
                        SELECT questions.question_id
                        FROM questions
                        WHERE questions.quiz_id = ?
                        """


            cursor.execute(quizQuery, (quizId,))
            quizQId = cursor.fetchall()

            # delete queries
            quizDeleteQuery = """
                              Delete FROM quizzes
                              WHERE quiz_id = ?
                              """

            questionDeleteQuery = """
                                  Delete FROM questions
                                  WHERE quiz_id = ?
                                  """

            answerDeleteQuery = """
                                Delete FROM answers
                                WHERE question_id = ?
                                """
            # creates a transaction - ensures each delete query executes successfully
            # if one fails they all do
            cursor.execute("begin")
            try:

                for row in quizQId:
                    questionId = row["question_id"]
                    cursor.execute(answerDeleteQuery, (questionId,))

                cursor.execute(questionDeleteQuery, (quizId,))

                cursor.execute(quizDeleteQuery, (quizId,))

            except:
                cursor.execute("rollback")
                flash("couldn't delete quiz at this time")
                return redirect(url_for("quizList"))

            #commits changes
            db.commit()

            flash("Quiz Deleted")
            return redirect(url_for("quizList"))

        except Exception as e:
            flash(str(e))
            flash("Couldn't delete the quiz at this time")
            return redirect(url_for("quizList"))

    else:
        quizId = request.args["quizId"]
        return render_template("delete-quiz.html", quizId = quizId)

# print config information to the user
# uses decorator fuction requires_admin to ensure an admin is logged in before displaying information
@app.route('/config')
@requires_admin
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
