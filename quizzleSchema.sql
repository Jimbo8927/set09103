DROP TABLE IF EXISTS admins;

CREATE TABLE admins (
admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
image_path TEXT NOT NULL,
first_name TEXT NOT NULL,
surname TEXT NOT NULL,
email_address TEXT NOT NULL UNIQUE,
username TEXT NOT NULL UNIQUE,
password TEXT NOT NULL,
account_type TEXT NOT NULL
);

DROP TABLE IF EXISTS users;

CREATE TABLE users (
user_id INTEGER PRIMARY KEY AUTOINCREMENT,
image_path TEXT NOT NULL,
first_name TEXT NOT NULL,
surname TEXT NOT NULL,
email_address TEXT NOT NULL UNIQUE,
username TEXT NOT NULL UNIQUE,
password TEXT NOT NULL,
account_type TEXT NOT NULL
);

DROP TABLE IF EXISTS quizzes;

CREATE TABLE quizzes (
quiz_id INTEGER PRIMARY KEY AUTOINCREMENT,
admin_id INTEGER NOT NULL,
title TEXT NOT NULL,
FOREIGN KEY(admin_id) REFERENCES admins(admin_id)
);

DROP TABLE IF EXISTS questions;

CREATE TABLE questions (
question_id INTEGER PRIMARY KEY AUTOINCREMENT,
quiz_id INTEGER NOT NULL,
question TEXT NOT NULL,
FOREIGN KEY(quiz_id) REFERENCES quizzes(quiz_id)
);

DROP TABLE IF EXISTS answers;

CREATE TABLE answers (
answer_id INTEGER PRIMARY KEY AUTOINCREMENT,
question_id INTEGER NOT NULL,
answer TEXT NOT NULL,
is_correct TEXT NOT NULL,
FOREIGN KEY(question_id) REFERENCES questions(question_id)
);

DROP TABLE IF EXISTS quiz_scores;

CREATE TABLE quiz_scores (
score_id INTEGER PRIMARY KEY AUTOINCREMENT,
quiz_id INTEGER NOT NULL,
user_id INTEGER NOT NULL,
score TEXT NOT NULL,
FOREIGN KEY(quiz_id) REFERENCES quizzes(quiz_id),
FOREIGN KEY(user_id) REFERENCES users(user_id)
);
