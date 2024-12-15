function checkSignUp(event) {
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    const fname = document.getElementById('fname').value;
    const surname = document.getElementById('surname').value;
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;

    if(fname == "" || surname == "" || username == "" || email == "" || password == "" || confirmPassword == "") {
        event.preventDefault();
        errorMessage.textContent = "Please ensure all fields are filled";
    }
    else if (password === confirmPassword) {
        document.getElementById("sign-up").submit();
    } else {
        event.preventDefault();
        errorMessage.textContent = "Passwords Don't match, ensure both password and confirm password are the same";
    }
}

function checkPass(event) {
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    if(password == "" || confirmPassword == "") {
        event.preventDefault();
        errorMessage.textContent = "Please ensure all fields are filled";
    }
    else if (password === confirmPassword) {
        document.getElementById("sign-up").submit();
    } else {
        event.preventDefault();
        errorMessage.textContent = "Passwords Don't match, ensure both password and confirm password are the same";
    }
}

function createQuizInputFields(numb) {

    // fethces the id of the section to add the question and answer input fields
    let quizSection = document.getElementById("quizInput");

    // checks if the section has child nodes and removes them
    while(quizSection.hasChildNodes()) {
        quizSection.removeChild(quizSection.lastChild);
    }

    let form = document.createElement("FORM");
    form.setAttribute("name", "quiz");
    form.setAttribute("method", "post");

    let outerDiv = document.createElement("DIV");
    outerDiv.setAttribute("class", "container");

    let rowDiv = document.createElement("DIV");
    rowDiv.setAttribute("class", "row");

    // creates a label for each question
    let quizNameLabel = document.createElement("LABEL");
    quizNameLabel.setAttribute("name", "quizName-input");

    // creates a text node and appends it to the label
    let text0 = document.createTextNode("Quiz Name");
    quizNameLabel.appendChild(text0);

    // creates an input for the quiz name
    let quizNameInput = document.createElement("INPUT");
    quizNameInput.setAttribute("type", "text");
    quizNameInput.setAttribute("name", "quiz-name");
    quizNameInput.setAttribute("class", "form-control w-25 mx-auto mb-3");
    quizNameInput.setAttribute("style", "min-width: 300px");

    form.appendChild(quizNameLabel);
    form.appendChild(quizNameInput);

    for(let count = 0; count < numb; count++) {

        let innerDivs = document.createElement("DIV");
        innerDivs.setAttribute("class", "col-4 mx-auto mb-3 border");
        innerDivs.setAttribute("style", "min-width: 300px");
        innerDivs.style.maxWidth = "500px";

        // creates a label for each question
        let questionLabel = document.createElement("LABEL");
        questionLabel.setAttribute("name", "question-input");

        // creates a text node and appends it to the label
        let text1 = document.createTextNode("Question " + (count+1));
        questionLabel.appendChild(text1);

        // creates an input for each question
        let questionInput = document.createElement("INPUT");
        questionInput.setAttribute("type", "text");
        questionInput.setAttribute("name", "question"+(count+1));
        questionInput.setAttribute("class", "form-control mb-3");

        // creates a label for wrong answers
        let wrongAnswersLabel = document.createElement("LABEL");
        wrongAnswersLabel.setAttribute("name", "question-input");

        // creates a text node and appends it to the label
        let text2 = document.createTextNode("Wrong Answers");
        wrongAnswersLabel.appendChild(text2);

        // creates 4 answer input for each question
        // answer 1
        let answerOneInput = document.createElement("INPUT");
        answerOneInput.setAttribute("type", "text");
        answerOneInput.setAttribute("name", "answerOneQ"+(count+1));
        answerOneInput.setAttribute("class", "form-control mb-3");

        // answer 2
        let answerTwoInput = document.createElement("INPUT");
        answerTwoInput.setAttribute("type", "text");
        answerTwoInput.setAttribute("name", "answerTwoQ"+(count+1));
        answerTwoInput.setAttribute("class", "form-control mb-3");

        // answer 3
        let answerThreeInput = document.createElement("INPUT");
        answerThreeInput.setAttribute("type", "text");
        answerThreeInput.setAttribute("name", "answerThreeQ"+(count+1));
        answerThreeInput.setAttribute("class", "form-control mb-3");

        // creates a label for wrong answers
        let correctAnswerLabel = document.createElement("LABEL");
        correctAnswerLabel.setAttribute("name", "question-input");

        // creates a text node and appends it to the label
        let text3 = document.createTextNode("Correct Answer");
        correctAnswerLabel.appendChild(text3);

        // answer 4
        let answerFourInput = document.createElement("INPUT");
        answerFourInput.setAttribute("type", "text");
        answerFourInput.setAttribute("name", "answerFourQ"+(count+1));
        answerFourInput.setAttribute("class", "form-control mb-3");

        // appends the input fields and labels
        innerDivs.append(questionLabel);
        innerDivs.append(questionInput);

        innerDivs.append(wrongAnswersLabel);
        innerDivs.append(answerOneInput);

        innerDivs.append(answerTwoInput);

        innerDivs.append(answerThreeInput);

        innerDivs.append(correctAnswerLabel);
        innerDivs.append(answerFourInput);

        // appends innerDiv to outerDiv
        rowDiv.append(innerDivs);



    }
    // appends rowDiv to outerDiv
    outerDiv.append(rowDiv);

    // appends outerDiv to form
    form.appendChild(outerDiv);

    // creates button, adds attributes
    let submitBtn = document.createElement("BUTTON")
    submitBtn.setAttribute("type", "submit");
    submitBtn.setAttribute("class", "btn btn-secondary");
    submitBtn.textContent = "Create Quiz";

    // appends the button to the bottom of the form
    form.append(submitBtn);

    // appends the form created above to the section
    quizSection.append(form);
}

