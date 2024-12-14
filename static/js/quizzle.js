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

    let form = document.createElement("FORM");
    form.setAttribute("name", "quiz");
    form.setAttribute("method", "post");

    for(let count = 0; count < numb; count++) {

        let div = documnet.createElement("DIV");
        div.setAttribute("class", "d-flex flex-column");

        // creates a label for each question
        let label = document.createElement("LABEL");
        label.setAttribute("name", "question-input");
        // creates a text node and appends it to the label
        let text = documnet.createTextNode("Question " + count);
        label.appendChile(text);

        // creates an input for each question
        let questionInput = document.createElement("INPUT");
        questionInput.setAttribute("type", "text")

        // creates 4 answer input for each question
        // answer 1
        let answerOneInput = document.createElement("INPUT");
        questionInput.setAttribute("type", "text")

        // answer 2
        let answerTwoInput = document.createElement("INPUT");
        questionInput.setAttribute("type", "text")

        // answer 3
        let answerThreeInput = document.createElement("INPUT");
        questionInput.setAttribute("type", "text")

        // answer 4
        let answerFourInput = document.createElement("INPUT");
        questionInput.setAttribute("type", "text")

        // appends the input fields and labels
        div.append(label);
        div.append(questioninput);
        div.append(answerOneInput);
        div.append(answerTwoInput);
        div.append(answerThreeInput);
        div.append(answerFourInput);

        form.appendChild(div);

        //questionInput.setAttribute("", "")

    }
    // creates button, adds attributes
    let submitBtn = document.createElement("BUTTON")
    submitBtn.setAttribute("type", "submit");
    submitBtn.setAttribute("class", "btn btn-secondary");

    // appends the button to the bottom of the form
    form.append(submitBtn);

    // fethces the id of the section to add the question and answer input fields
    // appends the form created above to the section
    let quizSection = document.getElementById("quizInput");
    quizSection.append(form);
}

