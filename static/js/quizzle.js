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
