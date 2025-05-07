'use strict'

const $ = document.querySelector.bind(document);

$('#loginLink').addEventListener('click', openLoginScreen);

$('#registerLink').addEventListener('click', openRegisterScreen);

$('#logoutLink').addEventListener('click', openLoginScreen);

$('#loginBtn').addEventListener('click', () => {
    if (!$('#loginUsername').value || !$('#loginPassword').value)
        return;

    fetch(`/users/${$('#loginUsername').value}`)
        .then(response => response.json())
        .then(doc => {
            if (doc.error) {
                showError(doc.error);
            } else if (doc.password !== $('#loginPassword').value) {
                showError('Username and password do not match.');
            } else {
                openHomeScreen(doc);
            }
        })
        .catch(err => showError('ERROR: ' + err));
});

$('#registerBtn').addEventListener('click', () => {
    if (!$('#registerUsername').value ||
        !$('#registerPassword').value ||
        !$('#registerName').value ||
        !$('#registerEmail').value) {
        showError('All fields are required.');
        return;
    }

    var data = {
        username: $('#registerUsername').value,
        password: $('#registerPassword').value,
        name: $('#registerName').value,
        email: $('#registerEmail').value
    };

    fetch('/users', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
        .then(response => response.json())
        .then(doc => {
            if (doc.error) {
                showError(doc.error);
            } else {
                openHomeScreen(doc);
            }
        })
        .catch(err => showError('ERROR: ' + err));
});

$('#updateBtn').addEventListener('click', () => {
    if (!$('#updateName').value || !$('#updateEmail').value) {
        showError('Fields cannot be blank.');
        return;
    }

    var data = {
        name: $('#updateName').value,
        email: $('#updateEmail').value
    };

    fetch(`/users/${$('#username').innerText}`, {
        method: 'PATCH',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
        .then(response => response.json())
        .then(doc => {
            if (doc.error) {
                showError(doc.error);
            } else if (doc.ok) {
                alert("Your name and email have been updated.");
            }
        })
        .catch(err => showError('ERROR: ' + err));
});

$('#deleteBtn').addEventListener('click', () => {
    if (!confirm("Are you sure you want to delete your profile?"))
        return;

    fetch(`/users/${$('#username').innerText}`, {
        method: 'DELETE'
    })
        .then(response => response.json())
        .then(doc => {
            if (doc.error) {
                showError(doc.error);
            } else {
                openLoginScreen();
            }
        })
        .catch(err => showError('ERROR: ' + err));
});

function showListOfUsers() {
    fetch('/users')
        .then(response => response.json())
        .then(docs => {
            docs.forEach(showUserInList);
        })
        .catch(err => showError('Could not get user list: ' + err));
}

function showUserInList(doc) {
    var item = document.createElement('li');
    $('#userlist').appendChild(item);
    item.innerText = doc.username;
}

function showError(err) {
    $('#error').innerText = err;
}

function resetInputs() {
    var inputs = document.getElementsByTagName("input");
    for (var input of inputs) {
        input.value = '';
    }
}

function openHomeScreen(doc) {
    $('#loginScreen').classList.add('hidden');
    $('#registerScreen').classList.add('hidden');
    resetInputs();
    showError('');
    $('#homeScreen').classList.remove('hidden');
    $('#name').innerText = doc.name;
    $('#username').innerText = doc.username;
    $('#updateName').value = doc.name;
    $('#updateEmail').value = doc.email;
    $('#userlist').innerHTML = '';
    showListOfUsers();
}

function openLoginScreen() {
    $('#registerScreen').classList.add('hidden');
    $('#homeScreen').classList.add('hidden');
    resetInputs();
    showError('');
    $('#loginScreen').classList.remove('hidden');
}

function openRegisterScreen() {
    $('#loginScreen').classList.add('hidden');
    $('#homeScreen').classList.add('hidden');
    resetInputs();
    showError('');
    $('#registerScreen').classList.remove('hidden');
}