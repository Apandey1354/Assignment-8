const express = require('express');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static('public'));

const usersFilePath = path.join(__dirname, 'users.json');

const readUsers = () => {
    if (!fs.existsSync(usersFilePath)) return [];
    return JSON.parse(fs.readFileSync(usersFilePath));
};

const writeUsers = (users) => {
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
};

const generateAuthToken = () => crypto.randomBytes(32).toString('hex');
app.post('/users', async (req, res) => {
    let users = readUsers();
    const { username, password } = req.body;

    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (users.find(user => user.username === username)) return res.status(400).json({ error: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const authToken = generateAuthToken();

    const newUser = { username, password: hashedPassword, authToken };
    users.push(newUser);
    writeUsers(users);

    const { password: _, ...userWithoutPassword } = newUser;
    res.status(201).json(userWithoutPassword);
});
app.post('/users/auth', async (req, res) => {
    const users = readUsers();
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    const newAuthToken = generateAuthToken();
    user.authToken = newAuthToken;
    writeUsers(users);

    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
});
app.get('/users', (req, res) => {
    const users = readUsers();
    const sanitized = users.map(({ password, authToken, ...rest }) => rest);
    res.json(sanitized);
});
app.patch('/users/:username/:authToken', async (req, res) => {
    let users = readUsers();
    const { username, authToken } = req.params;
    const userIndex = users.findIndex(u => u.username === username && u.authToken === authToken);

    if (userIndex === -1) return res.status(401).json({ error: 'Unauthorized' });

    if (req.body.password) {
        users[userIndex].password = await bcrypt.hash(req.body.password, 10);
    }

    writeUsers(users);
    const { password: _, ...userWithoutPassword } = users[userIndex];
    res.json(userWithoutPassword);
});
app.delete('/users/:username/:authToken', (req, res) => {
    let users = readUsers();
    const { username, authToken } = req.params;

    const user = users.find(u => u.username === username && u.authToken === authToken);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });

    users = users.filter(u => u.username !== username);
    writeUsers(users);

    res.json({ message: 'User deleted' });
});
app.post('/users/:username/logout', (req, res) => {
    let users = readUsers();
    const { username } = req.params;

    const user = users.find(u => u.username === username);
    if (user) {
        user.authToken = null;
        writeUsers(users);
    }

    res.json({ message: 'Logged out' });
});

app.listen(PORT, () => {
    console.log(`Secure server running on http://localhost:${PORT}`);
});