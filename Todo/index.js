const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const authenticate = require('./authMiddleware');
const authorizeAdmin = require('./adminMiddleware');

const app = express();
app.use(bodyParser.json());

const SECRET_KEY = 'supersecretkey';

// In-memory "databases"
let users = [];
let todos = [];
let todoIdCounter = 1;
app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password required' });
    }
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: users.length + 1,
        username,
        password: hashedPassword,
        role: role || 'user'
    };
    users.push(newUser);
    res.json({ message: 'User registered successfully' });
});
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(400).json({ message: 'Invalid username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: 'Invalid username or password' });
    }

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});
// Get user's own todos
app.get('/api/todos', authenticate, (req, res) => {
    const userTodos = todos.filter(todo => todo.userId === req.user.id);
    res.json(userTodos);
});

// Create todo
app.post('/api/todos', authenticate, (req, res) => {
    const { task } = req.body;
    if (!task) return res.status(400).json({ message: 'Task required' });

    const newTodo = {
        id: todoIdCounter++,
        task,
        userId: req.user.id
    };
    todos.push(newTodo);
    res.json(newTodo);
});

// Delete todo (only if owner)
app.delete('/api/todos/:id', authenticate, (req, res) => {
    const todoId = parseInt(req.params.id);
    const todo = todos.find(t => t.id === todoId);
    if (!todo) return res.status(404).json({ message: 'Todo not found' });

    if (todo.userId !== req.user.id) {
        return res.status(403).json({ message: 'You can only delete your own todos' });
    }

    todos = todos.filter(t => t.id !== todoId);
    res.json({ message: 'Todo deleted' });
});
app.get('/api/admin/all-todos', authenticate, authorizeAdmin, (req, res) => {
    res.json(todos);
});
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
