const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

const secretKey = "your_secret_key";

// In-memory user storage for simplicity (replace with DB)
const users = [];
const games = [];

// Middleware to parse JSON
app.use(express.json());

// Register Route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.status(201).send({ message: 'User registered' });
});

// Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).send({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ username }, secretKey);
    res.send({ token });
});

// Middleware to authenticate JWT
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Protected route to get player profile
app.get('/profile', authenticateToken, (req, res) => {
    const user = users.find(u => u.username === req.user.username);
    res.send({ username: user.username });
});

// WebSocket Connection
io.on('connection', (socket) => {
    console.log('A player connected.');

    // Handle player matchmaking
    socket.on('findGame', () => {
        if (games.length > 0) {
            const game = games.pop(); // Pair with an existing game
            game.player2 = socket.id;
            io.to(game.player1).emit('startGame', { opponent: 'Player 2' });
            io.to(game.player2).emit('startGame', { opponent: 'Player 1' });
        } else {
            games.push({ player1: socket.id });
        }
    });

    // Handle real-time game moves
    socket.on('gameMove', (data) => {
        // Broadcast moves to opponent
        const opponent = games.find(g => g.player1 === socket.id || g.player2 === socket.id);
        const opponentId = opponent.player1 === socket.id ? opponent.player2 : opponent.player1;
        io.to(opponentId).emit('receiveMove', data);
    });

    socket.on('disconnect', () => {
        console.log('A player disconnected.');
    });
});

// Start the server
server.listen(3000, () => {
    console.log('Server is running on port 3000');
});
