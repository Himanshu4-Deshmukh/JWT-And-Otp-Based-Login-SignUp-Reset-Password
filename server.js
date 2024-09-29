const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

 
const app = express();
app.use(express.json());  

// MongoDB 
mongoose.connect('mongodb://localhost:27017/jwt-auth', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error(err));

// User Schema and Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// JWTSecretKey
const JWT_SECRET = 'secret'; 

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1]; // Extract token from Authorization header
  if (!token) return res.status(401).json({ message: 'Access Denied. No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Signup 
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ username });
  if (existingUser) return res.status(400).json({ message: 'Username already taken' });

  // Hash the password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Create a new user
  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();

  res.json({ message: 'User registered successfully' });
});

// Login 
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Find user by username
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ message: 'Invalid username or password' });

  // Verify password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(400).json({ message: 'Invalid username or password' });

  // Generate JWT
  const token = jwt.sign({ _id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

  res.json({ token }); // Return the JWT token
});

// dashboard
app.get('/dashboard', authenticateToken, (req, res) => {
  res.json({ message: `Welcome, ${req.user.username}! This is a protected Dashboard.` });
});

app.get('/', (req, res) => {
  res.send('Himanshu Deshmukh');
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
