require('dotenv').config(); // Load environment variables

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const nodemailer = require('nodemailer'); 
const crypto = require('crypto'); 

const app = express();
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error(err));

// User Schema and Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },  
  password: { type: String, required: true },
  otp: { type: String },
  otpExpires: { type: Date },
});

const User = mongoose.model('User', userSchema);

// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET;

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

// Swagger setup using the YAML file
const swaggerDocument = YAML.load('./swagger.yaml');
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Configure Nodemailer with provided SMTP credentials
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, 
  auth: {
    user: process.env.SMTP_USER, 
    pass: process.env.SMTP_PASS, 
  },
});

app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  const existingUser = await User.findOne({ username });
  if (existingUser) return res.status(400).json({ message: 'Username already taken' });

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();

  res.json({ message: 'User registered successfully' });
});


app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ message: 'Invalid username or password' });

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(400).json({ message: 'Invalid username or password' });

  const token = jwt.sign({ _id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

  res.json({ token });
});


app.get('/dashboard', authenticateToken, (req, res) => {
  res.json({ message: `Welcome, ${req.user.username}! This is a protected Dashboard.` });
});

// Request OTP for Password Reset
app.post('/request-otp', async (req, res) => {
  const { username } = req.body; // Username is treated as email

  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ message: 'User not found' });

  // Generate a 6-digit OTP
  const otp = crypto.randomInt(100000, 999999).toString();

  // Set OTP expiration (10 minutes)
  const otpExpires = Date.now() + 600000; // 10 minutes

  // Update user with the OTP and expiration
  user.otp = otp;
  user.otpExpires = otpExpires;
  await user.save();

  // Send OTP to user's email
  const mailOptions = {
    from: process.env.SMTP_USER,  
    to: user.username,  
    subject: 'Password Reset OTP',
    text: `Your OTP for password reset is: ${otp}. It expires in 10 minutes.`,
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) return res.status(500).json({ message: 'Error sending email', error: err });
    res.json({ message: 'OTP sent to your email' });
  });
});

// Verify OTP and Reset Password
app.post('/reset-password', async (req, res) => {
  const { username, otp, newPassword } = req.body;

  const user = await User.findOne({ username, otp, otpExpires: { $gt: Date.now() } });
  if (!user) return res.status(400).json({ message: 'Invalid or expired OTP' });

  // Hash the new password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(newPassword, salt);

  // Update the user's password and clear the OTP
  user.password = hashedPassword;
  user.otp = undefined;
  user.otpExpires = undefined;
  await user.save();

  res.json({ message: 'Password has been reset successfully' });
});

 
app.get('/', (req, res) => {
  res.send('Himanshu Deshmukh');
});

 
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
