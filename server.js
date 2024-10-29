require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error(err));

// User Schema with email and OTP details
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  otp: { type: String },
  otpExpires: { type: Date },
});

const User = mongoose.model('User', userSchema);

// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access Denied. No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Swagger setup
const swaggerDocument = YAML.load('./swagger.yaml');
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Nodemailer transporter configuration
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

 
// Signup route with OTP
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
  
    try {
      const existingUser = await User.findOne({ $or: [{ username }, { email }] });
      if (existingUser) {
        return res.status(400).json({ 
          message: existingUser.username === username 
            ? 'Username already taken' 
            : 'Email already registered' 
        });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
      const otp = crypto.randomInt(100000, 999999).toString();
      const otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  
      const newUser = new User({ username, email, password: hashedPassword, otp, otpExpires });
      await newUser.save();
  
      const mailOptions = {
        from: process.env.SMTP_USER,
        to: email,
        subject: 'Verify Your Account',
        text: `Your OTP is ${otp}. It expires in 10 minutes.`,
      };
  
      transporter.sendMail(mailOptions, (error) => {
        if (error) return res.status(500).json({ message: 'Error sending email', error });
        res.json({ message: 'OTP sent to email. Please verify.' });
      });
    } catch (error) {
      res.status(500).json({ message: 'Signup failed', error });
    }
  });
  
  // Verify OTP
  app.post('/verify-otp', async (req, res) => {
    const { otp, email } = req.body;
  
    try {
      const user = await User.findOne({ email });
  
      if (!user) return res.status(400).json({ message: 'User not found.' });
  
      if (user.otp === otp && user.otpExpires > Date.now()) {
        user.isVerified = true;
        user.otp = null;
        user.otpExpires = null;
        await user.save();
  
        res.json({ message: 'OTP verified. Account activated.' });
      } else {
        res.status(400).json({ message: 'Invalid or expired OTP.' });
      }
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
  });
  


// Login route with email or username
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ $or: [{ username }, { email: username }] });
    if (!user) return res.status(400).json({ message: 'Invalid username/email or password' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).json({ message: 'Invalid username/email or password' });

    const token = jwt.sign({ _id: user._id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Login error', error: error.message });
  }
});

// Dashboard route
app.get('/dashboard', authenticateToken, (req, res) => {
  res.json({
    username: req.user.username,
    email: req.user.email,
    message: `Welcome to the Dashboard`,
  });
});

// Request OTP for password reset
app.post('/request-otp', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpires = Date.now() + 600000;

    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();

    const mailOptions = {
      from: process.env.SMTP_USER,
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is: ${otp}. It expires in 10 minutes.`,
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) return res.status(500).json({ message: 'Error sending OTP email', error: err.message });
      res.json({ message: 'OTP sent to your email' });
    });
  } catch (error) {
    res.status(500).json({ message: 'Error processing request', error: error.message });
  }
});

// Password reset with OTP verification
app.post('/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const user = await User.findOne({ email, otp, otpExpires: { $gt: Date.now() } });
    if (!user) return res.status(400).json({ message: 'Invalid or expired OTP' });

    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.json({ message: 'Password has been reset successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error resetting password', error: error.message });
  }
});

// Base route
app.get('/', (req, res) => {
  res.send('Himanshu Deshmukh');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
