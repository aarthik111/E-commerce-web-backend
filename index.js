require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");

const app = express();
const port = process.env.PORT || 4000;

// ✅ CORS: Allow frontend + admin URLs
app.use(cors({
  origin: [
    'https://e-commerce-web-frontend-hs4r.onrender.com',
    'https://e-commerce-web-admin-e9pb.onrender.com'
  ],
  credentials: true
}));
app.options('*', cors()); // For preflight requests

app.use(express.json());

// ✅ MongoDB connection
mongoose.connect(process.env.MONGODB_URI);

// ✅ Email transporter using Brevo
const transporter = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
  tls: {
    rejectUnauthorized: false
  }
});

const otpStore = new Map();

// ✅ Image Uploads (⚠️ Render storage is not persistent!)
const storage = multer.diskStorage({
  destination: './upload/images',
  filename: (req, file, cb) => {
    cb(null, `${file.fieldname}_${Date.now()}${path.extname(file.originalname)}`);
  }
});
const upload = multer({ storage });
app.use('/images', express.static('upload/images'));

app.post("/upload", upload.single('product'), (req, res) => {
  const host = req.protocol + '://' + req.get('host');
  res.json({
    success: 1,
    image_url: `${host}/images/${req.file.filename}`
  });
});

// ✅ MongoDB Schemas
const Product = mongoose.model("Product", {
  id: Number,
  name: String,
  image: String,
  category: String,
  new_price: Number,
  old_price: Number,
  date: { type: Date, default: Date.now },
  available: { type: Boolean, default: true }
});

const Users = mongoose.model("Users", {
  name: String,
  email: { type: String, unique: true },
  password: String,
  cartData: Object,
  date: { type: Date, default: Date.now }
});

// ✅ Send OTP
app.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 5 * 60 * 1000;
  otpStore.set(email, { otp, expiresAt });

  try {
    await transporter.sendMail({
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: 'OTP Verification',
      text: `Your OTP is ${otp}`
    });
    res.json({ success: true, message: "OTP sent to email" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
});

// ✅ Verify OTP & Signup
app.post('/verify-otp-signup', async (req, res) => {
  const { name, email, password, otp } = req.body;
  const otpData = otpStore.get(email);

  if (!otpData || otpData.otp !== otp || Date.now() > otpData.expiresAt) {
    return res.status(400).json({ success: false, message: "Invalid or expired OTP" });
  }

  const existingUser = await Users.findOne({ email });
  if (existingUser) return res.status(400).json({ success: false, message: "User already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);
  const cart = {}; for (let i = 0; i < 300; i++) cart[i] = 0;

  const user = new Users({ name, email, password: hashedPassword, cartData: cart });
  await user.save();
  otpStore.delete(email);

  const token = jwt.sign({ user: { id: user._id } }, process.env.JWT_SECRET);
  res.json({ success: true, token });
});

// ✅ Login
app.post('/login', async (req, res) => {
  const user = await Users.findOne({ email: req.body.email });
  if (!user) return res.json({ success: false, errors: "Wrong Email Id" });

  const isMatch = await bcrypt.compare(req.body.password, user.password);
  if (!isMatch) return res.json({ success: false, error: "Wrong Password" });

  const token = jwt.sign({ user: { id: user._id } }, process.env.JWT_SECRET);
  res.json({ success: true, token });
});

// ✅ Forgot Password
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await Users.findOne({ email });
  if (!user) return res.json({ success: false, message: "Email not registered" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
  const resetLink = `https://e-commerce-web-frontend-hs4r.onrender.com/reset-password/${token}`;

  try {
    await transporter.sendMail({
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Reset your password",
      html: `<p>Click the link to reset your password:</p><a href="${resetLink}">${resetLink}</a>`
    });
    res.json({ success: true, message: "Reset link sent to email." });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to send email." });
  }
});

// ✅ Reset Password
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await Users.findById(decoded.id);
    if (!user) return res.status(400).json({ success: false, message: "User not found" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    res.status(400).json({ success: false, message: "Invalid or expired token" });
  }
});

// ✅ Auth Middleware
const fetchUser = async (req, res, next) => {
  const token = req.header('auth-token');
  if (!token) return res.status(401).send({ errors: "Please authenticate using a valid token" });

  try {
    const data = jwt.verify(token, process.env.JWT_SECRET);
    req.user = data.user;
    next();
  } catch (error) {
    return res.status(401).send({ errors: "Invalid token" });
  }
};

// ✅ Product Routes
app.post('/addproduct', async (req, res) => {
  const products = await Product.find({});
  const id = products.length > 0 ? products[products.length - 1].id + 1 : 1;

  const product = new Product({ id, ...req.body });
  await product.save();
  res.json({ success: true, name: req.body.name });
});

app.post('/removeproduct', async (req, res) => {
  await Product.findOneAndDelete({ id: req.body.id });
  res.json({ success: true });
});

app.get('/allproducts', async (req, res) => {
  const products = await Product.find({});
  res.json(products);
});

app.get('/newcollections', async (req, res) => {
  const products = await Product.find({});
  const newcollection = products.slice(1).slice(-8);
  res.send(newcollection);
});

app.get('/popularinwomen', async (req, res) => {
  const products = await Product.find({ category: "women" });
  const popular = products.slice(0, 4);
  res.send(popular);
});

// ✅ Cart Routes
app.post('/addtocart', fetchUser, async (req, res) => {
  const userData = await Users.findById(req.user.id);
  userData.cartData[req.body.itemId] += 1;
  await Users.findByIdAndUpdate(req.user.id, { cartData: userData.cartData });
  res.json({ success: true });
});

app.post('/removefromcart', fetchUser, async (req, res) => {
  const userData = await Users.findById(req.user.id);
  if (userData.cartData[req.body.itemId] > 0)
    userData.cartData[req.body.itemId] -= 1;
  await Users.findByIdAndUpdate(req.user.id, { cartData: userData.cartData });
  res.json({ success: true });
});

app.post('/getcart', fetchUser, async (req, res) => {
  const userData = await Users.findById(req.user.id);
  res.json(userData.cartData);
});

// ✅ Start server
app.listen(port, () => {
  console.log(`✅ Server running on http://localhost:${port}`);
});
