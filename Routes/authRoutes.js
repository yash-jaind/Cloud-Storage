const multer = require('multer');
const upload = multer({ dest: 'uploads/' }); // creates 'uploads/' folder if not present

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const app = express();
const cors = require('cors');
app.use(cors());
app.use(express.json());


mongoose.connect('mongodb://localhost:27017/dsa')
  .then(() => console.log("Connected to MongoDB (dsa)"))
  .catch(err => console.error("MongoDB connection error:", err));
const userSchema = new mongoose.Schema({
    email: String,
    password: String
});
const User = mongoose.model('User', userSchema);

app.post('/api/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }
    const hash = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hash });
    await user.save();
    res.json({ message: 'Signup successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'User not found' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Wrong password' });
    res.json({ message: 'Login successful' });
});

app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  res.json({ message: 'File uploaded successfully!' });
});
app.listen(5000, () => console.log('Server running on http://localhost:5000'));


