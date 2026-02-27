
// Allowed file types
const multer = require('multer');

// 👇 PUT IT HERE
const allowedTypes = [
  'application/pdf',
  'image/jpeg',
  'image/png',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
];

const storage = multer.memoryStorage();

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported file type. Only PDF, JPG, PNG, DOCX allowed.'));
    }
  }
});
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const app = express();
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

const fileSchema = new mongoose.Schema({
  filename: String,
  originalname: String,
  email: String,
  data: Buffer,          // Store file binary data here
  contentType: String,   // Store file MIME type
  uploadDate: { type: Date, default: Date.now },
   fileHash: String // Add this line!
});
const File = mongoose.model('File', fileSchema);



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
 res.json({ message: 'Login successful', email: email });
});
const crypto = require('crypto'); // Add this import
app.post('/api/upload', upload.single('file'), async (req, res) => {
  const { userEmail } = req.body;
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  try {
    // Create hash from file buffer
    const hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
    
    // Check if file with same hash already exists for this user
    const existing = await File.findOne({ fileHash: hash, email: userEmail });
    if (existing) {
      return res.status(409).json({ error: 'Duplicate file detected. This file already exists.' });
    }


    const file = new File({
      filename: req.file.originalname,
      originalname: req.file.originalname,
      email: userEmail,
      data: req.file.buffer,
      contentType: req.file.mimetype,
      fileHash: hash // Save hash in document
    });
    await file.save();
    res.json({ message: 'File uploaded and saved to DB!' });
  } catch (err) {
    res.status(500).json({ error: 'Error saving file info' });
  }
});


// API to list files metadata without data buffer
app.get('/api/files', async (req, res) => {
  const userEmail = req.query.email;
  if (!userEmail) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const files = await File.find({ email: userEmail })
      .select('filename originalname contentType uploadDate');
    res.json(files);
  } 
   catch (error) {  
    res.status(500).json({ error: 'Failed to list files' });
  } 
});

const sharp = require('sharp');

app.get('/api/file/:id', async (req, res) => {
  try {

    const userEmail = req.query.email;

    // Step 1: user must send email
    if (!userEmail) {
      return res.status(401).send('Unauthorized');
    }

    // Step 2: file must belong to that user
    const file = await File.findOne({
      _id: req.params.id,
      email: userEmail
    });

    if (!file) {
      return res.status(403).send('Access denied');
    }

    const isDownload = req.query.download === '1';

    res.setHeader('Content-Type', file.contentType);

    if (isDownload) {
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${file.originalname}"`
      );
    } else {
      res.setHeader(
        'Content-Disposition',
        `inline; filename="${file.originalname}"`
      );
    }

    res.send(file.data);

  } catch (err) {
    console.error(err);
    res.status(500).send('Error serving file');
  }
});




app.delete('/api/files/:id', async (req, res) => {
  const fileId = req.params.id;
  const userEmail = req.query.email;

  try {
    const file = await File.findById(fileId);
    if (!file) return res.status(404).json({ error: 'File not found' });

    // 🔐 ACCESS CONTROL
    if (!userEmail || file.email !== userEmail) {
      return res.status(403).json({ error: 'Unauthorized delete attempt' });
    }

    await File.findByIdAndDelete(fileId);

    res.json({ message: 'File deleted successfully' });

  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});
// Handle multer file type errors properly
app.use((err, req, res, next) => {

  // FILE SIZE LIMIT ERROR
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({
      error: 'File size exceeds 10MB limit.'
    });
  }

  // FILE TYPE ERROR
  if (err.message && err.message.includes('Unsupported file type')) {
    return res.status(400).json({
      error: err.message
    });
  }

  // OTHER ERRORS
  console.error(err);
  res.status(500).json({ error: 'Server error occurred' });
});
app.listen(5000, '0.0.0.0', () => {
  console.log('Server running on network');
});
