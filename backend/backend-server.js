  // Allowed file types
  const multer = require('multer');
  const jwt = require('jsonwebtoken');
 const SECRET_KEY = process.env.JWT_SECRET; // (you can change later)
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
  const userSchema = new mongoose.Schema({
    email: {
      type: String,
      required: true,
      unique: true
    },
    password: {
      type: String,
      required: true
    }
  });
  const User = mongoose.model('User', userSchema);
  app.post('/api/signup', async (req, res) => {
    try {
      console.log("Request body:", req.body); // 👈 ADD THIS

      const { email, password } = req.body;

      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: "User already exists" });
      }

      const hash = await bcrypt.hash(password, 10);

      const user = new User({ email, password: hash });
      await user.save();

      res.json({ message: "Signup successful" });

    } catch (error) {
      console.error("Signup error:", error); // 👈 ADD THIS
      res.status(500).json({ error: "Internal server error" });
    }
  });
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
  function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];

    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      req.user = decoded;
      next();
    } catch (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
  }

  app.get('/api/files', verifyToken, async (req, res) => {
    const userEmail = req.user.email;

    try {
      const files = await File.find({ email: userEmail })
        .select('filename originalname contentType uploadDate');

      res.json(files);
    } catch (error) {
      res.status(500).json({ error: 'Failed to list files' });
    }
  });
  app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'User not found' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ email: user.email }, SECRET_KEY, {
    expiresIn: '1h'
  });

  res.json({
    message: 'Login successful',
    token: token
  });
  });
  const crypto = require('crypto'); // Add this import
  app.post('/api/upload', verifyToken, upload.single('file'), async (req, res) => {
    const userEmail = req.user.email;

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    try {
      const hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');

      const existing = await File.findOne({ fileHash: hash, email: userEmail });
      if (existing) {
        return res.status(409).json({ error: 'Duplicate file detected.' });
      }

      const file = new File({
        filename: req.file.originalname,
        originalname: req.file.originalname,
        email: userEmail,
        data: req.file.buffer,
        contentType: req.file.mimetype,
        fileHash: hash
      });

      await file.save();
      res.json({ message: 'File uploaded successfully!' });

    } catch (err) {
      res.status(500).json({ error: 'Error saving file' });
    }
  });
  // API to list files metadata without data buffer

  const sharp = require('sharp');

  app.get('/api/file/:id', verifyToken, async (req, res) => {
    try {
      const userEmail = req.user.email;

      const file = await File.findOne({      
        _id: req.params.id,
        email: userEmail
      });

      if (!file) {
        return res.status(403).send('Access denied');
      }

      res.setHeader('Content-Type', file.contentType);
      res.send(file.data);

    } catch (err) {
      res.status(500).send('Error serving file');
    }
  });

  app.delete('/api/files/:id', verifyToken, async (req, res) => {
    const fileId = req.params.id;
    const userEmail = req.user.email;

    try {
      const file = await File.findById(fileId);

      if (!file || file.email !== userEmail) {
        return res.status(403).json({ error: 'Unauthorized' });
      }

      await File.findByIdAndDelete(fileId);
      res.json({ message: 'File deleted successfully' });

    } catch (err) {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // your routes above...

  app.get('/', (req, res) => {
    res.send('Server is running successfully 🚀');
  });
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB Connected");

    app.listen(5001, () => {
      console.log("🚀 Server running on port 5000");
    });

  })
  .catch(err => {
    console.log("❌ MongoDB Error:", err);
  });
  
