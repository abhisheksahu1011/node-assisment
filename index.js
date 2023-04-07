const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const env = require('dotenv').config();

const app = express();
const port = 3000;

// Connect to MongoDB
mongoose.connect(env, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Failed to connect to MongoDB', err));

// Define student schema and model
const studentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const Student = mongoose.model('Student', studentSchema);

// Middleware for parsing JSON body
app.use(bodyParser.json());

// Middleware for authenticating JWT tokens
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    req.studentId = decoded.studentId;
    next();
  });
};

// CRUD routes for students
app.get('/students', auth, async (req, res) => {
  const students = await Student.find().select('-password');
  res.json(students);
});

app.get('/students/:id', auth, async (req, res) => {
  const student = await Student.findById(req.params.id).select('-password');
  if (!student) return res.status(404).json({ message: 'Student not found' });
  res.json(student);
});

app.post('/students', async (req, res) => {
  const { name, email, password } = req.body;
  const existingStudent = await Student.findOne({ email });
  if (existingStudent) return res.status(409).json({ message: 'Email already registered' });
  const hashedPassword = await bcrypt.hash(password, 10);
  const student = new Student({ name, email, password: hashedPassword });
  await student.save();
  const token = jwt.sign({ studentId: student._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
  res.json({ token });
});

app.put('/students/:id', auth, async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const student = await Student.findByIdAndUpdate(req.params.id, { name, email, password: hashedPassword }, { new: true });
  if (!student) return res.status(404).json({ message: 'Student not found'});
});

app.listen(port,()=>{
  console.log(`connect to port ${port}`);
})
