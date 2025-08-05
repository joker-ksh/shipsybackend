const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

//–– Middleware
const corsOptions = {
  origin: '*', // allow all origins
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));

app.use(express.json());

//–– MongoDB Connection
const mongoUri = process.env.MONGODB_URI;
if (!mongoUri) {
  console.error('❌ MONGODB_URI not set in .env');
  process.exit(1);
}

mongoose.connect(mongoUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(async () => {
  console.log('✅ Connected to MongoDB');

  // 👉 Drop email_1 index if it exists to avoid duplicate key error
  try {
    const indexes = await mongoose.connection.db.collection('users').indexes();
    const emailIndex = indexes.find(i => i.name === 'email_1');

    if (emailIndex) {
      console.log('⚠️ Dropping email_1 index to prevent duplicate key error...');
      await mongoose.connection.db.collection('users').dropIndex('email_1');
      console.log('✅ Dropped email_1 index successfully.');
    }
  } catch (err) {
    console.error('❌ Failed to drop email_1 index:', err.message);
  }
})
.catch(err => {
  console.error('❌ MongoDB connection error:', err.message);
  process.exit(1);
});

//–– Schemas & Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

const taskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  status: {
    type: String,
    enum: ['pending', 'in-progress', 'completed', 'cancelled'],
    default: 'pending'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  isUrgent: { type: Boolean, default: false },
  dueDate: { type: Date },
  createdAt: { type: Date, default: Date.now },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});
const Task = mongoose.model('Task', taskSchema);

//–– Utility wrapper for async routes
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

//–– JWT verification middleware
const verifyToken = wrap(async (req, res, next) => {
  const header = req.header('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const { userId } = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = userId;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
});

//–– Auth Routes

// Register
app.post('/api/auth/register', wrap(async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'Username and password required' });

  if (await User.exists({ username }))
    return res.status(400).json({ message: 'Username already taken' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await User.create({ username, password: hashedPassword });

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });

  res.status(201).json({
    message: 'Registered successfully',
    token,
    user: { id: user._id, username: user.username }
  });
}));

// Login
app.post('/api/auth/login', wrap(async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(400).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });

  res.json({
    message: 'Login successful',
    token,
    user: { id: user._id, username: user.username }
  });
}));

// Logout (stateless)
app.post('/api/auth/logout', verifyToken, (req, res) => {
  res.json({ message: 'Logout successful' });
});

//–– Task CRUD
app.post('/api/tasks', verifyToken, wrap(async (req, res) => {
  const task = await Task.create({ ...req.body, userId: req.userId });
  res.status(201).json(task);
}));

app.get('/api/tasks', verifyToken, wrap(async (req, res) => {
  const { page = 1, limit = 10, status, priority, isUrgent, search } = req.query;
  const filter = { userId: req.userId };

  if (status) filter.status = status;
  if (priority) filter.priority = priority;
  if (isUrgent !== undefined) filter.isUrgent = isUrgent === 'true';
  if (search) {
    filter.$or = [
      { title: { $regex: search, $options: 'i' } },
      { description: { $regex: search, $options: 'i' } }
    ];
  }

  const skip = (page - 1) * limit;
  const [tasks, total] = await Promise.all([
    Task.find(filter).sort({ createdAt: -1 }).skip(skip).limit(+limit),
    Task.countDocuments(filter)
  ]);

  res.json({
    tasks,
    currentPage: +page,
    totalPages: Math.ceil(total / limit),
    totalTasks: total
  });
}));

app.get('/api/tasks/:id', verifyToken, wrap(async (req, res) => {
  const task = await Task.findOne({ _id: req.params.id, userId: req.userId });
  if (!task) return res.status(404).json({ message: 'Task not found' });
  res.json(task);
}));

app.put('/api/tasks/:id', verifyToken, wrap(async (req, res) => {
  const task = await Task.findOneAndUpdate(
    { _id: req.params.id, userId: req.userId },
    req.body,
    { new: true, runValidators: true }
  );
  if (!task) return res.status(404).json({ message: 'Task not found' });
  res.json(task);
}));

app.delete('/api/tasks/:id', verifyToken, wrap(async (req, res) => {
  const task = await Task.findOneAndDelete({ _id: req.params.id, userId: req.userId });
  if (!task) return res.status(404).json({ message: 'Task not found' });
  res.json({ message: 'Task deleted' });
}));

//–– Global error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: 'Server error', details: err.message });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
