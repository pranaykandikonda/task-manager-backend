const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const dbPath = path.join(__dirname, 'tasks.db');
const SECRET_KEY = 'pranay';
const db = new sqlite3.Database(dbPath);
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Authorization token required' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};


// SQL QUERIES //
const CREATE_USERS_TABLE = `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )`;

const CREATE_TASKS_TABLE = `
  CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'pending',
    category TEXT,
    priority TEXT DEFAULT 'medium',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    due_date DATETIME,
    user_id INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`;

const REGISTER_USER = `
  INSERT INTO users (email, password) 
  VALUES (?, ?)`;

const FIND_USER_BY_EMAIL = `
  SELECT * FROM users 
  WHERE email = ?`;

const CREATE_TASK = `
  INSERT INTO tasks 
    (title, description, category, priority, due_date, user_id) 
  VALUES (?, ?, ?, ?, ?, ?)`;

const GET_USER_TASKS = `
  SELECT * FROM tasks 
  WHERE user_id = ?`;

const GET_FILTERED_TASKS = `
  SELECT * FROM tasks 
  WHERE user_id = ? 
    AND (category = ? OR ? IS NULL) 
    AND (status = ? OR ? IS NULL) 
    AND title LIKE ?
  `;

const UPDATE_TASK = `
  UPDATE tasks SET 
    title = COALESCE(?, title), 
    description = COALESCE(?, description),
    status = COALESCE(?, status),
    category = COALESCE(?, category),
    due_date = COALESCE(?, due_date),
    priority = COALESCE(?, priority)
  WHERE id = ? AND user_id = ?`;

const DELETE_TASK = `
  DELETE FROM tasks 
  WHERE id = ? AND user_id = ?`;

const GET_STATS = `
  SELECT 
    COUNT(*) as total,
    SUM(status = 'completed') as completed,
    SUM(status = 'pending') as pending,
    category,
    COUNT(category) as category_count
  FROM tasks 
  WHERE user_id = ?
  GROUP BY category`;

const GET_PRIORITY_STATS = `
  SELECT 
    priority,
    COUNT(*) as count 
  FROM tasks 
  WHERE user_id = ?
  GROUP BY priority`;

// INITIALIZE DB //
db.serialize(() => {
  db.run(CREATE_USERS_TABLE);
  db.run(CREATE_TASKS_TABLE);
});

// API ENDPOINTS //
// Register API REQUEST
app.post('/api/register', async (request, response) => {
  try {
    const { email, password, confirmPassword } = request.body;
    
    if (password !== confirmPassword) {
      return response.status(400).json({ error: "Passwords don't match" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(REGISTER_USER, [email, hashedPassword], function(err) {
      if (err) {
        return response.status(400).json({ error: 'Email already exists' });
      }
      response.status(201).json({ id: this.lastID });
    });
  } catch (error) {
    response.status(500).json({ error: 'Registration failed' });
  }
});

// Login API REQUEST
app.post('/api/login', (request, response) => {
  const { email, password } = request.body;
  
  db.get(FIND_USER_BY_EMAIL, [email], async (err, user) => {
    if (err || !user || !(await bcrypt.compare(password, user.password))) {
      return response.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: user.id, email: user.email }, 
      SECRET_KEY, 
      { expiresIn: '1h' }
    );
    
    response.json({ token, userId: user.id });
  });
});

// GET Tasks API REQUEST
app.get('/api/tasks', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { search = '', category, status } = req.query;
  const cat = category || null;
  const stat = status || null;

  db.all(
    GET_FILTERED_TASKS,
    [userId, cat, cat, stat, stat, `%${search}%`],
    (err, tasks) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Failed to fetch tasks' });
      }
      res.json(tasks);
    }
  );
});



// Create Task API REQUEST
app.post('/api/tasks', authenticateToken, (request, response) => {
  const { title, description, category, priority, dueDate } = request.body;
  const userId = request.user.id;

  const taskDueDate = dueDate ? dueDate : null;

  console.log('Request Body:', { title, description, category, priority, dueDate: taskDueDate, userId });

  db.run(
    CREATE_TASK,
    [title, description, category, priority, taskDueDate, userId],
    function(err) {
      if (err) {
        console.error('Task creation error:', err);
        return response.status(500).json({ error: 'Task creation failed' });
      }
      response.status(201).json({
        id: this.lastID,
        message: 'Task created successfully'
      });
    }
  );
});

app.get('/api/tasks/:id', authenticateToken, (request, response) => {
  const userId = request.user.id;
  const taskId = request.params.id;

  const GET_SINGLE_TASK = `SELECT * FROM tasks WHERE id = ? AND user_id = ?`;
  
  db.get(GET_SINGLE_TASK, [taskId, userId], (err, task) => {
    if (err) {
      console.error('Error fetching task:', err);
      return response.status(500).json({ error: 'Failed to fetch task' });
    }
    if (!task) {
      return response.status(404).json({ error: 'Task not found' });
    }
    response.json(task);
  });
});


// Update Task API REQUEST
app.put('/api/tasks/:id', authenticateToken, (request, response) => {
  const taskId = request.params.id;
  const userId = request.user.id;
  const { title, description, status, category, priority, due_date } = request.body;

  db.run(
    UPDATE_TASK,
    [
      title, 
      description, 
      status, 
      category, 
      due_date,
      priority, 
      taskId, 
      userId
    ],
    function(err) {
      if (err) {
        console.error('Update error:', err);
        return response.status(500).json({ error: 'Update failed' });
      }
      if (this.changes === 0) {
        return response.status(404).json({ error: 'Task not found' });
      }
      response.json({ message: 'Task updated successfully' });
    }
  );
});


//DELETE Task API REQUEST
app.delete('/api/tasks/:id', authenticateToken, (request, response) => {
  const taskId = request.params.id;
  const userId = request.user.id;

  db.run(DELETE_TASK, [taskId, userId], function(err) {
    if (err) return response.status(500).json({error: 'Delete failed'});
    if (this.changes === 0) return response.status(404).json({error: 'Task not found'});
    response.status(204).send();
  });
});

//GET Dashboard Stats
app.get('/api/stats', authenticateToken, (request, response) => {
  const userId = request.user.id;

  db.all(GET_STATS, [userId], (err, stats) => {
    if (err) return response.status(500).send('Failed to get stats');
    response.json(stats);
  });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

//Testing Server
app.get('/api/test', (req, res) => {
  res.json({ message: "Server is working!", timestamp: new Date() });
});

//For testing purpose
app.get('/api/users', (req, res) => {
  db.all("SELECT id, email FROM users", (err, rows) => {
    if(err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Database file: ${dbPath}`);
});