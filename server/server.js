const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');  // <-- Only keep this one
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = 3000;

// Environment configuration
require('dotenv').config();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// Serve login.html at root
app.get('/', (req, res) => {
  const filePath = path.join(__dirname, '..', 'frontend', 'login.html');
  res.sendFile(filePath, (err) => {
    if (err) {
      console.error('Error serving login.html:', err);
      res.status(500).send('Error loading login page');
    }
  });
});


// MySQL connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'sales_playbook',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-strong-secret-key';
const JWT_EXPIRES_IN = '1h';

// ----------- AUTHENTICATION -------------
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    // Get user from database
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = users[0];
    
    // Use bcrypt for password comparison
    const passwordMatch = await bcrypt.compare(password, user.password);
    // Switch back to bcrypt for production:
    // const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create JWT token
    const token = jwt.sign(
      { userId: user.user_id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    
    // Return user data (without password) and token
    const { password: _, ...userData } = user;
    res.json({ user: userData, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during authentication' });
  }
});

// Authentication middleware
const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Authorization middleware for admin only
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};



// ----------- PROTECTED ROUTES -------------
// Users routes (admin only)
app.get('/api/users', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT user_id, name, email, role FROM users WHERE role != "admin"');
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ... [Include all your other existing routes with authentication middleware] ...
app.get('/api/users/:id', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT user_id, name, email, role FROM users WHERE user_id = ?', [req.params.id]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(users[0]);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

app.post('/api/users', authenticate, authorizeAdmin, async (req, res) => {
  const { name, email, password, role } = req.body;
  
  if (!name || !email || !password || !role) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  if (!['admin', 'sales_rep'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  try {
    // Check if email exists
    const [existingUsers] = await pool.query('SELECT user_id FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Insert user
    const [result] = await pool.query(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name, email, hashedPassword, role]
    );
    
    // Fetch the newly created user
    const [newUser] = await pool.query('SELECT user_id, name, email, role FROM users WHERE user_id = ?', [result.insertId]);
    res.status(201).json(newUser[0]);
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.put('/api/users/:id', authenticate, authorizeAdmin, async (req, res) => {
  const { name, email, password, role } = req.body;
  
  if (!name || !email || !role) {
    return res.status(400).json({ error: 'Name, email, and role are required' });
  }
  
  if (!['admin', 'sales_rep'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  
  try {
    // Check if user exists
    const [users] = await pool.query('SELECT user_id FROM users WHERE user_id = ?', [req.params.id]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if email is taken by another user
    const [existingUsers] = await pool.query('SELECT user_id FROM users WHERE email = ? AND user_id != ?', [email, req.params.id]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    
    // Prepare update query
    let query = 'UPDATE users SET name = ?, email = ?, role = ?';
    const params = [name, email, role];
    
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      query += ', password = ?';
      params.push(hashedPassword);
    }
    
    query += ' WHERE user_id = ?';
    params.push(req.params.id);
    
    // Update user
    await pool.query(query, params);
    
    // Fetch updated user
    const [updatedUser] = await pool.query('SELECT user_id, name, email, role FROM users WHERE user_id = ?', [req.params.id]);
    res.json(updatedUser[0]);
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.delete('/api/users/:id', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM users WHERE user_id = ?', [req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(204).send();
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Industries routes
app.get('/api/industries', authenticate, async (req, res) => {
  try {
    const [industries] = await pool.query('SELECT industry_id, industry_name FROM industries');
    res.json(industries);
  } catch (err) {
    console.error('Error fetching industries:', err);
    res.status(500).json({ error: 'Failed to fetch industries' });
  }
});

app.get('/api/industries/:id', authenticate, async (req, res) => {
  try {
    const [industries] = await pool.query('SELECT industry_id, industry_name FROM industries WHERE industry_id = ?', [req.params.id]);
    if (industries.length === 0) {
      return res.status(404).json({ error: 'Industry not found' });
    }
    res.json(industries[0]);
  } catch (err) {
    console.error('Error fetching industry:', err);
    res.status(500).json({ error: 'Failed to fetch industry' });
  }
});

app.post('/api/industries', authenticate, authorizeAdmin, async (req, res) => {
  const { industry_name } = req.body;
  
  if (!industry_name) {
    return res.status(400).json({ error: 'Industry name is required' });
  }
  
  try {
    const [result] = await pool.query('INSERT INTO industries (industry_name) VALUES (?)', [industry_name]);
    const [newIndustry] = await pool.query('SELECT industry_id, industry_name FROM industries WHERE industry_id = ?', [result.insertId]);
    res.status(201).json(newIndustry[0]);
  } catch (err) {
    console.error('Error creating industry:', err);
    res.status(500).json({ error: 'Failed to create industry' });
  }
});

app.put('/api/industries/:id', authenticate, authorizeAdmin, async (req, res) => {
  const { industry_name } = req.body;
  
  if (!industry_name) {
    return res.status(400).json({ error: 'Industry name is required' });
  }
  
  try {
    const [result] = await pool.query('UPDATE industries SET industry_name = ? WHERE industry_id = ?', [industry_name, req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Industry not found' });
    }
    const [updatedIndustry] = await pool.query('SELECT industry_id, industry_name FROM industries WHERE industry_id = ?', [req.params.id]);
    res.json(updatedIndustry[0]);
  } catch (err) {
    console.error('Error updating industry:', err);
    res.status(500).json({ error: 'Failed to update industry' });
  }
});

app.delete('/api/industries/:id', authenticate, authorizeAdmin, async (req, res) => {
  try {
    // Check if industry is referenced by products
    const [products] = await pool.query('SELECT product_id FROM products WHERE industry_id = ?', [req.params.id]);
    if (products.length > 0) {
      return res.status(400).json({ error: 'Cannot delete industry with associated products' });
    }
    
    const [result] = await pool.query('DELETE FROM industries WHERE industry_id = ?', [req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Industry not found' });
    }
    res.status(204).send();
  } catch (err) {
    console.error('Error deleting industry:', err);
    res.status(500).json({ error: 'Failed to delete industry' });
  }
});

// Products routes


app.get('/api/products', authenticate, async (req, res) => {
    try {
        let query = `
            SELECT p.product_id, p.name, p.industry_id, i.industry_name, 
                   p.product_info, p.pain_points, p.benefits
            FROM products p
            JOIN industries i ON p.industry_id = i.industry_id
        `;
        
        // Add industry filter if provided
        if (req.query.industry) {
            query += ` WHERE p.industry_id = ${mysql.escape(req.query.industry)}`;
        }
        
        const [products] = await pool.query(query);
        res.json(products);
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});


app.get('/api/products/:id', authenticate, async (req, res) => {
  try {
    const [products] = await pool.query(`
      SELECT p.product_id, p.name, p.industry_id, i.industry_name, p.product_info, p.pain_points, p.benefits
      FROM products p
      JOIN industries i ON p.industry_id = i.industry_id
      WHERE p.product_id = ?
    `, [req.params.id]);
    if (products.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json(products[0]);
  } catch (err) {
    console.error('Error fetching product:', err);
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

app.post('/api/products', authenticate, authorizeAdmin, async (req, res) => {
  const { name, industry_id, product_info, pain_points, benefits } = req.body;
  
  if (!name || !industry_id || !product_info || !pain_points || !benefits) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  try {
    // Verify industry exists
    const [industries] = await pool.query('SELECT industry_id FROM industries WHERE industry_id = ?', [industry_id]);
    if (industries.length === 0) {
      return res.status(400).json({ error: 'Invalid industry ID' });
    }
    
    // Insert product
    const [result] = await pool.query(
      'INSERT INTO products (name, industry_id, product_info, pain_points, benefits) VALUES (?, ?, ?, ?, ?)',
      [name, industry_id, product_info, pain_points, benefits]
    );
    
    // Fetch the newly created product
    const [newProduct] = await pool.query(`
      SELECT p.product_id, p.name, p.industry_id, i.industry_name, p.product_info, p.pain_points, p.benefits
      FROM products p
      JOIN industries i ON p.industry_id = i.industry_id
      WHERE p.product_id = ?
    `, [result.insertId]);
    
    res.status(201).json(newProduct[0]);
  } catch (err) {
    console.error('Error creating product:', err);
    res.status(500).json({ error: 'Failed to create product' });
  }
});

app.put('/api/products/:id', authenticate, authorizeAdmin, async (req, res) => {
  const { name, industry_id, product_info, pain_points, benefits } = req.body;
  
  if (!name || !industry_id || !product_info || !pain_points || !benefits) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  try {
    // Verify industry exists
    const [industries] = await pool.query('SELECT industry_id FROM industries WHERE industry_id = ?', [industry_id]);
    if (industries.length === 0) {
      return res.status(400).json({ error: 'Invalid industry ID' });
    }
    
    // Update product
    const [result] = await pool.query(
      'UPDATE products SET name = ?, industry_id = ?, product_info = ?, pain_points = ?, benefits = ? WHERE product_id = ?',
      [name, industry_id, product_info, pain_points, benefits, req.params.id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    // Fetch updated product
    const [updatedProduct] = await pool.query(`
      SELECT p.product_id, p.name, p.industry_id, i.industry_name, p.product_info, p.pain_points, p.benefits
      FROM products p
      JOIN industries i ON p.industry_id = i.industry_id
      WHERE p.product_id = ?
    `, [req.params.id]);
    
    res.json(updatedProduct[0]);
  } catch (err) {
    console.error('Error updating product:', err);
    res.status(500).json({ error: 'Failed to update product' });
  }
});

app.delete('/api/products/:id', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM products WHERE product_id = ?', [req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.status(204).send();
  } catch (err) {
    console.error('Error deleting product:', err);
    res.status(500).json({ error: 'Failed to delete product' });
  }
});
// ----------- ICP ROUTES (COMPLETE CRUD) -------------

// Helper function to validate profile type
const validateProfileType = (type) => {
  const validTypes = ['decision_maker', 'influencer'];
  return validTypes.includes(type);
};

// 1. GET ALL ICPS
app.get('/api/icp', authenticate, async (req, res) => {
  try {
    const [profiles] = await pool.query(`
      SELECT p.profile_id, p.industry_id, i.industry_name, 
             p.profile_details, p.decision_maker_or_influencer_type
      FROM ideal_customer_profiles p
      JOIN industries i ON p.industry_id = i.industry_id
      ORDER BY p.profile_id
    `);
    res.json(profiles);
  } catch (err) {
    console.error('Error fetching ICPs:', err);
    res.status(500).json({ 
      error: 'Failed to fetch ICPs', 
      details: err.message 
    });
  }
});

// 2. GET SINGLE ICP BY ID
app.get('/api/icp/:id', authenticate, async (req, res) => {
  const profileId = req.params.id;
  
  try {
    const [profile] = await pool.query(`
      SELECT p.profile_id, p.industry_id, i.industry_name, 
             p.profile_details, p.decision_maker_or_influencer_type
      FROM ideal_customer_profiles p
      JOIN industries i ON p.industry_id = i.industry_id
      WHERE p.profile_id = ?
    `, [profileId]);
    
    if (profile.length === 0) {
      return res.status(404).json({ error: 'ICP not found' });
    }
    
    res.json(profile[0]);
  } catch (err) {
    console.error('Error fetching ICP:', err);
    res.status(500).json({ 
      error: 'Failed to fetch ICP', 
      details: err.message 
    });
  }
});

// 3. CREATE NEW ICP
app.post('/api/icp', authenticate, authorizeAdmin, async (req, res) => {
  const { industry_id, profile_details, decision_maker_or_influencer_type } = req.body;
  
  // Validate required fields
  if (!industry_id || !profile_details || !decision_maker_or_influencer_type) {
    return res.status(400).json({ 
      error: 'All fields are required: industry_id, profile_details, decision_maker_or_influencer_type' 
    });
  }

  // Validate profile type
  if (!validateProfileType(decision_maker_or_influencer_type)) {
    return res.status(400).json({ 
      error: 'Invalid profile type. Must be "decision_maker" or "influencer"' 
    });
  }

  try {
    // Verify industry exists
    const [industries] = await pool.query(
      'SELECT industry_id FROM industries WHERE industry_id = ?', 
      [industry_id]
    );
    
    if (industries.length === 0) {
      return res.status(400).json({ error: 'Invalid industry ID' });
    }
    
    // Insert ICP
    const [result] = await pool.query(
      `INSERT INTO ideal_customer_profiles 
      (industry_id, profile_details, decision_maker_or_influencer_type) 
      VALUES (?, ?, ?)`,
      [industry_id, profile_details, decision_maker_or_influencer_type]
    );
    
    // Return the created ICP
    const [newProfile] = await pool.query(`
      SELECT p.profile_id, p.industry_id, i.industry_name, 
             p.profile_details, p.decision_maker_or_influencer_type
      FROM ideal_customer_profiles p
      JOIN industries i ON p.industry_id = i.industry_id
      WHERE p.profile_id = ?
    `, [result.insertId]);
    
    res.status(201).json(newProfile[0]);
  } catch (err) {
    console.error('Error creating ICP:', err);
    res.status(500).json({ 
      error: 'Failed to create ICP', 
      details: err.message 
    });
  }
});

// 4. UPDATE ICP
app.put('/api/icp/:id', authenticate, authorizeAdmin, async (req, res) => {
  const profileId = req.params.id;
  const { industry_id, profile_details, decision_maker_or_influencer_type } = req.body;
  
  // Validate required fields
  if (!industry_id || !profile_details || !decision_maker_or_influencer_type) {
    return res.status(400).json({ 
      error: 'All fields are required: industry_id, profile_details, decision_maker_or_influencer_type' 
    });
  }

  // Validate profile type
  if (!validateProfileType(decision_maker_or_influencer_type)) {
    return res.status(400).json({ 
      error: 'Invalid profile type. Must be "decision_maker" or "influencer"' 
    });
  }

  try {
    // Verify industry exists
    const [industries] = await pool.query(
      'SELECT industry_id FROM industries WHERE industry_id = ?', 
      [industry_id]
    );
    
    if (industries.length === 0) {
      return res.status(400).json({ error: 'Invalid industry ID' });
    }
    
    // Update ICP
    const [result] = await pool.query(
      `UPDATE ideal_customer_profiles 
      SET industry_id = ?, 
          profile_details = ?, 
          decision_maker_or_influencer_type = ?
      WHERE profile_id = ?`,
      [industry_id, profile_details, decision_maker_or_influencer_type, profileId]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'ICP not found' });
    }
    
    // Return the updated ICP
    const [updatedProfile] = await pool.query(`
      SELECT p.profile_id, p.industry_id, i.industry_name, 
             p.profile_details, p.decision_maker_or_influencer_type
      FROM ideal_customer_profiles p
      JOIN industries i ON p.industry_id = i.industry_id
      WHERE p.profile_id = ?
    `, [profileId]);
    
    res.json(updatedProfile[0]);
  } catch (err) {
    console.error('Error updating ICP:', err);
    res.status(500).json({ 
      error: 'Failed to update ICP', 
      details: err.message 
    });
  }
});

// 5. DELETE ICP
app.delete('/api/icp/:id', authenticate, authorizeAdmin, async (req, res) => {
  const profileId = req.params.id;
  
  try {
    const [result] = await pool.query(
      'DELETE FROM ideal_customer_profiles WHERE profile_id = ?', 
      [profileId]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'ICP not found' });
    }
    
    res.status(204).send();
  } catch (err) {
    console.error('Error deleting ICP:', err);
    res.status(500).json({ 
      error: 'Failed to delete ICP', 
      details: err.message 
    });
  }
});


// Get all strategies or by industry
app.get('/api/strategies', authenticate, async (req, res) => {
  const { industry } = req.query;
  try {
    const [rows] = industry
      ? await pool.query(
          `SELECT s.strategy_id, s.industry_id, i.industry_name, s.linkedin_strategy
           FROM strategies s
           JOIN industries i ON s.industry_id = i.industry_id
           WHERE s.industry_id = ?`,
          [industry]
        )
      : await pool.query(
          `SELECT s.strategy_id, s.industry_id, i.industry_name, s.linkedin_strategy
           FROM strategies s
           JOIN industries i ON s.industry_id = i.industry_id`
        );

    res.json(rows);
  } catch (err) {
    console.error('Error fetching strategies:', err);
    res.status(500).json({ error: 'Failed to fetch strategies' });
  }
});

// Get strategy by ID
app.get('/api/strategies/:id', authenticate, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT s.strategy_id, s.industry_id, i.industry_name, s.linkedin_strategy
       FROM strategies s
       JOIN industries i ON s.industry_id = i.industry_id
       WHERE s.strategy_id = ?`,
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Strategy not found' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Error fetching strategy:', err);
    res.status(500).json({ error: 'Failed to fetch strategy' });
  }
});

// Create strategy
app.post('/api/strategies', authenticate, authorizeAdmin, async (req, res) => {
  const { industry_id, linkedin_strategy } = req.body;
  if (!industry_id || !linkedin_strategy) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  try {
    const [result] = await pool.query(
      `INSERT INTO strategies (industry_id, linkedin_strategy)
       VALUES (?, ?)`,
      [industry_id, linkedin_strategy]
    );
    res.status(201).json({ message: 'Strategy added successfully', strategy_id: result.insertId });
  } catch (err) {
    console.error('Error adding strategy:', err);
    res.status(500).json({ error: 'Failed to add strategy' });
  }
});

// Update strategy
app.put('/api/strategies/:id', authenticate, authorizeAdmin, async (req, res) => {
  const { industry_id, linkedin_strategy } = req.body;
  try {
    const [result] = await pool.query(
      `UPDATE strategies SET industry_id = ?, linkedin_strategy = ? WHERE strategy_id = ?`,
      [industry_id, linkedin_strategy, req.params.id]
    );
    res.json({ message: 'Strategy updated successfully' });
  } catch (err) {
    console.error('Error updating strategy:', err);
    res.status(500).json({ error: 'Failed to update strategy' });
  }
});

// Delete strategy
app.delete('/api/strategies/:id', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const [result] = await pool.query(`DELETE FROM strategies WHERE strategy_id = ?`, [req.params.id]);
    res.json({ message: 'Strategy deleted successfully' });
  } catch (err) {
    console.error('Error deleting strategy:', err);
    res.status(500).json({ error: 'Failed to delete strategy' });
  }
});


// Get all strategies or by industry
app.get('/api/email-strategies', authenticate, async (req, res) => {
  const { industry } = req.query;
  try {
    const [rows] = industry
      ? await pool.query(
          `SELECT s.strategy_id, s.industry_id, i.industry_name, s.email_strategy
           FROM email_strategies s
           JOIN industries i ON s.industry_id = i.industry_id
           WHERE s.industry_id = ?`,
          [industry]
        )
      : await pool.query(
          `SELECT s.strategy_id, s.industry_id, i.industry_name, s.email_strategy
           FROM email_strategies s
           JOIN industries i ON s.industry_id = i.industry_id`
        );

    res.json(rows);
  } catch (err) {
    console.error('Error fetching email :', err);
    res.status(500).json({ error: 'Failed to fetch email strategies' });
  }
});

// Get strategy by ID
app.get('/api/email-strategies/:id', authenticate, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT s.strategy_id, s.industry_id, i.industry_name, s.email_strategy
       FROM email_strategies s
       JOIN industries i ON s.industry_id = i.industry_id
       WHERE s.strategy_id = ?`,
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Strategy not found' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Error fetching strategy:', err);
    res.status(500).json({ error: 'Failed to fetch strategy' });
  }
});

// Create strategy
app.post('/api/email-strategies', authenticate, authorizeAdmin, async (req, res) => {
  const { industry_id, email_strategy } = req.body;
  if (!industry_id || !email_strategy) {
    return res.status(400).json({ error: 'All fields are required' });D
  }
  try {
    const [result] = await pool.query(
      `INSERT INTO email_strategies (industry_id, email_strategy)
       VALUES (?, ?)`,
      [industry_id, email_strategy]
    );
    res.status(201).json({ message: 'Strategy added successfully', strategy_id: result.insertId });
  } catch (err) {
    console.error('Error adding strategy:', err);
    res.status(500).json({ error: 'Failed to add strategy' });
  }
});

// Update strategy
app.put('/api/email-strategies/:id', authenticate, authorizeAdmin, async (req, res) => {
  const { industry_id, email_strategy } = req.body;
  try {
    const [result] = await pool.query(
      `UPDATE email_strategies SET industry_id = ?, email_strategy = ? WHERE strategy_id = ?`,
      [industry_id, email_strategy, req.params.id]
    );
    res.json({ message: 'Strategy updated successfully' });
  } catch (err) {
    console.error('Error updating strategy:', err);
    res.status(500).json({ error: 'Failed to update strategy' });
  }
});

// Delete strategy
app.delete('/api/email-strategies/:id', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const [result] = await pool.query(`DELETE FROM email_strategies WHERE strategy_id = ?`, [req.params.id]);
    res.json({ message: 'Strategy deleted successfully' });
  } catch (err) {
    console.error('Error deleting strategy:', err);
    res.status(500).json({ error: 'Failed to delete strategy' });
  }
});



// Get all email strategies
app.get('/api/email-strategies', authenticate, authorizeAdmin, (req, res) => {
  const query = `
    SELECT es.strategy_id, es.email_strategy, i.industry_name
    FROM email_strategies es
    JOIN industries i ON es.industry_id = i.industry_id
    ORDER BY es.strategy_id DESC
  `;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(results);
  });
});

// Add new email strategy
app.post('/api/email-strategies', authenticate, authorizeAdmin, (req, res) => {
  const { industry_id, email_strategy } = req.body;
  if (!industry_id || !email_strategy) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const query = 'INSERT INTO email_strategies (industry_id, email_strategy) VALUES (?, ?)';
  db.query(query, [industry_id, email_strategy], (err, result) => {
    if (err) return res.status(500).json({ error: 'Insert failed' });
    res.status(201).json({ message: 'Strategy added', id: result.insertId });
  });
});

// Get email strategy by ID
app.get('/api/email-strategies/:id', authenticate, authorizeAdmin, (req, res) => {
  const query = 'SELECT * FROM email_strategies WHERE strategy_id = ?';
  db.query(query, [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json(results[0]);
  });
});

// Update email strategy
app.put('/api/email-strategies/:id', authenticate, authorizeAdmin, (req, res) => {
  const { industry_id, email_strategy } = req.body;
  if (!industry_id || !email_strategy) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const query = 'UPDATE email_strategies SET industry_id = ?, email_strategy = ? WHERE strategy_id = ?';
  db.query(query, [industry_id, email_strategy, req.params.id], (err, result) => {
    if (err) return res.status(500).json({ error: 'Update failed' });
    res.json({ message: 'Strategy updated' });
  });
});

// Delete email strategy
app.delete('/api/email-strategies/:id', authenticate, authorizeAdmin, (req, res) => {
  const query = 'DELETE FROM email_strategies WHERE strategy_id = ?';
  db.query(query, [req.params.id], (err, result) => {
    if (err) return res.status(500).json({ error: 'Delete failed' });
    res.json({ message: 'Strategy deleted' });
  });
});



// Get all call strategies
app.get('/api/call-strategies', authenticate, async (req, res) => {
  try {
    const query = `
      SELECT cs.strategy_id,cs.industry_id, cs.call_strategy, i.industry_name
      FROM call_strategies cs 
      JOIN industries i ON cs.industry_id = i.industry_id
      ORDER BY cs.strategy_id DESC
    `;
    const [results] = await pool.query(query);
    res.json(results);
  } catch (err) {
    console.error('Error fetching call strategies:', err);
    res.status(500).json({ error: 'Failed to fetch call strategies' });
  }
});



// Add new call strategy
app.post('/api/call-strategies', authenticate, authorizeAdmin, async (req, res) => {
  const { industry_id, call_strategy } = req.body;
  if (!industry_id || !call_strategy) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const [result] = await pool.query(
      'INSERT INTO call_strategies (industry_id, call_strategy) VALUES (?, ?)',
      [industry_id, call_strategy]
    );
    res.status(201).json({ message: 'Strategy added', id: result.insertId });
  } catch (err) {
    console.error('Error adding call strategy:', err);
    res.status(500).json({ error: 'Failed to add call strategy' });
  }
});

// Get call strategy by ID
app.get('/api/call-strategies/:id', authenticate, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT  cs.strategy_id, cs.call_strategy, i.industry_name FROM call_strategies cs JOIN industries i ON cs.industry_id = i.industry_id WHERE cs.strategy_id = ?',
      [req.params.id]
    );
    if (results.length === 0) {
      return res.status(404).json({ error: 'Strategy not found' });
    }
    res.json(results[0]);
  } catch (err) {
    console.error('Error fetching call strategy:', err);
    res.status(500).json({ error: 'Failed to fetch call strategy' });
  }
});



// Update call strategy
app.put('/api/call-strategies/:id', authenticate, authorizeAdmin, async (req, res) => {
  const { industry_id, call_strategy } = req.body;
  if (!industry_id || !call_strategy) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const [result] = await pool.query(
      'UPDATE call_strategies SET industry_id = ?, call_strategy = ? WHERE strategy_id = ?',
      [industry_id, call_strategy, req.params.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Strategy not found' });
    }
    res.json({ message: 'Strategy updated' });
  } catch (err) {
    console.error('Error updating call strategy:', err);
    res.status(500).json({ error: 'Failed to update call strategy' });
  }
});



// Delete call strategy
app.delete('/api/call-strategies/:id', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM call_strategies WHERE strategy_id = ?', [req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Strategy not found' });
    }
    res.json({ message: 'Strategy deleted' });
  } catch (err) {
    console.error('Error deleting call strategy:', err);
    res.status(500).json({ error: 'Failed to delete call strategy' });
  }
});









// Get all objection strategies

app.get('/api/objection-strategies', authenticate, async (req, res) => {
    try {
        const { industryId } = req.query; // Extract industryId from query parameters
        let query;
        let params = [];

        // Base query to fetch strategies, always joining with industries to get the name
        query = `
            SELECT 
                os.strategy_id, 
                os.objection_strategy, 
                os.industry_id, 
                i.industry_name 
            FROM objection_strategies os
            JOIN industries i ON os.industry_id = i.industry_id
        `;
        
        // Add WHERE clause if industryId is provided
        if (industryId) {
            query += ` WHERE os.industry_id = ?`;
            params.push(industryId); // Add industryId to parameters array
        }

        // Add ORDER BY clause
        query += ` ORDER BY os.strategy_id DESC`;

        const [results] = await pool.query(query, params);
        res.json(results);
    } catch (err) {
        console.error('Error fetching objection strategies:', err);
        res.status(500).json({ error: 'Failed to fetch objection strategies' });
    }
});

// Add new objection strategy
app.post('/api/objection-strategies', authenticate, authorizeAdmin, async (req, res) => {
  const { industry_id, objection_strategy } = req.body;
  if (!industry_id || !objection_strategy) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const [result] = await pool.query(
      'INSERT INTO objection_strategies (industry_id, objection_strategy) VALUES (?, ?)',
      [industry_id, objection_strategy]
    );
    res.status(201).json({ message: 'Strategy added', id: result.insertId });
  } catch (err) {
    console.error('Error adding objection strategy:', err);
    res.status(500).json({ error: 'Failed to add objection strategy' });
  }
});

// Get objection strategy by ID
app.get('/api/objection-strategies/:id', authenticate, async (req, res) => {
  try {
    const [results] = await pool.query(
      'SELECT os.strategy_id, os.objection_strategy, i.industry_name FROM objection_strategies os JOIN industries i ON os.industry_id = i.industry_id WHERE os.strategy_id = ?',
      [req.params.id]
    );
    if (results.length === 0) {
      return res.status(404).json({ error: 'Strategy not found' });
    }
    res.json(results[0]);
  } catch (err) {
    console.error('Error fetching objection strategy:', err);
    res.status(500).json({ error: 'Failed to fetch objection strategy' });
  }
});

// Update objection strategy
app.put('/api/objection-strategies/:id', authenticate, authorizeAdmin, async (req, res) => {
  const { industry_id, objection_strategy } = req.body;
  if (!industry_id || !objection_strategy) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const [result] = await pool.query(
      'UPDATE objection_strategies SET industry_id = ?, objection_strategy = ? WHERE strategy_id = ?',
      [industry_id, objection_strategy, req.params.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Strategy not found' });
    }
    res.json({ message: 'Strategy updated' });
  } catch (err) {
    console.error('Error updating objection strategy:', err);
    res.status(500).json({ error: 'Failed to update objection strategy' });
  }
});

// Delete objection strategy
app.delete('/api/objection-strategies/:id', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM objection_strategies WHERE strategy_id = ?', [req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Strategy not found' });
    }
    res.json({ message: 'Strategy deleted' });
  } catch (err) {
    console.error('Error deleting objection strategy:', err);
    res.status(500).json({ error: 'Failed to delete objection strategy' });
  }
});



// Backend API Routes (Node.js/Express)

// Get all menu items 
app.get('/api/menu/all', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM menu_table ORDER BY sort_order ASC');
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch menu items' });
    }
});

// Get enabled menu items for sidebar
app.get('/api/menu', async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT * FROM menu_table 
            WHERE is_enabled = TRUE 
            ORDER BY sort_order ASC
        `);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch menu items' });
    }
});

// Get single menu item
app.get('/api/menu/:id', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM menu_table WHERE menu_id = ?', [req.params.id]);
        
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Menu item not found' });
        }
        
        res.json(rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch menu item' });
    }
});

// Create new menu item
app.post('/api/menu', async (req, res) => {
    try {
        const { name, icon, url, sort_order, is_enabled } = req.body;
        
        const [result] = await pool.query(
            'INSERT INTO menu_table (name, icon, url, sort_order, is_enabled) VALUES (?, ?, ?, ?, ?)',
            [name, icon, url, sort_order, is_enabled]
        );
        
        res.status(201).json({ 
            message: 'Menu item created successfully',
            menu_id: result.insertId 
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to create menu item' });
    }
});


// Update menu item
app.put('/api/menu/:id', async (req, res) => {
    try {
        const { name, icon, url, sort_order, is_enabled } = req.body;
        
        const [result] = await pool.query(
            'UPDATE menu_table SET name = ?, icon = ?, url = ?, sort_order = ?, is_enabled = ? WHERE menu_id = ?',
            [name, icon, url, sort_order, is_enabled, req.params.id]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Menu item not found' });
        }
        
        res.json({ message: 'Menu item updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update menu item' });
    }
});

// Delete menu item
app.delete('/api/menu/:id', async (req, res) => {
    try {
        const [result] = await pool.query('DELETE FROM menu_table WHERE menu_id = ?', [req.params.id]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Menu item not found' });
        }

        res.json({ message: 'Menu item deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete menu item' });
    }
});



// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

// Start server
app.listen(PORT, async () => {
  try {
    // Test database connection
    await pool.query('SELECT 1');
    console.log('Connected to MySQL database');
    console.log(`Server running at http://localhost:${PORT}`);
  } catch (err) {
    console.error('Failed to connect to MySQL:', err);
    process.exit(1);
  }
});

