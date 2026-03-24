const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const authMiddleware = require('./authMiddleware');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// ------------------- REGISTER -------------------
app.post('/api/register', async (req, res) => {
    const { fname, lname, email, mobile, password, collegeId, branch, cgpa, backlogs, year } = req.body;

    // validation
    if (!fname || !lname || !email || !mobile || !password || !collegeId || branch === undefined || cgpa === undefined || backlogs === undefined || !year) {
        return res.status(400).json({ error: 'All fields required' });
    }
    if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    try {
        // check if email exists
        const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // insert user
        const [result] = await pool.query(
            `INSERT INTO users (fname, lname, email, mobile, password_hash, college_id, branch, cgpa, backlogs, year)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [fname, lname, email, mobile, passwordHash, collegeId, branch, cgpa, backlogs, year]
        );
        const userId = result.insertId;

        // add default skills
        const defaultSkills = [
            { name: 'Python', color: 'blue' },
            { name: 'Java', color: 'blue' },
            { name: 'React', color: 'green' },
            { name: 'SQL', color: 'green' },
            { name: 'Node.js', color: 'green' },
            { name: 'Communication', color: 'orange' }
        ];
        for (const skill of defaultSkills) {
            await pool.query('INSERT INTO skills (user_id, name, color) VALUES (?, ?, ?)', [userId, skill.name, skill.color]);
        }

        // generate JWT
        const token = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({ token, user: { id: userId, fname, lname, email, collegeId, branch, cgpa, backlogs, year } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ------------------- LOGIN -------------------
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    try {
        const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

        const user = users[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        // Return profile data (without password)
        const { password_hash, ...userData } = user;
        res.json({ token, user: userData });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ------------------- GET PROFILE -------------------
app.get('/api/profile', authMiddleware, async (req, res) => {
    try {
        const [users] = await pool.query('SELECT id, fname, lname, email, college_id, branch, cgpa, backlogs, year FROM users WHERE id = ?', [req.userId]);
        if (users.length === 0) return res.status(404).json({ error: 'User not found' });
        res.json(users[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ------------------- UPDATE PROFILE -------------------
app.put('/api/profile', authMiddleware, async (req, res) => {
    const { fname, lname, collegeId, branch, cgpa, backlogs, year } = req.body;

    try {
        await pool.query(
            `UPDATE users SET fname = ?, lname = ?, college_id = ?, branch = ?, cgpa = ?, backlogs = ?, year = ?
             WHERE id = ?`,
            [fname, lname, collegeId, branch, cgpa, backlogs, year, req.userId]
        );
        res.json({ message: 'Profile updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ------------------- GET SKILLS -------------------
app.get('/api/skills', authMiddleware, async (req, res) => {
    try {
        const [skills] = await pool.query('SELECT id, name, color FROM skills WHERE user_id = ? ORDER BY created_at', [req.userId]);
        res.json(skills);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ------------------- ADD SKILL -------------------
app.post('/api/skills', authMiddleware, async (req, res) => {
    const { name, color } = req.body;
    if (!name) return res.status(400).json({ error: 'Skill name required' });

    try {
        const [result] = await pool.query('INSERT INTO skills (user_id, name, color) VALUES (?, ?, ?)', [req.userId, name, color || 'blue']);
        res.status(201).json({ id: result.insertId, name, color: color || 'blue' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ------------------- DELETE SKILL -------------------
app.delete('/api/skills/:id', authMiddleware, async (req, res) => {
    const skillId = req.params.id;
    try {
        // ensure skill belongs to user
        const [skills] = await pool.query('SELECT * FROM skills WHERE id = ? AND user_id = ?', [skillId, req.userId]);
        if (skills.length === 0) return res.status(404).json({ error: 'Skill not found' });

        await pool.query('DELETE FROM skills WHERE id = ?', [skillId]);
        res.json({ message: 'Skill deleted' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));