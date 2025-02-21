const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const SECRET_KEY = "7838723987"; // Change this to a strong secret key
const verifyToken = (req, res, next) => {
    const token = req.headers["authorization"];

    if (!token) {
        return res.status(403).json({ error: "Access denied! No token provided." });
    }

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: "Invalid token!" });
        }
        req.user = decoded; // Store user info in request
        next();
    });
};



const app = express();
app.use(express.json()); // Enable JSON parsing in Express

// MySQL Database Connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "1234", // Use your MySQL password
    database: "school_management" // Your database name
});

db.connect((err) => {
    if (err) {
        console.error("Database connection failed: " + err.message);
    } else {
        console.log("Connected to MySQL database");
    }
});

// User Registration Route
app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: "All fields are required!" });
    }

    try {
        // Hash password before saving
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert into database
        const sql = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
        db.query(sql, [name, email, hashedPassword], (err, result) => {
            if (err) {
                console.error("Database Error:", err); // Print the actual error
                return res.status(500).json({ error: err.sqlMessage });
            }
            res.json({ message: "User registered successfully!" });
        });
    } catch (error) {
        console.error("Server Error:", error);
        res.status(500).json({ error: "Internal server error!" });
    }
});


// Start the Server
app.listen(5000, () => {
    console.log("Server running on port 5000");
});

app.post("/login", (req, res) => {
    const { email, password } = req.body;

    const sql = "SELECT * FROM users WHERE email = ?";
    db.query(sql, [email], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: "Database error!" });
        }
        
        if (results.length === 0) {
            return res.status(401).json({ error: "Invalid email or password!" });
        }

        const user = results[0];

        // Compare passwords (assuming passwords are stored as plain text - ideally, hash them)
        if (password !== user.password) {
            return res.status(401).json({ error: "Invalid email or password!" });
        }

        // Generate JWT Token
        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });

        res.json({ message: "Login successful!", token });
    });
});
app.get("/profile", verifyToken, (req, res) => {
    const userId = req.user.id;

    const sql = "SELECT id, name, email FROM users WHERE id = ?";
    db.query(sql, [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: "Database error!" });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ error: "User not found!" });
        }

        res.json({ user: results[0] });
    });
});


