const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { Sequelize, DataTypes } = require('sequelize');
const Admin = require('./Modal/AdminModal');
const Updates = require('./Modal/UpdateModal');

const app = express();
app.use(express.json());
app.use(express.static('Public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["POST", "GET", "PUT", "DELETE"],
    credentials: true,
}));

const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET_KEY;
const sequelize = new Sequelize({
    dialect: 'mysql',
    host: process.env.HOST,
    username: process.env.USER,
    password: process.env.PASS,
    database: process.env.DATABASE,
    logging:false
});
app.get('/', (req, res) => {
    console.log("Connected");
    return res.json('Connected');
});

// Middleware to check admin authentication
const checkAdminAuth = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.json({ error: 'Unauthorized' });
    } else {
        jwt.verify(token, jwtSecret, (err, decodedToken) => {
            if (err) {
                return res.json({ error: 'Unauthorized' });
            } else {
                req.id = decodedToken.userId;
                req.name = decodedToken.username;
                req.admin = decodedToken;
                // console.log(req.id)
                next();
            }
        });
    }
};

//Route can be used for authentication in frontend
app.get('/api/protectedRoute', checkAdminAuth, (req, res) => {
    res.json({ message: 'Admin is authenticated', adminId: req.id, name: req.name, login: true });
});

// Admin Register
app.post('/api/register', async (req, res) => {
    const { name, email, password, cpassword } = req.body;

    if (cpassword !== password) {
        return res.json({ msg: "Password didn't match, try again...", msg_type: 'error' });
    }

    if (!cpassword) {
        return res.json({ msg: "Enter valid Confirm Password, try again...", msg_type: 'error' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await Admin.create({
            name: name,
            email: email,
            password: hashedPassword,
        });

        res.status(201).json({ msg: 'Admin registered successfully', msg_type: 'good' });
    } catch (error) {
        console.error('Error registering admin:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Login data
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const admin = await Admin.findOne({ where: { email: email } });
        if (!admin) {
            return res.json({ msg: 'Invalid email or password', msg_type: 'error' });
        }

        const isPasswordMatch = await bcrypt.compare(password, admin.password);

        if (isPasswordMatch) {
            const token = jwt.sign({ userId: admin.id, username: admin.name, email: admin.email }, jwtSecret, { expiresIn: '1h' });
            res.cookie('token', token, { httpOnly: true, sameSite: 'none', secure: true });
            return res.json({ msg: 'Login successful', msg_type: 'good', login: true });

        } else {
            res.json({ msg: 'Password Error. . . ', msg_type: 'error' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// All updates data
app.get('/api/getAllUpdates', async (req, res) => {
    try {
        const allUpdates = await Updates.findAll({ order: [['uploadDateTime', 'DESC']] });

        if (!allUpdates) {
            return res.status(404).json({ success: false, error: 'Updates not found' });
        }

        return res.json({ success: true, updates: allUpdates });
    } catch (error) {
        console.error('Error retrieving updates from Prisma:', error);
        res.status(500).json({ success: false, error: 'Internal Server Error' });
    }
});

// Delete a resource by ID
app.delete('/api/resources/:selectedResourceId', checkAdminAuth, async (req, res) => {
    const selectedResourceId = req.params.selectedResourceId;
    try {
        const deletedUpdate = await Updates.destroy({ where: { id: selectedResourceId } });

        if (!deletedUpdate) {
            return res.status(404).json({ error: 'Update not found' });
        }

        res.json({ msg: 'Post deleted successfully', msg_type: 'good' });
    } catch (error) {
        console.error('Error deleting update:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Updating Data API
app.post('/api/saveUpdate', checkAdminAuth, async (req, res) => {
    const { topic, content } = req.body;
    const date = req.body.date;
    const time = req.body.time;

    try {
        const desc = JSON.stringify(content);
        console.log(typeof (desc))
        await Updates.create({
            topic: topic,
            desc: desc,
        });

        res.status(201).json({ msg: 'Update saved successfully' });
    } catch (error) {
        console.error('Error saving update:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Logout
app.get('/api/logout', (req, res) => {
    res.clearCookie('token')
    return res.json({ logout: true, msg: 'Logout Successful', msg_type: 'error' });
});

// Start the server
sequelize.sync().then(() => {
    app.listen(port, () => {
        console.log(`Server is running on port ${port}`);
    });
});
