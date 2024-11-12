// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const sgMail = require('@sendgrid/mail');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { MongoClient } = require('mongodb');
const app = express();
const PORT = process.env.PORT || 3000;
const mongoUri = process.env.MONGODB_URI || "mongodb+srv://dclarence322:COFFEELOVER2024@cluster0.xh3hj.mongodb.net/"; // Use your MongoDB URI
const client = new MongoClient(mongoUri);
const database = client.db("test"); // Replace "myDatabase" with your database name
let usersCollection;
usersCollection = database.collection("users"); // Replace "tblUser" with your collection name

app.set('trust proxy', 1);

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));
app.use(helmet());
app.use(cors());

async function connectToDatabase() {
    try {
        await client.connect();
        console.log('Connected to MongoDB');
        const database = client.db('test');
        usersCollection = database.collection('users');
    } catch (err) {
        console.error('Failed to connect to MongoDB', err);
        process.exit(1);
    }
}
connectToDatabase();

// MongoDB connection using the URI from .env
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((error) => {
    console.error('MongoDB connection error:', error);
});

// User Schema
const userSchema = new mongoose.Schema({
    emaildb: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetKey: String,
    resetExpires: Date,
});
const User = mongoose.model('User', userSchema);

// Token Schema
const tokenSchema = new mongoose.Schema({
    email: { type: String, required: true },
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 3600 }, // Token expires in 1 hour
});
const Token = mongoose.model('Token', tokenSchema);

// Configure SendGrid API Key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);



// Hash Password Function
function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hashSync(password, saltRounds);
}

// Generate Random String Function
function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

// Forgot Password Endpoint
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).send('Email is required');
    }
    try {
        let existingToken = await Token.findOne({ email: email });
        const resetToken = generateRandomString(32);
        if (existingToken) {
            existingToken.token = resetToken;
            await existingToken.save();
        } else {
            const newToken = new Token({
                email: email,
                token: resetToken,
            });
            await newToken.save();
        }
        const msg = {
            to: email,
            from: 'dclarence322@gmail.com',
            subject: 'Password Reset Request',
            text: `Your password reset token is: ${resetToken}`,
            html: `<p>Your password reset token is:</p><h3>${resetToken}</h3>`,
        };
        await sgMail.send(msg);
        res.status(200).send('Password reset email sent');
    } catch (error) {
        res.status(500).send('Error finding or updating token');
    }
});

// Send Password Reset Endpoint
app.post('/send-password-reset', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ emaildb: email });
        if (!user) {
            res.status(404).json({ success: false, message: 'No account with that email address exists.' });
            return;
        }

        const resetCode = generateRandomString(32); // Generate a reset code
        await User.updateOne(
            { emaildb: email },
            { $set: { resetKey: resetCode, resetExpires: new Date(Date.now() + 3600000) } }
        );

        const msg = {
            to: email,
            from: 'dclarence322@gmail.com',
            subject: 'Password Reset Request',
            text: `Your password reset code is: ${resetCode}`,
            html: `<p>Your password reset code is:</p><h3>${resetCode}</h3>`,
        };
        await sgMail.send(msg);
        res.json({ success: true, redirectUrl: '/reset-password.html' });
    } catch (error) {
        console.error('Error processing your request', error);
        res.status(500).json({ success: false, message: 'Error processing your request' });
    }
});

// Reset Password Endpoint
app.post('/reset-password', async (req, res) => {
    const { resetKey, newPassword } = req.body;
    try {
        const user = await User.findOne({
            resetKey: resetKey,
            resetExpires: { $gt: new Date() }
        });
        if (!user) {
            res.status(400).json({ success: false, message: 'Invalid or expired reset key.' });
            return;
        }

        const hashedPassword = hashPassword(newPassword);
        await User.updateOne(
            { _id: user._id },
            {
                $set: {
                    password: hashedPassword,
                    resetKey: null,
                    resetExpires: null
                }
            }
        );

        res.json({ success: true, message: 'Your password has been successfully reset.' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ success: false, message: 'Error resetting password' });
    }
});

// Sign Up Route
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    function isValidPassword(password) {
        // Example: Password must be at least 8 characters, contain letters and numbers
        const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
        return passwordRegex.test(password);
        }
    try {
    // Check if user already exists
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required.'
    
    });
    }
    const existingUser = await usersCollection.findOne({ emaildb: email });
    if (existingUser) {
        return res.status(400).json({ success: false, message: 'Email already registered.' });
    }
    // Validate password strength (optional)
    if (!isValidPassword(password)) {
        return res.status(400).json({ success: false, message: 'Password does not meet complexity requirements.' });
    
    }
    // Hash the password
    const hashedPassword = hashPassword(password);

    function hashPassword(password) {
        const saltRounds = 10;
        return bcrypt.hashSync(password, saltRounds);
        }

    function isValidPassword(password) {
        // Requires at least one uppercase letter, one lowercase letter, one number, and at least 8 characters
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
        return passwordRegex.test(password);
        }


    

    // Create the new user object
    const newUser = {
    emaildb: email,
    password: hashedPassword,
    createdAt: new Date()
    };
    // Insert the new user into the database
    const insertResult = await usersCollection.insertOne(newUser);
    // Check if the insert operation was successful
    if (insertResult.acknowledged) {
        res.json({ success: true, message: 'Account created successfully!' });
    } else {
        res.status(500).json({ success: false, message: 'Failed to create account.' });
    }
    } catch (error) {
        console.error('Error creating account:', error.stack || error);
        res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
    });

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: mongoUri }),
    
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 30 * 60 * 1000 // 30 minutes session expiry
        }
    }));


const loginLimiter = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: 'Too many login attempts, please try again after 30 minutes.',
    handler: function (req, res, next, options) {
    res.status(options.statusCode).json({ success: false, message: options.message });
    }
    });
     
app.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    try {
    
    // Input validation
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }
        if (!validator.isEmail(email)) {
            return res.status(400).json({ success: false, message: 'Invalid email format.' });
        }
        // Fetch user
        const user = await usersCollection.findOne({ emaildb: email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid email or password.' });
        }
        // Account lockout check
        if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
            const remainingTime = Math.ceil((user.accountLockedUntil - new Date()) / 60000);
            return res.status(403).json({ success: false, message: `Account is locked. Try again in ${remainingTime} minutes.` });
        }


    // Password verification
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            // Handle failed attempts
                let invalidAttempts = (user.invalidLoginAttempts || 0) + 1;
                let updateFields = { invalidLoginAttempts: invalidAttempts };
            if (invalidAttempts >= 3) {
            // Lock account
                updateFields.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000);
                updateFields.invalidLoginAttempts = 0;
            await usersCollection.updateOne({ _id: user._id }, { $set:updateFields });
            return res.status(403).json({ success: false, message: 'Account is locked due to multiple failed login attempts. Please try again after 30 minutes.' });
            
            } else {
            await usersCollection.updateOne({ _id: user._id }, { $set:updateFields });
            return res.status(400).json({ success: false, message: 'Invalid email or password.' });
            }
        }
    
    // Successful login
        await usersCollection.updateOne(
        { _id: user._id },
        { $set: { invalidLoginAttempts: 0, accountLockedUntil: null,lastLoginTime: new Date() } }
        );
        req.session.userId = user._id;
        req.session.email = user.emaildb;
        req.session.role = user.role;
        req.session.studentIDNumber = user.studentIDNumber;
        await new Promise((resolve, reject) => {
        req.session.save((err) => {
        if (err) return reject(err);
            resolve();
            });
        });
            res.json({ success: true, role: user.role, message: 'Login successful!' });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ success: false, message: 'Error during login.' });
    }
    });

function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized access.' });
    }
    }

app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/dashboard.html');
    });

// Fetch user details route
app.get('/user-details', isAuthenticated, async (req, res) => {
    try {
        const email = req.session.email;
        if (!email) {
            return res.status(401).json({ success: false, message: 'Unauthorized access.' });
        }
        // Fetch user details from the database
        const user = await usersCollection.findOne(
            { emaildb: email },
            { projection: { emaildb: 1 } }
            );
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        // Return only necessary details
        res.json({
            success: true,
            user: {
            email: user.emaildb
        }
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ success: false, message: 'Error fetching user details.' });
    }
    });



// Logout Route
app.post('/logout', async (req, res) => {
    if (!req.session.userId) {
        return res.status(400).json({ success: false, message: 'No user is logged in.' });
    }
    try {
        req.session.destroy(err => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.status(500).json({ success: false, message: 'Logout failed.' });
            }
            res.clearCookie('connect.sid');
            res.json({ success: true, message: 'Logged out successfully.' });
        });
    } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).json({ success: false, message: 'Logout failed.' });
    }
    });

// Start the Server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
