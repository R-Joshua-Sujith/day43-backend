const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const otpGenerator = require('otp-generator');

const UserModel = require('./models/User')

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URL)
    .then(() => console.log("DB Connection Successful"))
    .catch((err) => console.log(err));

app.get("/", async (req, res) => {
    res.send("Day43 Backend")
})


app.post("/signup", async (req, res) => {
    const email = req.body.email;
    const user = await UserModel.findOne({ email });
    if (user) {
        return res.status(404).json({ message: 'Account Already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    const newUser = new UserModel({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,
    });

    try {
        const savedUser = await newUser.save();
        res.status(200).json({ message: `Account Created Successfully` });
    } catch (err) {
        res.status(500).json(err);
    }
})

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid Credentials' });
        }

        res.status(200).json({ message: `Login Successful` });
    }
    catch (error) {
        res.status(500).json({ message: 'Internal Server error' });
    }

})

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    // Find user by email
    const user = await UserModel.findOne({ email });

    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    // Generate OTP

    const otp = otpGenerator.generate(6, { digits: true, alphabets: false, upperCase: false });
    const otpExpiry = Date.now() + 600000; // 10 minutes

    // Save  OTP, and their expiry to user
    user.otp = otp;
    user.otpExpiry = otpExpiry;
    await user.save();

    // Send password reset email with OTP
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'joshuasujith14@gmail.com',
            pass: process.env.PASS_KEY,
        },
    });

    const mailOptions = {
        from: 'joshuasujith14@gmail.com',
        to: email,
        subject: 'Password Reset',
        text: `You are receiving this email because you requested a password reset. Your OTP is: ${otp}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
            return res.status(500).json({ message: 'Failed to send password reset email' });
        }

        res.json({ message: 'Password reset email sent' });
    });
});

app.post('/reset-password', async (req, res) => {
    const { otp, newPassword } = req.body;

    // Find user by reset token and OTP
    const user = await UserModel.findOne({
        otp,
        otpExpiry: { $gt: Date.now() },
    });

    if (!user) {
        return res.status(400).json({ message: 'Invalid OTP' });
    }

    // Update user password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    user.password = hashedPassword;
    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save();

    res.json({ message: 'Password reset successful' });
});

app.listen(5000, () => {
    console.log("Backend Server is Running")
})