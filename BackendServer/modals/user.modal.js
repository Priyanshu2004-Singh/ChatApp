import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const userSchema = mongoose.Schema({
    userName: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    }
    ,
    accessToken: {
        type: String,
    },
    refreshToken: {
        type: String,
    }
}, { timestamps: true });

// Before saving the user, hash the password if it has been modified
userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) {
        return next();
    }
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        // generate JWTs when a user is created or password changed
        try {
            const payload = { id: this._id, userName: this.userName, email: this.email };
            const accessSecret = process.env.JWT_SECRET || 'change_this_access_secret';
            const refreshSecret = process.env.JWT_REFRESH_SECRET || 'change_this_refresh_secret';
            const accessExpires = process.env.ACCESS_TOKEN_EXPIRES || '15m';
            const refreshExpires = process.env.REFRESH_TOKEN_EXPIRES || '7d';

            this.accessToken = jwt.sign(payload, accessSecret, { expiresIn: accessExpires });
            this.refreshToken = jwt.sign(payload, refreshSecret, { expiresIn: refreshExpires });
        } catch (tokenErr) {
            console.error('Error generating tokens:', tokenErr);
            // don't block user creation on token generation failure, but pass through
        }
        next();
    } catch (error) {
        next(error);
    }
});


export const User = mongoose.model("User",userSchema);