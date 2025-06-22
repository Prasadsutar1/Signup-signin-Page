const express = require("express");
const { UserModel } = require("./db");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const JWT_SECRET = "s3cret";
const bcrypt = require("bcrypt");
const cors = require("cors");
require("dotenv").config();
const DB_URL = process.env.DB_URL;
const app = express();
mongoose.connect(DB_URL);           
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => res.send("Express on Vercel"));

app.post("/signup", async function (req, res) {

    const email = req.body.email;
    const password = req.body.password;
    const name = req.body.name;
    const hashPassword = await bcrypt.hash(password, 5);

    try {
        await UserModel.create({
            email: email,
            password: hashPassword,
            name: name
        });
    } catch (error) {
        res.json({
            message: error
        })
        return;
    }

    res.json({
        message: "You are signed up"
    })
});


app.post("/signin", async function (req, res) {
    const email = req.body.email;
    const password = req.body.password;

    try {
        const response = await UserModel.findOne({
            email: email
        });
        if (!response) {
            res.status(403).json({
                message: "users does not exist in the database"
            })
            return
        }
        const checkPass = await bcrypt.compare(password, response.password);
        if (checkPass) {
            const token = jwt.sign({
                id: response._id.toString()
            }, JWT_SECRET, {
                expiresIn: '1h' // optional, adjust the expiration time as needed
            });

            res.json({
                token: token,
                message: "&#10004; Signed in"
            })
        } else {
            res.status(403).json({
                message: "Incorrect creds"
            })
        }
    }
    catch (error) {
        res.status(405).json({
            message: error
        })
    }
});

app.listen(process.env.PORT, () => console.log(`Server ready on port ${process.env.PORT}.`));
module.exports = app;