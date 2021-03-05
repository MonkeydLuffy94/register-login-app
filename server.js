const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const User = require("./model/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const app = express();

const JWT_SECRET =
  "jcwebclmlkmlcwkjbjkwebwbcbjwbwbcoiqweyzmxcmb@32374889234bcvjbkebrbekvb";

app.use("/", express.static(path.join(__dirname, "static")));
app.use(bodyParser.json());

const dbUrl = "mongodb://localhost:27017/user-management";

mongoose.connect(
  dbUrl,
  {
    useUnifiedTopology: true,
    useNewUrlParser: true,
    useCreateIndex: true,
  },
  (err) => {
    if (err) {
      console.log("MongoDB connection error", err);
    } else {
      console.log("MongoDB connected");
    }
  }
);

app.post("/api/register", async (req, res) => {
  const { userName, password: plainPassword } = req.body;

  if (!userName || typeof userName !== "string") {
    return res.json({ status: "error", message: "Username can not be empty" });
  }

  if (!plainPassword || typeof plainPassword !== "string") {
    return res.json({ status: "error", message: "Password can not be empty" });
  }

  if (plainPassword.length < 5) {
    return res.json({
      status: "ERROR",
      message: "Password is too small. It should be atleast 6 characters.",
    });
  }

  const password = await bcrypt.hash(plainPassword, 11);

  await User.create({
    userName,
    password,
  })
    .then((response) => {
      console.log("User created successfully: ", response);
      res.status(200).json({
        status: "OK",
        message: "Registration successful",
      });
    })
    .catch((err) => {
      console.log(err.message);
      if (err.code === 11000) {
        res.json({status: "ERROR", message: "Username already in use"});
      } else {
        res
          .status(400)
          .send(
            "Registration is not possible due to an unknown reason. Please try again."
          );
      }
    });
});

app.post("/api/login", (req, res) => {
  const { userName, password } = req.body;

  if (!userName || typeof userName !== "string") {
    return res.json({ status: "error", message: "Username can not be empty" });
  }

  if (!password || typeof password !== "string") {
    return res.json({ status: "error", message: "Password can not be empty" });
  }

  if (password.length < 5) {
    return res.json({
      status: "ERROR",
      message: "Password is too small. It should be atleast 6 characters.",
    });
  }

  User.findOne({ userName })
    .lean()
    .then((user) => {
      const wrongNamePassResponse = {
        status: "ERROR",
        message: "Invalid username or password.",
      };

      if (user) {
        const { _id, userName, password: encryptedPass } = user;
        bcrypt
          .compare(password, encryptedPass)
          .then((isMatch) => {
            if (isMatch) {
              const token = jwt.sign({ id: _id, userName }, JWT_SECRET);
              console.log("Login successful");
              res.json({
                status: "OK",
                message: "Login successful.",
                payload: token,
              });
            } else {
              res.json(wrongNamePassResponse);
            }
          })
          .catch((err) => {
            console.log(err.message);
          });
      } else {
        res.json(wrongNamePassResponse);
      }
    });
});

app.post("/api/change-password", (req, res) => {
  const { token, currentPass, newPass, confirmPass } = req.body;

  if (!currentPass || typeof currentPass !== "string") {
    return res.json({ status: "error", message: "Password can not be empty" });
  }

  if (currentPass.length < 5) {
    return res.json({
      status: "ERROR",
      message: "Unauthorised request for changing password.",
    });
  }

  if (newPass.length < 5) {
    return res.json({
      status: "ERROR",
      message: "New password is too small. It should be atleast 6 characters.",
    });
  }

  try {
    const { id } = jwt.verify(token, JWT_SECRET);
    User.findOne({ _id: id })
      .lean()
      .then((user) => {
        if (user) {
          // check if user is authorised to change password | check if entered old password is correct
          bcrypt.compare(currentPass, user.password).then((isMatched) => {
            if (isMatched) {
              // check if both new password entered correctly | confirm new password
              if (newPass === confirmPass) {
                //hash new password
                bcrypt
                  .hash(newPass, 11)
                  .then((hashedPass) => {
                    //update new password
                    User.updateOne(
                      { _id: id },
                      {
                        $set: { password: hashedPass },
                      }
                    ).then(() => {
                      console.log("Password has been changed successfully.");
                      res.json({
                        status: "OK",
                        message: "Password has been changed successfully.",
                      });
                    }).catch(err => {
                      res.json({
                        status: "ERROR",
                        message: "Password can not be changed due to " + err.message,
                      });
                    })
                  })
                  .catch((err) => {
                    res.json({ status: "ERROR", message: err.message });
                  });
              } else {
                res.json({
                  status: "ERROR",
                  message: "Password is not confirmed. Please try again.",
                });
              }
            } else {
              res.json({
                status: "ERROR",
                message: "Please enter your current password.",
              });
            }
          });
        }
      });
  } catch (err) {
    res.json({
      status: "ERROR",
      message: "Unauthorised request for changing password.",
    });
  }
});

app.listen(3001, () => {
  console.log("Server up at 3001");
});
