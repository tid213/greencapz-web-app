var bcrypt = require("bcryptjs");
const { body, validationResult } = require("express-validator");
var crypto = require("crypto");
var nodemailer = require("nodemailer");
var Users = require("../models/users");
var Token = require("../models/token");
var Reading = require("../models/readings");
var CurrentReading = require("../models/currentReading");
const { DateTime } = require("luxon");
var async = require("async");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
var session = require("express-session");

var session;

// Home page
exports.index = function (req, res) {
  console.log(req.session.username);
  res.render("homepage", {
    title: "Login or Sign up!",
    user: req.session.username,
  });
};

// Create User
exports.user_create_get = function (req, res) {
  if (req.session.username) {
    res.redirect("/users/dashboard");
  }
  res.render("create_user", { title: "Create Account" });
};

exports.user_create_post = [
  body("username")
    .trim()
    .isLength({ min: 5 })
    .escape()
    .withMessage("Username must be 5 characters or more."),
  body("password")
    .trim()
    .isLength({ min: 8 })
    .escape()
    .withMessage("Password must be 8 characters or more."),
  body("first_name")
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage("First name must be specified.")
    .isAlphanumeric()
    .withMessage("First name has non-alphanumeric characters."),
  body("last_name")
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage("Last name must be specified.")
    .isAlphanumeric()
    .withMessage("Last name has non-alphanumeric characters."),
  body("dob", "Invalid date of birth")
    .optional({ checkFalsy: true })
    .isISO8601()
    .toDate(),
  body("email").trim().isEmail().escape().withMessage("Enter valid email."),

  (req, res, next) => {
    const errors = validationResult(req);
    var errorMsgs = errors.array();
    var showError = [];

    if (!errors.isEmpty()) {
      // There are errors. Render form again with sanitized values/errors messages.
      for (i = 0; i < errorMsgs.length; i++) {
        showError.push(errorMsgs[i].msg);
      }
      res.render("create_user", { title: "Create Account", errors: showError });
      return;
    } else {
      async.parallel(
        {
          user: function (callback) {
            Users.find({ username: req.body.username }).exec(callback);
          },
          email: function (callback) {
            Users.find({ email: req.body.email }).exec(callback);
          },
        },
        function (err, results) {
          if (err) {
            return next(err);
          }
          if (results.user.length != 0 || results.email.length != 0) {
            var userTaken = ["Username or Email already in use"];
            res.render("create_user", {
              title: "Create Account",
              errors: userTaken,
            });
          } else {
            var user = new Users({
              username: req.body.username,
              password: req.body.password,
              first_name: req.body.first_name,
              last_name: req.body.last_name,
              dob: req.body.dob,
              email: req.body.email,
            });
            user.save(function (err) {
              if (err) {
                return next(err);
              }
              var token = new Token({
                _userId: user._id,
                token: crypto.randomBytes(16).toString("hex"),
              });

              token.save(function (err) {
                if (err) {
                  return res.status(500).send({ msg: err.message });
                }

                // Send the email
                var smtpConfig = {
                  host: "smtp.gmail.com",
                  port: 587,
                  secure: false, // use SSL
                  auth: {
                    user: "example@email.com",
                    pass: "password_here",
                  },
                };

                var transporter = nodemailer.createTransport(smtpConfig);
                var mailOptions = {
                  from: "no-reply@yourwebapplication.com",
                  to: user.email,
                  subject: "Account Verification Token",
                  text:
                    "Hello,\n\n" +
                    "Please verify your account by clicking the link: \nhttp://" +
                    req.headers.host +
                    "/users/" +
                    "confirmation/" +
                    token.token +
                    ".\n",
                };
                transporter.sendMail(mailOptions, function (err) {
                  if (err) {
                    return res.status(500).send({ msg: err.message });
                  }
                  res.render("verification", {
                    title: "Verification Sent",
                    text:
                      "A verification email has been sent to " +
                      user.email +
                      " please follow the link in your inbox.",
                  });
                });
              });
            });
          }
        }
      );
    }
  },
];

//User login get
exports.user_login = function (req, res) {
  if (req.session.username) {
    res.redirect("/users/dashboard");
  }
  res.render("login", { title: "Login" });
};

//User login post
exports.user_login_post = [
  // Validate and sanitize
  body("username", "Username required")
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage("Username required"),
  body("password", "Password required")
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage("Password required"),

  // Process request after validation and sanitization.
  (req, res, next) => {
    // Extract the validation errors from a request.
    const errors = validationResult(req);
    var errorMsgs = errors.array();
    var showError = [];

    if (!errors.isEmpty()) {
      // There are errors. Render form again with sanitized values/errors messages.
      for (i = 0; i < errorMsgs.length; i++) {
        showError.push(errorMsgs[i].msg);
      }
      res.render("login", { title: "Login", errors: showError });
      return;
    } else {
      Users.findOne({ username: req.body.username }).exec(function (
        err,
        user_name
      ) {
        if (err) {
          return next(err);
        }
        let invalidMatch = ["WRONG USERNAME OR PASSWORD"];
        if (user_name) {
          let password = req.body.password;
          let hash = user_name.password;
          bcrypt.compare(password, hash, function (error, isMatch) {
            if (error) {
              throw error;
            } else if (!isMatch) {
              res.render("login", { title: "Login", errors: invalidMatch });
            } else {
              if (!user_name.isVerified)
                return res.render("resend_verification");
              req.session.loggedIn = true;
              req.session.username = req.body.username;
              console.log(req.session.username);
              res.redirect("/users/dashboard");
            }
          });
        } else {
          res.render("login", { title: "Login", errors: invalidMatch });
        }
      });
    }
  },
];

//// Email Validation confirmation/resend POST
exports.confirmationPost = function (req, res, next) {
  Token.findOne({ token: req.params.token }, function (err, token) {
    if (!token)
      return res.status(400).send({
        type: "not-verified",
        msg: "We were unable to find a valid token. Your token my have expired.",
      });

    // If we found a token, find a matching user
    Users.findOne({ _id: token._userId }, function (err, user) {
      if (!user)
        return res
          .status(400)
          .send({ msg: "We were unable to find a user for this token." });
      if (user.isVerified)
        return res.status(400).send({
          type: "already-verified",
          msg: "This user has already been verified.",
        });

      // Verify and save the user
      user.isVerified = true;
      user.save(function (err) {
        if (err) {
          return res.status(500).send({ msg: err.message });
        }
        res.render("confirmation", {
          title: "Verification Successful!",
          text: "Thanks for verifying, you can now login!",
        });
      });
    });
  });
};
//

exports.resendTokenPost = [
  // Validate and sanitize
  body("email", "email required").trim().isEmail().escape(),

  // Process request after validation and sanitization.
  (req, res, next) => {
    // Extract the validation errors from a request.
    const errors = validationResult(req);
    var errorMsgs = errors.array();
    var showError = [];

    if (!errors.isEmpty()) {
      // There are errors. Render form again with sanitized values/errors messages.
      for (i = 0; i < errorMsgs.length; i++) {
        showError.push(errorMsgs[i].msg);
      }
      res.render("resend_verification", {
        title: "Verification",
        text: "Enter email to resend verification",
        errors: showError,
      });
      return;
    } else {
      let invalidEmail = ["Invalid email"];
      let verificationMatch = ["Account already verified, please login"];
      Users.findOne({ email: req.body.email }, function (err, user) {
        if (!user)
          return res.render("resend_verification", {
            title: "Verification",
            text: "Enter email to resend verification",
            errors: invalidEmail,
          });
        if (user.isVerified)
          return res.render("resend_verification", {
            title: "Verification",
            text: "Enter email to resend verification",
            errors: verificationMatch,
          });

        // Create a verification token, save it, and send email
        var token = new Token({
          _userId: user._id,
          token: crypto.randomBytes(16).toString("hex"),
        });

        // Save the token
        token.save(function (err) {
          if (err) {
            return res.status(500).send({ msg: err.message });
          }
          var smtpConfig = {
            host: "smtp.gmail.com",
            port: 587,
            secure: false, // use SSL
            auth: {
              user: "example@email.com",
              pass: "password_here",
            },
          };
          // Send the email
          var transporter = nodemailer.createTransport(smtpConfig);
          var mailOptions = {
            from: "no-reply@yourwebapplication.com",
            to: user.email,
            subject: "Account Verification Token",
            text:
              "Hello,\n\n" +
              "Please verify your account by clicking the link: \nhttp://" +
              req.headers.host +
              "/users/" +
              "confirmation/" +
              token.token +
              ".\n",
          };
          transporter.sendMail(mailOptions, function (err) {
            if (err) {
              return res.status(500).send({ msg: err.message });
            }
            res.render("verification", {
              title: "Verification Sent",
              text:
                "A verification email has been sent to " +
                user.email +
                " please follow the link in your inbox.",
            });
          });
        });
      });
    }
  },
];

//Logout
exports.user_logout = function (req, res) {
  req.session.destroy((err) => {});
  res.redirect("/");
  console.log(req.session);
};

//User dashboard
exports.user_dashboard = function (req, res) {
  if (req.session.loggedIn) {
    Users.findOne({ username: req.session.username }, function (err, user) {
      if (!user)
        return res
          .status(400)
          .send({ type: "not-verified", msg: "None valid user" });
      CurrentReading.find(
        { _userId: user._id },
        function (err, currentReading) {
          var temperature1 = currentReading[0].measurements; //Water temp
          var temperature2 = currentReading[1].measurements; //Tent temp
          var temperature3 = currentReading[2].measurements; //Room temp
          var ppm1 = currentReading[3].measurements;

          Reading.find({ _userId: user._id }, function (err, userreading) {
            console.log(userreading.length);
            if (userreading.length != 0) {
              var reading = userreading[0].measurements;
              var reading2 = userreading[1].measurements;
              var sensor_name = userreading[0].sensor_id;
              var sensor_name2 = userreading[1].sensor_id;
              var timeStamp = [];
              var timeStamp2 = [];
              var readings = [];
              var readings2 = [];
              var readings_max = reading.length - 42;
              for (i = 0; i < 42; i++) {
                timeStamp.push(
                  DateTime.fromJSDate(
                    reading[readings_max + i].timestamp
                  ).toFormat("LLL d, t")
                );
                readings.push(reading[readings_max + i].sensor_reading);
              }
              for (i = 0; i < 42; i++) {
                timeStamp2.push(
                  DateTime.fromJSDate(
                    reading2[readings_max + i].timestamp
                  ).toFormat("LLL d, t")
                );
                readings2.push(reading2[readings_max + i].sensor_reading);
              }
              var reading_count = readings.length + readings2.length;
              var sensor_data = {
                labels: timeStamp,
                datasets: [
                  {
                    label: sensor_name,
                    data: readings,
                    backgroundColor: ["rgba(0, 255, 0, 1)"],
                    borderColor: ["rgba(0, 255, 0, 1)"],
                    borderWidth: 2,
                  },
                ],
              };
              var sensor_data2 = {
                labels: timeStamp2,
                datasets: [
                  {
                    label: sensor_name2,
                    data: readings2,
                    backgroundColor: ["rgba(0, 255, 0, 1)"],
                    borderColor: ["rgba(0, 255, 0, 1)"],
                    borderWidth: 2,
                  },
                ],
              };
              var chart_options = {
                plugins: {
                  legend: {
                    display: true,
                    labels: {
                      color: "white",
                    },
                  },
                },
                scales: {
                  y: {
                    beginAtZero: true,
                    grid: {
                      color: "grey",
                    },
                    max: 120,
                    ticks: {
                      color: "white",
                    },
                  },
                  x: {
                    grid: {
                      color: "grey",
                    },
                    ticks: {
                      display: false,
                    },
                  },
                },
              };
              var chart_options2 = {
                plugins: {
                  legend: {
                    display: true,
                    labels: {
                      color: "white",
                    },
                  },
                },
                scales: {
                  y: {
                    beginAtZero: true,
                    grid: {
                      color: "grey",
                    },
                    max: 900,
                    ticks: {
                      color: "white",
                    },
                  },
                  x: {
                    grid: {
                      color: "grey",
                    },
                    ticks: {
                      display: false,
                    },
                  },
                },
              };

              //Converting UTC to Arizona time//

              let newDate = temperature1[0].timestamp;
              var ldate = DateTime.fromJSDate(newDate);
              var ldate = ldate.setZone("utc");
              var convertedDate = DateTime.local();
              convertedDate = convertedDate.setZone("UTC+7");
              convertedDate = convertedDate.set({
                year: ldate.year,
                month: ldate.month,
                day: ldate.day,
                hour: ldate.hour,
                minute: ldate.minute,
                second: ldate.second,
                millisecond: ldate.millisecond,
              });
              var azDate = convertedDate.toJSDate();
              //
              res.render("dashboard", {
                user: req.session.username,
                sensor_data: sensor_data,
                sensor_data2: sensor_data2,
                reading_count: reading_count,
                chart_options: chart_options,
                chart_options2: chart_options2,
                temperature_1: temperature1[0].sensor_reading,
                temperature_2: temperature2[0].sensor_reading,
                temperature_3: temperature3[0].sensor_reading,
                ppm: ppm1[0].sensor_reading,
                status: "live",
                time_temp_1: DateTime.fromJSDate(azDate).toFormat("LLL d, t"),
              });
              res.end();
            } else {
              res.render("dashboard", { user: req.session.username });
              res.end();
            }
          });
        }
      );
    });
  } else {
    res.redirect("/");
  }
};

// Change password
exports.password_change_get = function (req, res) {
  if (req.session.loggedIn) {
    res.render("change_password", {
      title: "Change Password",
      user: req.session.username,
    });
  } else {
    res.redirect("/");
  }
};

exports.password_change_post = [
  // Validate and sanitize
  body("current_password", "Password required")
    .trim()
    .isLength({ min: 1 })
    .escape(),
  body("password", "Password required").trim().isLength({ min: 8 }).escape(),

  // Process request after validation and sanitization.
  (req, res, next) => {
    // Extract the validation errors from a request.
    const errors = validationResult(req);
    var errorMsgs = errors.array();
    var showError = [];

    if (!errors.isEmpty()) {
      // There are errors. Render the form again with sanitized values/error messages.
      for (i = 0; i < errorMsgs.length; i++) {
        showError.push(errorMsgs[i].msg);
      }
      res.render("change_password", {
        title: "Change Password",
        errors: showError,
        user: req.session.username,
      });
      return;
    } else {
      Users.findOne({ username: req.session.username }).exec(function (
        err,
        user_name
      ) {
        if (err) {
          return next(err);
        }

        if (user_name) {
          let new_password = req.body.password;
          let password = req.body.current_password;
          let hash = user_name.password;
          bcrypt.compare(password, hash, function (error, isMatch) {
            if (error) {
              throw error;
            } else if (!isMatch) {
              var failedMatch = ["PASSWORDS DO NOT MATCH"];
              res.render("change_password", {
                title: "Change Password",
                errors: failedMatch,
              });
            } else {
              user_name.password = new_password;
              user_name.save(function (err) {
                if (err) {
                  return next(err);
                }
                res.render("change_password_success", {
                  title: "Successfully changed password",
                  user: req.session.username,
                });
              });
            }
          });
        } else {
          res.redirect("/users/login");
        }
      });
    }
  },
];

// Delete User
exports.user_delete_get = function (req, res) {
  if (req.session.loggedIn) {
    res.render("delete_user", {
      title:
        "WARNING!!! ONCE USER IS DELETED ALL ASSOSIATED READINGS WILL ALSO BE REMOVED.  CLICK THE BUTTON BELOW TO PROCEED.",
      user: req.session.username,
    });
  } else {
    res.redirect("/");
  }
};
exports.user_delete_post = function (req, res) {
  Users.findOne({ username: req.session.username }).exec(function (err, user) {
    if (err) {
      return next(err);
    }
    var token = new Token({
      _userId: user._id,
      token: crypto.randomBytes(16).toString("hex"),
    });
    token.save(function (err) {
      if (err) {
        return res.status(500).send({ msg: err.message });
      }

      // Send the email
      var smtpConfig = {
        host: "smtp.gmail.com",
        port: 587,
        secure: false, // use SSL
        auth: {
          user: "example@email.com",
          pass: "password_here",
        },
      };

      var transporter = nodemailer.createTransport(smtpConfig);
      var mailOptions = {
        from: "no-reply@yourwebapplication.com",
        to: user.email,
        subject: "Account Delete Token",
        text:
          "Hello,\n\n" +
          "Please follow the link to proceed with account deletion: \nhttp://" +
          req.headers.host +
          "/users/" +
          "delete/" +
          token.token +
          ".\n",
      };
      transporter.sendMail(mailOptions, function (err) {
        if (err) {
          return res.status(500).send({ msg: err.message });
        }
        res.render("verification", {
          title: "Delete Account",
          text:
            "A verification email has been sent to " +
            user.email +
            " please follow the link in your inbox to continue the process.",
        });
      });
    });
  });
};
exports.user_delete_confirmation = function (req, res, next) {
  Token.findOne({ token: req.params.token }, function (err, token) {
    if (!token)
      return res.status(400).send({
        type: "not-verified",
        msg: "We were unable to find a valid token. Your token my have expired.",
      });

    // If we found a token, find a matching user
    Users.findOne({ _id: token._userId }, function (err, user) {
      if (!user)
        return res
          .status(400)
          .send({ msg: "We were unable to find a user for this token." });

      user.deleteOne(function (err) {
        if (err) {
          return res.status(500).send({ msg: err.message });
        }
        res.render("confirmation", { title: "Your Account has been deleted!" });
      });
    });
  });
};

// Update User info
exports.user_update_get = function (req, res) {
  if (req.session.loggedIn) {
    Users.findOne({ username: req.session.username }).exec(function (
      err,
      user_name
    ) {
      if (err) {
        return next(err);
      }
      res.render("update_user", {
        title: "Update user info.",
        user: req.session.username,
        user_name: user_name,
        first_name: user_name.first_name,
        last_name: user_name.last_name,
        dob: user_name.dob,
        email: user_name.email,
      });
    });
  } else {
    res.redirect("/");
  }
};
exports.user_update_post = [
  body("first_name")
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage("First name must be specified.")
    .isAlphanumeric()
    .withMessage("First name has non-alphanumeric characters."),
  body("last_name")
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage("Last name must be specified.")
    .isAlphanumeric()
    .withMessage("Last name has non-alphanumeric characters."),
  body("dob", "Invalid date of birth")
    .optional({ checkFalsy: true })
    .isISO8601()
    .toDate(),

  (req, res, next) => {
    const errors = validationResult(req);
    var errorMsgs = errors.array();
    var showError = [];

    if (!errors.isEmpty()) {
      for (i = 0; i < errorMsgs.length; i++) {
        showError.push(errorMsgs[i].msg);
      }
      // There are errors. Render form again with sanitized values/errors messages.
      res.render("update_user", {
        title: "Update user info.",
        errors: showError,
        user: req.session.username,
      });
      return;
    } else {
      Users.findOneAndUpdate(
        { username: req.session.username },
        {
          first_name: req.body.first_name,
          last_name: req.body.last_name,
          dob: req.body.dob,
          email: req.body.email,
        }
      ).exec(function (err, user_name) {
        if (err) {
          return next(err);
        }
        res.redirect("/users/dashboard");
      });
    }
  },
];

exports.forgot_password_get = function (req, res) {
  res.render("forgot_password", {
    title: "Forgot Password",
    text: "Enter email to reset password.",
  });
};

exports.forgot_password_post = [
  // Validate and sanitize
  body("email", "email required")
    .trim()
    .isEmail()
    .escape()
    .withMessage("Invalid Email"),

  // Process request after validation and sanitization.
  (req, res, next) => {
    // Extract the validation errors from a request.
    const errors = validationResult(req);
    var errorMsgs = errors.array();
    var showError = [];

    if (!errors.isEmpty()) {
      // There are errors. Render the form again with sanitized values/error messages.
      for (i = 0; i < errorMsgs.length; i++) {
        showError.push(errorMsgs[i].msg);
      }
      res.render("forgot_password", {
        title: "Forgot Password",
        text: "Enter email to reset password",
        errors: showError,
      });
      return;
    } else {
      let invalidEmail = ["Invalid email"];
      Users.findOne({ email: req.body.email }, function (err, user) {
        if (!user)
          return res.render("forgot_password", {
            title: "Forgot Password",
            text: "Enter email to reset password",
            errors: invalidEmail,
          });

        // Create a verification token, save it, and send email
        var token = new Token({
          _userId: user._id,
          token: crypto.randomBytes(16).toString("hex"),
        });

        // Save the token
        token.save(function (err) {
          if (err) {
            return res.status(500).send({ msg: err.message });
          }
          var smtpConfig = {
            host: "smtp.gmail.com",
            port: 587,
            secure: false, // use SSL
            auth: {
              user: "example@email.com",
              pass: "password_here",
            },
          };
          // Send the email
          var transporter = nodemailer.createTransport(smtpConfig);
          var mailOptions = {
            from: "no-reply@yourwebapplication.com",
            to: user.email,
            subject: "Password Reset",
            text:
              "Hello,\n\n" +
              "Reset your password by clicking the link: \nhttp://" +
              req.headers.host +
              "/users/" +
              "resetpassword/" +
              token.token +
              ".\n",
          };
          transporter.sendMail(mailOptions, function (err) {
            if (err) {
              return res.status(500).send({ msg: err.message });
            }
            res.render("verification", {
              title: "Password Reset",
              text:
                "A link has been sent to: " +
                user.email +
                " please follow the link to continue password reset.",
            });
          });
        });
      });
    }
  },
];
exports.reset_password_get = function (req, res, next) {
  Token.findOne({ token: req.params.token }, function (err, token) {
    if (!token) return res.redirect("/users/forgotpassword");

    // If we found a token, find a matching user
    Users.findOne({ _id: token._userId }, function (err, user) {
      if (!user)
        return res
          .status(400)
          .send({ msg: "We were unable to find a user for this token." });
      res.render("reset_password", {
        title: "Reset Password",
        text: "Please enter your new password below.",
      });
    });
  });
};

exports.reset_password_post = [
  // Validate and sanitize
  body("password", "Password required")
    .trim()
    .isLength({ min: 8 })
    .escape()
    .withMessage("Invalid Password"),

  // Process request after validation and sanitization.
  (req, res, next) => {
    // Extract the validation errors from a request.
    const errors = validationResult(req);

    var errorMsgs = errors.array();
    var showError = [];

    if (!errors.isEmpty()) {
      // There are errors. Render the form again with sanitized values/error messages.
      for (i = 0; i < errorMsgs.length; i++) {
        showError.push(errorMsgs[i].msg);
      }
      res.render("reset_password", {
        title: "Reset Password",
        text: "Please enter your new password below.",
        errors: showError,
      });
    } else {
      Token.findOne({ token: req.params.token }, function (err, token) {
        if (!token)
          return res.status(400).send({
            type: "not-verified",
            msg: "We were unable to find a valid token. Your token my have expired.",
          });

        // If we found a token, find a matching user
        Users.findOne({ _id: token._userId }, function (err, user) {
          if (!user)
            return res
              .status(400)
              .send({ msg: "We were unable to find a user for this token." });
          user.password = req.body.password;
          user.save(function (err) {
            if (err) {
              return next(err);
            }
            res.render("change_password_success", {
              title: "Successfully changed your password, now you can login",
              user: req.session.username,
            });
          });
        });
      });
    }
  },
];

exports.about_page_get = function (req, res) {
  res.render("about", { user: req.session.username });
};
