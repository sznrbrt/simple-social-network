'use strict';

var mongoose = require('mongoose');
var jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || "saddad3434sjahdjd343242sadjah343242";

var userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  biography: { type: String },
  profileImg: { type: String },
  website: { type: String }
});

// IT'S MIDDLEWARE!!
userSchema.statics.isLoggedIn = function(req, res, next) {
  var token = req.cookies.accessToken;

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if(err) return res.status(401).send({error: 'Must be authenticated.'});

    User
      .findById(payload._id)
      .select({password: false})
      .exec((err, user) => {
        if(err || !user) {
          return res.clearCookie('accessToken').status(400).send(err || {error: 'User not found.'});
        }

        req.user = user;
        next();
      })
  });
};

userSchema.statics.register = function(userObj, cb) {
  this.create(userObj, cb);
};

userSchema.statics.editProfile = function(userId, newUser, cb) {
  User.findByIdAndUpdate(userId, { $set: newUser }, {new: true}, cb);
};

userSchema.statics.authenticate = function(userObj, cb) {
  // find the user by the username
  // confirm the password

  // if user is found, and password is good, create a token
  this.findOne({username: userObj.username}, (err, dbUser) => {
    if(err || !dbUser) return cb(err || { error: 'Login failed. Username or password incorrect.' });

    if(dbUser.password !== userObj.password) {
      return cb({error: 'Login failed. Username or password incorrect.'});
    }

    var token = dbUser.makeToken();

    cb(null, token);
  });
};

userSchema.methods.makeToken = function() {
  var token = jwt.sign({ _id: this._id }, JWT_SECRET);
  return token;
};

var User = mongoose.model('User', userSchema);

module.exports = User;
