var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');

var Schema = mongoose.Schema;

var UserSchema = new Schema (
    {
        "username": {type: String},
        "email": {type: String},
        "isVerified": { type: Boolean, default: false },
        "password": {type: String},
        "first_name": {type: String},
        "last_name": {type: String},
        "dob": {type: Date},
        "measurements": [
            {
                "sensor_id": {type: String},
                "timestamp" : {type: Date},
                "sensor_reading": {type: Number}
            }
        ]
    }
);

UserSchema.pre("save", function (next) {
    const user = this
  
    if (this.isModified("password") || this.isNew) {
      bcrypt.genSalt(10, function (saltError, salt) {
        if (saltError) {
          return next(saltError)
        } else {
          bcrypt.hash(user.password, salt, function(hashError, hash) {
            if (hashError) {
              return next(hashError)
            }
  
            user.password = hash
            next()
          })
        }
      })
    } else {
      return next()
    }
  })

  UserSchema.methods.comparePassword = function(password, callback) {
    bcrypt.compare(password, this.password, function(error, isMatch) {
      if (error) {
        return callback(error)
      } else {
        callback(null, isMatch)
      }
    })
  }


module.exports = mongoose.model('User', UserSchema);