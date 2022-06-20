// model for the user :
import lodash from 'lodash';
import mongoose from "mongoose";
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import bcrypt from "bcryptjs";
import dotenv from 'dotenv';
const _=lodash;
const reject = lodash;
//handling .env variables :- this method is used to handle the .env variables
dotenv.config();
const jwtsecret = process.env.JWT;


const UserShema = new mongoose.Schema({
    email:{
        type: String,
        required: false,
        unique: true,
        minlength: 1,
        trim: true,
    },
    password:{
        type: String,
        required: false,
        minlength: 8,

    },
    sessions:[{
            token : {
                type: String,
                required: false,
            },
            expires: {
                type: Number,
                required: false,
            }
    }]

});
// MAIN METHODES :- this method is used to 
// Create a new user 
UserShema.methods.toJSON = function () {
    const user = this;
    const userObject = user.toObject();
    // retreive doc without password and sessions fields (its shoudn't be sent to the client (not public)
    return _.omit(userObject, ['password', 'sessions']);
}
// generate a token for the user
 UserShema.methods.generateAuthToken = function () {
    const user = this;
    return new Promise((resolve, reject) => {
        jwt.sign({_id: user._id.toHexString()}, jwtsecret,{expiresIn: '10m'},(error,token)=>{
            if(!error){
                resolve(token);
            }
           else{
            reject();
           }
        });
    })
    
 }
 // generate a refresh token :- this method is used to generate a refresh token for the user
UserShema.methods.generateRefreshAuthToken = function () {
        //this moethide generate a 64byte hex string
        return new Promise((resolve, reject) => {
                crypto.randomBytes(64, (error, buffer) => {
                    if (!error) {
                        let token = buffer.toString('hex');
                        resolve(token);
                    }
                })
        })
    }
//Create a Session :- this method is used to create a session for the user
UserShema.methods.createSession = function () {

    let User = this;
    return User.generateRefreshAuthToken().then((refreshToken) => {
        return SaveSession(User, refreshToken);
    }).then((refreshToken)=>{
        //saved to DB successfully
        //return the refresh token
        return refreshToken;
    }).catch((error) => {
        return Promise.reject("Failder to save :" + error);
    })

}
// MODEL MOTHODES :

UserShema.statics.findByToken = function(_id,token) {
//find the user by the token and id
//used by the Medllware in authentication.
const User = this;

return User.findOne({
    _id,
    'sessions.token':token});
}

//  this method is used to check if the user is logged in with the right credentials.
UserShema.statics.findByAccess = function(email, password){
    let User=this;
    return User.findOne({email})
    .then((user)=>{
        if(!user){return Promise.reject("User not found");}
        else{
            return new Promise((resolve,reject)=>{
                bcrypt.compare(password,user.password,(error,result)=>{
                    if(result){
                        resolve(user);
                    }
                    else{
                        reject("Incorrect password");
                    }
                })
            })
        }
    })

}

// MIDDLEWARE :- this method is used to
// before saving the user to the DB to encrypt the password
UserShema.pre('save', function (next) {
    let user = this;
    if (user.isModified('password')) {
        bcrypt.genSalt(10, (error, salt) => {
            bcrypt.hash(user.password, salt, (error, hash) => {
                user.password = hash;
                next();
            })})
        }else{
            next();
        }
    }
)
// SUB METHODES 
// save the session to the DB
let SaveSession =  (user, expiredrefreshTokens) =>{
       
        //save the session to DB
        return new Promise((resolve, reject) => {
           let expires =  TokenExpireTime();
           user.sessions.push({'token':expiredrefreshTokens,'expires':expires});
        //    user.sessions={...user.sessions,'token':expireredfreshTokens,"expires": ExprieAt}
           
           user.save().then(() => {
            //saved seccessfully
            return resolve(expiredrefreshTokens); 
        }).catch((error) => {
            reject(error);
        })

    })
    }
// calculate the time of the token expiry
let TokenExpireTime = () =>{
        let daysUnitExprie="5";
        let secondsUnitExprie = ((daysUnitExprie * 24) * 60) * 60;
        return (Date.now() + secondsUnitExprie);

    }
//Check Refresh Token :- this method is used to check if the refresh token is expired or not
UserShema.statics.IsRefreshTokenExpired = (expire) => {
    let Second = Date.now() / 1000;
    if(expire>Second){
        //the token is not expired
        return false;
    }else{
        //the token is expired
        return true;
    }
}
export default mongoose.model('User', UserShema);