const User = require("../models/user")
const Token = require("../models/Token")  

const {StatusCodes} = require("http-status-codes")
const {BadRequestError,UnauthenticatedError} = require("../error/index")
const CustomError = require("../error/index")
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const crypto = require("crypto")
const { attachCookiesToResponse } = require("../utils/jwt")
const createTokenUser = require("../utils/createTokenUser")
const sendVerificationEmail = require("../utils/sendVerficationEmail")
const sendResetPasswordEmail = require("../utils/sendResetPasswordEmail")
const register = async (req,res,next)=>{
const sendResetPasswordEmail = require("../utils/sendResetPasswordEmail")
const createHash = require("../utils/createHash")
  // const {name,email,password} = req.body
  // // if(!name || !email || !password){
  // //   return next(new BadRequestError("Please provide name, email and password"))
  // // }
  // const salt = await bcrypt.genSalt(10)
  // const hashPassword  = await bcrypt.hash(password,salt)

  // const tempUser = {name,email,password:hashPassword}
  const {name,email,password} = req.body

  const emailAllreadyExist = await User.findOne({email})
  if (emailAllreadyExist){
    throw new BadRequestError('Email Allready Exist!!!')
  }
  const isFirstAccount = (await User.countDocuments({})) === 0;
  const role = isFirstAccount ? 'admin':'user'
  
  const verificationToken = crypto.randomBytes(40).toString('hex');

  const user = await User.create({
    name,
    email,
    password,
    role,
    verificationToken,
  });
  const origin = 'http://localhost:5000';
  // const newOrigin = 'https://react-node-user-workflow-front-end.netlify.app';

  // const tempOrigin = req.get('origin');
  // const protocol = req.protocol;
  // const host = req.get('host');
  // const forwardedHost = req.get('x-forwarded-host');
  // const forwardedProtocol = req.get('x-forwarded-proto');

  await sendVerificationEmail({
    name: user.name,
    email: user.email,
    verificationToken: user.verificationToken,
    origin,
  });
  // send verification token back only while testing in postman!!!
  res.status(StatusCodes.CREATED).json({
    msg: 'Success! Please check your email to verify account',
  });
};

const verifyEmail = async (req, res) => {
  const { verificationToken, email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    throw new CustomError.UnauthenticatedError('Verification Failed');
  }

  if (user.verificationToken !== verificationToken) {
    throw new CustomError.UnauthenticatedError('Verification Failed');
  }

  (user.isVerified = true), (user.verified = Date.now());
  user.verificationToken = '';

  await user.save();

  res.status(StatusCodes.OK).json({ msg: 'Email Verified' });
};

  // const token = createJWT({payload:tokenUser})
  // const token = jwt.sign({userId:user._id,name:user.name},'jwtSecret',{
  //   expiresIn:'30d'
  // })
  // const oneDay = 1000*60*60*24
  // res.cookie('token',token,{
  //   httpOnly:true,
  //   expires:new Date(Date.now() + oneDay)
  // })
  // res.status(StatusCodes.CREATED).json({user:tokenUser})
  // res.status(StatusCodes.CREATED).json({user:{name:user.getName()},token})



  const login = async (req, res) => {
    const { email, password } = req.body;
  
    if (!email || !password) {
      throw new CustomError.BadRequestError('Please provide email and password');
    }
    const user = await User.findOne({ email });
  
    if (!user) {
      throw new CustomError.UnauthenticatedError('Invalid Credentials');
    }
    const isPasswordCorrect = await user.comparePassword(password);
  
    if (!isPasswordCorrect) {
      throw new CustomError.UnauthenticatedError('Invalid Credentials');
    }
    if (!user.isVerified) {
      throw new CustomError.UnauthenticatedError('Please verify your email');
    }
    const tokenUser = createTokenUser(user);
  
    // create refresh token
    let refreshToken = '';
    // check for existing token
    const existingToken = await Token.findOne({ user: user._id });
  
    if (existingToken) {
      const { isValid } = existingToken;
      if (!isValid) {
        throw new CustomError.UnauthenticatedError('Invalid Credentials');
      }
      refreshToken = existingToken.refreshToken;
      attachCookiesToResponse({ res, user: tokenUser, refreshToken });
      res.status(StatusCodes.OK).json({ user: tokenUser });
      return;
    }
  
    refreshToken = crypto.randomBytes(40).toString('hex');
    const userAgent = req.headers['user-agent'];
    const ip = req.ip;
    const userToken = { refreshToken, ip, userAgent, user: user._id };
    console.log("userAgent:" + userAgent);
    console.log("ip:" + ip);

    await Token.create(userToken);
  
    attachCookiesToResponse({ res, user: tokenUser, refreshToken });
  
    res.status(StatusCodes.OK).json({ user: tokenUser });
  };

  const logout = async (req, res) => {
    await Token.findOneAndDelete({ user: req.user.userId });
  
    res.cookie('accessToken', 'logout', {
      httpOnly: true,
      expires: new Date(Date.now()),
    });
    res.cookie('refreshToken', 'logout', {
      httpOnly: true,
      expires: new Date(Date.now()),
    });
    res.status(StatusCodes.OK).json({ msg: 'user logged out!' });
  };

  const forgotPassword = async(req,res)=>{
    const {email} = req.body
    if (!email) {
      throw new CustomError.BadRequestError('Please provide email');
    }
    const user = await User.findOne({ email });
  
    if (!user) {
      throw new CustomError.UnauthenticatedError('Invalid Credentials');
    }
    const passwordToken = crypto.randomBytes(70).toString('hex')
    // send email
    const origin = 'http://localhost:5000';
    await sendResetPasswordEmail({
      name:user.name,
      email:user.email,
      token:passwordToken,
      origin
    })
    const tenMinutes = 1000*60*10
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes)
    //updating a db with including token and expiresDate 
    user.passwordToken = passwordToken
    user.passwordTokenExpirationDate = passwordTokenExpirationDate
    
    await user.save

    res.status(StatusCodes.OK).json({msg:"Plese checck your email for reset password"})
  } 
  const resetPassword = async (req,res)=>{
    const {token,email,password} = req.body
    if (!token || !email || !password){
      throw new CustomError.BadRequestError('Please provide all values');
    }
    const user = await User.findOne({email})
    if (!user){
      throw new CustomError.UnauthenticatedError('Invalid Credentials');
    }
    const currentDate = Date(Date.now())

    if (
      user.passwordToken === createHash(token)&&
      user.passwordTokenExpirationDate> currentDate
    ){
      // updating a password 
      user.password = password;
      user.passwordToken = null;
      user.passwordTokenExpirationDate = null;
      await user.save()
    }

    res.status(StatusCodes.OK).json({msg:"Your password successfully updated!!! Uraa"})


  }

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword
}