/* eslint-disable unused-imports/no-unused-imports */
/* eslint-disable no-trailing-spaces */
/* eslint-disable semi */
/* eslint-disable unused-imports/no-unused-vars */
import { NextFunction, Request, Response } from "express"
import HttpStatusCode from "http-status-codes"
import { suid } from 'rand-token'
import validator from 'validator'
import User from '../models/user.model'
import passport from 'passport'
import * as GoogleStrategy from "passport-google-oauth20"
// import { Strategy as GoogleStrategy } from 'passport-google-oauth20'

// import config from "../configurations/config"
import { UserDocument } from "../interfaces/user.interface"
import { createAccessToken } from "../services/auth.service"
import UserService from "../services/user.service"
import { generateRefreshToken } from "../services/userToken"
import commonUtilitie from "../utilities/common"
import { sendEmail, sendEmailVerification } from "../utils/email.util"
import config from '../configurations/config'
import { Session } from 'express-session';
import { v4 as uuidv4 } from 'uuid';
import TempToken from '../models/tempToken.model'; // You'll need to create this model
import * as dotenv from 'dotenv';

dotenv.config();



// import passport from "passport"
// import { IVerifyOptions } from "passport-local"

// import "../config/passport"
// import HttpException from "../exceptions/HttpException"
// import { AdminDocument } from "../interfaces/admin.interface"
// import RequestWithAdmin from "../interfaces/requestWithAdmin"
// import { refreshToken as refreshToken1, removeAllTokens } from "../services/adminAuth"
// import { generateRefreshToken } from "../services/adminToken"
// import { sign } from "../utils/jwt.util"

interface MyUserRequest extends Request {
  user?: any;
}

// Add this interface at the top of your file
interface CustomSession extends Session {
  passport?: { user: { userId: string, token: string } };
}

/**
 * Used to check login credentials of admin and generate access token
 * @param req Request
 * @param res Response
 * @param next NextFunction
 */

const apiAdminLogin = async (req: Request, res: Response, _next: NextFunction) => {

  const payload: any = req.body ? req.body : undefined

  const loginSecure = suid(50)
  const findAdminResponse: any = await UserService.findUser({ 'email': payload.email })
  await UserService.updateUser(findAdminResponse.id, { 'loginSecure': loginSecure })

  //remove the static url and replce it with frontend admin dashboard url
  const templateData = {
    url: `${config.LOCAL_SERVER.host_url}/auth/checkAuthentication/${payload.email}/${loginSecure}`
  }

  const subject = `Verify your account`
  const to = payload.email
  const from = {
    email: process.env.SENDGRID_FROM_EMAIL,
    name: "Cure Migraine"
  }
  const html = `
  <p>Hi</p>
  <p>Please click on the following <a href="${templateData.url}">link</a> to verify your account.</p> 
  <p>If you did not request this, please ignore this email.</p>`

  await sendEmail({ to, from, subject, html })

  // Send template
  //remove the static sender id and replce it with payload.email
  // const res_ = await sendTemplate(payload.email, "Admin Verify Authentication", config.sendGrid.VERIFY_ADMIN_TEMPLATE, templateData)

  // console.log("res_", res_)

  return res.status(200).send({
    status: true,
    message: "Login Success, Check Mail for Authentication Link"
  })

}

/**
 * @summary - Resend admin login email API required
 * @param req
 * @param res
 * @param _next
 * @returns
 */
const resendApiAdminLogin = async (req: Request, res: Response, _next: NextFunction) => {

  const payload: any = req.body ? req.body : undefined

  const findAdminResponse: any = await UserService.findUser({ 'email': payload.email })
  const loginSecure = findAdminResponse.loginSecure

  if (!loginSecure) {
    return res.status(HttpStatusCode.BAD_REQUEST).send({
      status: false,
      message: `Kindly login again.`
    })
  }

  const templateData = {
    url: `${config.LOCAL_SERVER.host_url}/auth/checkAuthentication/${payload.email}/${loginSecure}`
  }

  const subject = `Verify your account`
  const to = payload.email
  const from = {
    email: process.env.SENDGRID_FROM_EMAIL,
    name: "Cure Migraine"
  }
  const html = `
  <p>Hi</p>
  <p>Please click on the following <a href="${templateData.url}">link</a> to verify your account.</p> 
  <p>If you did not request this, please ignore this email.</p>`

  await sendEmail({ to, from, subject, html })

  return res.status(200).send({
    status: true,
    message: "Email sent successfully."
  })
}

/**
 * @summary - Forgot password
 * @param req
 * @param res
 * @returns
 */
const forgetPassword = async (req: Request, res: Response) => {
  let statusCode = 500

  try {
    const { email } = req.body
    if (!email) {
      statusCode = 400
      throw new Error("'email' is required.")
    }

    const user: any = await UserService.findUser({ email })

    if (!user) {
      statusCode = 400
      throw new Error(`The email: ${email} is not associated with any account`)
    }

    // Generate and set password reset token
    user.generatePasswordReset()

    // Send email
    let subject = `Password change request`
    let to = user.email
    let from = {
      email: process.env.SENDGRID_FROM_EMAIL,
      name: "Cure Migraine"
    }
    let link = `${config.LOCAL_SERVER.host_url}/reset-password/${user.resetPasswordToken}`
    // let link = `${config.API_URL}/reset-password/${user.resetPasswordToken}`
    let html = `
    <p>Hi ${user.firstName},</p>
    <p>No stress! Remembering passwords can be pain in the neck - which for some is a trigger and for some it is a symptom of migraine. Let's get you back on track so you can continue your journey to a migraine-free life.</p>
    <p>Click the link below to reset your password:</p>
    <a href="${link}">${link}</a>
    <p>Remember, passwords are like toothbrushes – you should change them often and never share them with anyone else!</p>
    <p>Cheers,
    <br>
    The Scandinavian Method Team
    </p>
    `

    await sendEmail({ to, from, subject, html })


    // Save the updated user object
    await user.save()

    return res.status(200).json({
      message: `A reset password email has been sent to ${user.email}`
    })
  } catch (error: any) {
    // console.log(error.message)
    return res.status(statusCode).json({
      success: false,
      error: {
        code: statusCode,
        rawErrorMessage: error.response?.data?.message || "An error has occurred"
      },
      message: error.message || "An error has occurred"
    })
  }
}

/**
 * @summary - Reset password
 * @param req
 * @param res
 * @returns
 */
const resetPassword = async (req: Request, res: Response) => {
  try {
    const { token } = req.params

    const user: any = await UserService.findUser({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    })

    if (!user)
      return res
        .status(401)
        .json({ message: `Password reset token is invalid or has expired. Please try again` })

    // set the new password
    user.password = req.body.password
    user.resetPasswordToken = undefined
    user.resetPasswordExpires = undefined
    user.isVerified = true

    // save the updated user
    await user.save()

    // Send a password successfully reset confirmation email
    let subject = 'Your password has been changed'
    let to = user.email
    let from = {
      email: "no-reply@davigate.com",
      name: "Davigate"
    }
    let html = `
    <br />
    <p>Hi ${user.firstName},</p>
    <p>This is a confirmation that the password for your account ${user.email} has just been changed.</p>
    <p>If you did not ask to make this change, please contact <a href="mailto:support@davigate.com" style="color:blue;">support@davigate.com</a> immediately.</p>`

    await sendEmail({ to, from, subject, html })

    res.status(200).json({ status: true, message: `Your password has been updated` })
  } catch (error: any) {
    return res.status(500).send({
      status: false,
      message: error.message
    })
  }
}

const apiCheckAuthentication = async (req: Request, res: Response, _next: NextFunction) => {
  const email: any = req.params.email?.toString()
  const loginSecure: any = req.params.loginSecure?.toString()

  const admin: any = await UserService.findUser({ 'email': email })

  if (!admin) {
    return res.status(HttpStatusCode.BAD_REQUEST).send({
      status: false,
      message: "Admin not found by Given Email"
    })
  }

  // console.log(admin.loginSecure)

  if (admin.loginSecure === loginSecure) {
    //delete admin.loginSecure
    //generate token here and pass forward
    const tokens: Object = await generateAccessTokenAndRefreshToken(admin, req)
    // console.log("tokens", tokens)
    delete admin._doc.loginSecure
    return res.status(HttpStatusCode.OK).send({
      status: true,
      data: {
        ...admin._doc,
        ...tokens
      },
      message: "Logged-in successful"
    })

  } else {
    return res.status(HttpStatusCode.BAD_REQUEST).send({
      status: false,
      message: "Authentication Failed"
    })
  }


}

const apiCheckAuthenticationUser = async (req: Request, res: Response, _next: NextFunction) => {
  const email: any = req.params.email?.toString()

  const admin: any = await UserService.findUser({ 'email': email })

  if (admin) {
    // Update isVerified to true
    admin.isVerified = true
    await admin.save()

    // Generate token here and pass forward
    const tokens: Object = await generateAccessTokenAndRefreshToken(admin, req)
    delete admin._doc.loginSecure
    return res.status(HttpStatusCode.OK).send({
      status: true,
      data: {
        ...admin._doc,
        ...tokens
      },
      message: "Logged-in successful"
    })
  } else {
    return res.status(HttpStatusCode.BAD_REQUEST).send({
      status: false,
      message: "Authentication Failed"
    })
  }
}

const generateAccessTokenAndRefreshToken = async (user: any, req: Request) => {
  const token = user.generateJWT()
  const refreshToken = await generateRefreshToken(user._id, req)
  return { token, refreshToken }
}

/**
 * @summary - Register a patient
 * @param req
 * @param res
 * @returns
 */
const register = async (req: Request, res: Response) => {
  let statusCode = 500

  try {
    const { email, password, firstName, lastName, age } = req.body

    // validate request
    commonUtilitie.validateRequestForEmptyValues({ email, password, firstName, lastName, age })

    // check if the current user exist
    const userExist = await UserService.findUser({ email })
    if (userExist) {
      statusCode = 400
      throw new Error("User already exist.")
    }

    // create a new user
    const user_ = await UserService.createUser({ email, password, firstName, lastName, age: Number(age), role: "patient" })

    // send email verification - RESTORED
    await sendEmailVerification(user_, req)

    // NOTE: We no longer log the user in immediately.
    // The user must verify their email first.
    // The user's isVerified flag is set to false by default in the model.
    await user_.save()


    // Return success message indicating email was sent
    return res.status(200).json({
      status: true,
      data: {
        user: user_
      },
      message: `A verification email has been sent to ${user_?.firstName}`
    });

  } catch (error: any) {
    console.log("Error in register controller:", error)
    res.status(statusCode).json({ status: false, message: error.message })
  }
}

/**
 * @summary - Resend verification email
 * @param req
 * @param res
 * @returns
 */
const resendEmail = async (req: Request, res: Response) => {
  let statusCode = 500

  try {
    const { email } = req.body

    // validate request
    commonUtilitie.validateRequestForEmptyValues({ email })

    // check if the current user exist
    const userExist = await UserService.findUser({ email })
    if (!userExist) {
      statusCode = 400
      throw new Error("User does not exist.")
    }

    // check if user is already verified
    if (userExist.isVerified) {
      statusCode = 400
      throw new Error("User is already verified.")
    }

    // send email verification
    await sendEmailVerification(userExist, req)

    return res.status(200).json({
      status: true,
      message: `A verification email has been sent to ${userExist.email}`
    })

  } catch (error: any) {
    res.status(statusCode).json({ status: false, message: error.message })
  }
}

/**
 * @summary - Verify registration token
 * @param req
 * @param res
 */
const verifyRegistrationToken = async (req: Request, res: Response) => {
  let _statusCode = 500

  try {
    // validate request
    commonUtilitie.validateRequestForEmptyValues({ token: req.params.token })

    // Find match token
    const token = await UserService.findToken({ token: req.params.token })
    if (!token) {
      _statusCode = 400
      throw new Error(`Unable to find a valid token, your token might have expired`)
    }

    // If there is a token, find a matching user
    let user = await UserService.findUser({ _id: token.userId })
    if (!user) {
      return res.status(400).json({ success: false, msg: `Unable to find a user for this token` })
    }

    // check if user is verified
    if (user.isVerified) {
      _statusCode = 400
      throw new Error(`This user has already been verified.`)
    }

    // verify and save the user
    user.isVerified = true
    
    // FIX: Use the document's save method to ensure the update is atomic and correct
    await user.save() 

    // Delete the token after successful verification
    await token.remove() 

    // Redirect to login page after successful verification with a success flag
    res.status(301).redirect(`${config.CLIENT_URL}/login?verified=true`)

  } catch (error: any) {
    // Log the error to help with debugging
    console.error("error in verifyRegistrationToken:", error)
    // If an error occurs, redirect to login with a failure flag
    res.status(301).redirect(`${config.CLIENT_URL}/login?verified=false`)
  }
}


const facebookOAuth = async (req: MyUserRequest, res: Response) => {
  let statusCode = 500

  try {
    if (!req.user) {
      statusCode = 401
      throw new Error('User not authenticated')
    }

    const token: any = req.user?.generateJWT()

    return res.header("auth-token", token).status(200).json({
      status: true,
      data: {
        token,
        user: req.user
      }
    })
  } catch (error: any) {
    res.status(statusCode).json({ status: false, message: error.message })
  }
}

const googleCallback = async (req: Request, res: Response) => {
  try {
    console.log('Entering googleCallback function');

    if (!req.user) {
      console.log('No user data in request');
      return res.redirect('https://client.curemigraine.org/login?error=no_user_data');
    }

    const data = req.user as any;
    console.log('Google callback data structure:', Object.keys(data));

    if (!data.user || !data.token) {
      console.log('Invalid Google callback data structure');
      return res.redirect('https://client.curemigraine.org/login?error=invalid_data');
    }

    // Generate a temporary token
    const tempToken = uuidv4();

    // Create the temp token document
    const tempTokenDoc = new TempToken({
      token: tempToken,
      userData: {
        user: {
          _id: data.user._id,
          email: data.user.email,
          firstName: data.user.firstName,
          lastName: data.user.lastName,
          role: data.user.role,
          isPaid: data.user.isPaid
        },
        token: data.token
      },
      expiresAt: new Date(Date.now() + 15 * 60 * 1000)
    });

    // Save to database
    await tempTokenDoc.save();
    console.log('Saved temp token to database:', tempToken);

    // Redirect to frontend
    // const frontendURL = 'http://localhost:3000';
    const frontendURL = 'https://client.curemigraine.org';

    // Check if user is paid and redirect accordingly
    const isPaid = data.user.isPaid === true;

    // Always redirect to home with the token, the frontend will handle the redirection based on payment status
    const redirectURL = `${frontendURL}/home?googleToken=${tempToken}`;
    console.log('Redirecting to:', redirectURL);
    return res.redirect(redirectURL);

  } catch (error) {
    console.error('Error in googleCallback:', error);
    return res.redirect('https://client.curemigraine.org/login?error=server_error');
  }
};

const getGoogleUserData = async (req: Request, res: Response) => {
  try {
    console.log('Entering getGoogleUserData function');
    const { googleToken } = req.query;

    if (!googleToken || typeof googleToken !== 'string') {
      console.log('Invalid googleToken:', googleToken);
      return res.status(400).json({
        status: false,
        message: 'Invalid token provided'
      });
    }

    console.log('Looking for token:', googleToken);

    // Find the temporary token
    const tempTokenDoc = await TempToken.findOne({ token: googleToken });

    if (!tempTokenDoc) {
      console.log('Token not found:', googleToken);
      return res.status(404).json({
        status: false,
        message: 'Token not found or expired'
      });
    }

    console.log('Token found, user ID:', tempTokenDoc.userData.user._id);

    // Delete the token immediately after finding it to prevent reuse
    await TempToken.deleteOne({ token: googleToken });
    console.log('Successfully deleted temp token');

    // Return the user data
    return res.status(200).json({
      status: true,
      data: tempTokenDoc.userData
    });

  } catch (error) {
    console.error('Error in getGoogleUserData:', error);
    return res.status(500).json({
      status: false,
      message: 'Internal server error'
    });
  }
};

const googleSignIn = async (req: Request, res: Response) => {
  try {
    console.log('Entering googleSignIn function');
    const { token, userInfo } = req.body;

    if (!token || !userInfo || !userInfo.email) {
      console.log('Invalid Google sign-in data');
      return res.status(400).json({
        status: false,
        message: 'Invalid Google sign-in data'
      });
    }

    console.log('Processing Google sign-in for:', userInfo.email);

    // First try to find user by email
    let user: any = await User.findOne({ email: userInfo.email });

    if (!user) {
      // Create a new user if email doesn't exist
      console.log('Creating new user from Google profile');
      user = new User({
        method: 'google',
        email: userInfo.email,
        firstName: userInfo.given_name || userInfo.name || 'Google',
        lastName: userInfo.family_name || 'User',
        google: {
          id: userInfo.sub,
          token: token
        },
        isVerified: true,
        isActive: true,
        role: 'patient'
      });
      await user.save();
      console.log('New user created with ID:', user._id);
    } else {
      // Update existing user with Google info
      user.method = user.method || 'google';
      user.google = {
        id: userInfo.sub,
        token: token
      };
      user.isVerified = true;
      await user.save();
      console.log('Updated existing user with Google credentials');
    }

    // Login successful, generate JWT token
    let authToken = user.generateJWT();

    // Return user data and token
    return res.status(200).json({
      status: true,
      data: {
        user,
        token: authToken
      }
    });

  } catch (error) {
    console.error('Error in googleSignIn:', error);
    return res.status(500).json({
      status: false,
      message: 'Internal server error'
    });
  }
};

export default { apiAdminLogin, resetPassword, forgetPassword, apiCheckAuthentication, apiCheckAuthenticationUser, resendApiAdminLogin, register, verifyRegistrationToken, facebookOAuth, resendEmail, googleCallback, getGoogleUserData, googleSignIn }
