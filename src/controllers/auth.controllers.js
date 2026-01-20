import { ApiError } from '../utils/api-error.js';
import User from '../models/user.models.js';
import asyncHandler from '../utils/async-handler.js';
import {
  sendMail,
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
} from '../utils/mail.js';
import { ApiResponse } from '../utils/api-response.js';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const generateAccessAndRefreshToken = async (user) => {
  try {
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    // Save refresh token in DB
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(500, 'Error generating tokens', error);
  }
};

const registerUser = asyncHandler(async (req, res) => {
  // registration logic
  const { userName, email, password } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ $or: [{ email }, { userName }] });

  if (existingUser) {
    throw new ApiError(409, 'User with given email or username already exists');
  }

  // Create new user
  const newUser = await User.create({
    userName,
    email,
    password,
    isEmailVerified: false,
  });

  const { unHashedToken, hashedToken, tokenExpiry } =
    newUser.generateTemporaryToken();

  // Save the user with the hashed token and expiry
  newUser.emailVerificationToken = hashedToken;
  newUser.emailVerificationTokenExpiry = tokenExpiry;
  await newUser.save({ validateBeforeSave: false });

  // Send verification email
  const verificationLink = `${req.protocol}://${req.get(
    'host',
  )}/api/v1/users/verify-email/${unHashedToken}`;

  await sendMail({
    email: newUser?.email,
    subject: 'Verify Your Email - Project Management App',
    mailGenContent: emailVerificationMailgenContent(
      newUser.userName,
      verificationLink,
    ),
  });

  // Fetch the created user to ensure all fields are populated
  const createdUser = await User.findById(newUser._id).select(
    '-password -refreshToken -emailVerificationToken -emailVerificationTokenExpiry',
  );

  if (!createdUser) {
    throw new ApiError(500, 'User creation failed');
  }

  res.status(201).json(
    new ApiResponse(
      201,
      'User registered successfully and verification email sent successfully',
      {
        user: createdUser,
      },
    ),
  );
});

const loginUser = asyncHandler(async (req, res) => {
  const { email, password, userName } = req.body;

  if (!email) {
    throw new ApiError(404, 'Email not found');
  }

  const user = await User.findOne({ email });

  if (!user) {
    throw new ApiError(404, 'User not found');
  }

  // Check if password is correct

  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    throw new ApiError(401, 'Invalid credentials');
  }

  const { accessToken, refreshToken } =
    await generateAccessAndRefreshToken(user);

  const loggedInUser = await User.findById(user._id).select(
    '-password -refreshToken -emailVerificationToken -emailVerificationTokenExpiry',
  );

  // if (!loggedInUser) {
  //   throw new ApiError(500, 'User not found');
  // }

  const options = {
    httpOnly: true,
    secure: true,
    // Set secure to true in production, but false in development for HTTP
    // secure: process.env.NODE_ENV === 'production',
  };

  return res
    .status(200)
    .cookie('refreshToken', refreshToken, options)
    .cookie('accessToken', accessToken, options)
    .json(
      new ApiResponse(200, 'User logged in successfully', {
        user: loggedInUser,
        accessToken,
        refreshToken,
      }),
    );
});

const logOutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    { $set: { refreshToken: '' } },
    { new: true },
  );

  const options = {
    httpOnly: true,
    secure: true,
    // secure: process.env.NODE_ENV === 'production',
  };

  return res
    .status(200)
    .clearCookie('accessToken', options)
    .clearCookie('refreshToken', options)
    .json(new ApiResponse(200, 'User logged out successfully'));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  return res.status(200).json(
    new ApiResponse(200, 'User fetched successfully', {
      user: req.user,
    }),
  );
});

const verifyEmail = asyncHandler(async (req, res) => {
  const { token } = req.query;

  if (!token) {
    throw new ApiError(400, 'Invalid token or email');
  }

  let hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  const user = await User.findOne({
    emailVerificationToken: hashedToken, // ^--- This comma is treated as "AND"
    emailVerificationTokenExpiry: { $gt: Date.now() }, // the AND operator is implicit (automatic).
  });

  if (!user) {
    throw new ApiError(400, 'Invalid token or email');
  }

  user.emailVerificationToken = undefined;
  user.emailVerificationTokenExpiry = undefined;
  user.isEmailVerified = true;

  await user.save({ validateBeforeSave: false });
  return res.status(200).json(
    new ApiResponse(200, 'Email verified successfully', {
      isEmailVerified: true,
    }),
  );
});

const resendEmailVerification = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user?._id);
  if (!user) {
    throw new ApiError(404, 'User not found');
  }

  if (user.isEmailVerified) {
    throw new ApiError(400, 'Email already verified');
  }

  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  // Save the user with the hashed token and expiry
  user.emailVerificationToken = hashedToken;
  user.emailVerificationTokenExpiry = tokenExpiry;
  await user.save({ validateBeforeSave: false });

  // Send verification email
  const verificationLink = `${req.protocol}://${req.get(
    'host',
  )}/api/v1/users/verify-email?token=${unHashedToken}`;

  await sendMail({
    email: user?.email,
    subject: 'Verify Your Email - Project Management App',
    mailGenContent: emailVerificationMailgenContent(
      user.userName,
      verificationLink,
    ),
  });

  return res
    .status(200)
    .json(new ApiResponse(200, 'Email verification resent successfully'));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, 'Unauthorized request');
  }

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET,
    );

    const user = await User.findById(decodedToken?.id || decodedToken?._id);

    if (!user) {
      throw new ApiError(401, 'Invalid refresh token');
    }

    if (user.refreshToken !== incomingRefreshToken) {
      throw new ApiError(401, 'Refresh token is expired');
    }

    const options = {
      httpOnly: true,
      secure: true,
    };

    const { accessToken, refreshToken: newRefreshToken } =
      await generateAccessAndRefreshToken(user);

    user.refreshToken = newRefreshToken;
    await user.save();

    return res
      .status(200)
      .cookie('refreshToken', newRefreshToken, options)
      .cookie('accessToken', accessToken, options)
      .json(
        new ApiResponse(200, 'Access token refreshed successfully', {
          accessToken,
          refreshToken: newRefreshToken,
        }),
      );
  } catch (error) {
    throw new ApiError(401, error?.message || 'Invalid refresh token');
  }
});

const forgotPasswordRequest = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    throw new ApiError(404, 'User not found');
  }

  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  // Save the user with the hashed token and expiry
  user.forgotPasswordToken = hashedToken;
  user.forgotPasswordTokenExpiry = tokenExpiry;
  await user.save({ validateBeforeSave: false });

  // Send password reset email

  await sendMail({
    email: user?.email,
    subject: 'Reset Your Password - Project Management App',
    mailGenContent: forgotPasswordMailgenContent(
      user.userName,
      `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/${unHashedToken}`,
    ),
  });

  return res
    .status(200)
    .json(new ApiResponse(200, 'Password reset email sent successfully'));
});

const resetPassword = asyncHandler(async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  if (!token) {
    throw new ApiError(400, 'Invalid token');
  }

  let hashedToken = crypto.createHash('sha256').update(token).digest('hex');

  const user = await User.findOne({
    forgotPasswordToken: hashedToken,
    forgotPasswordTokenExpiry: { $gt: Date.now() },
  });

  if (!user) {
    throw new ApiError(489, 'Invalid token or token expired');
  }

  user.password = newPassword;
  user.forgotPasswordToken = undefined;
  user.forgotPasswordTokenExpiry = undefined;

  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, 'Password reset successfully'));
});

const changePassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(req.user?._id);

  if (!user) {
    throw new ApiError(404, 'User not found');
  }

  const isPasswordValid = await user.comparePassword(oldPassword);

  if (!isPasswordValid) {
    throw new ApiError(401, 'Invalid credentials');
  }

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, 'Password changed successfully'));
});

export {
  registerUser,
  loginUser,
  logOutUser,
  getCurrentUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
  forgotPasswordRequest,
  resetPassword,
  changePassword,
};

