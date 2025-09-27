import { ApiError } from '../utils/api-error.js';
import asyncHandler from '../utils/async-handler.js';
import jwt from 'jsonwebtoken';
import User from '../models/user.models.js';

const verifyJWT = asyncHandler(async (req, res, next) => {
  const token =
    req.cookies?.accessToken ||
    req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    throw new ApiError(401, 'Unauthorized request');
  }

  try {
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    // The user ID might be in the `_id` or `id` field of the token payload.
    // This makes the middleware more robust.
    const user = await User.findById(decodedToken?._id || decodedToken?.id).select(
      '-password -refreshToken -emailVerificationToken -emailVerificationTokenExpiry',
    );

    if (!user) {
      throw new ApiError(401, 'Invalid Access Token');
    }

    req.user = user;
    next();
  } catch (error) {
    throw new ApiError(401, error?.message || 'Invalid access token');
  }
});

export { verifyJWT };