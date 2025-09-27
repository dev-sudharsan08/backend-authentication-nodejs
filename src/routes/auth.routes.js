import { Router } from 'express';
import {
  registerUser,
  loginUser,
  logOutUser,
  refreshAccessToken,
  forgotPasswordRequest,
  resetPassword,
  changePassword,
  verifyEmail,
  resendEmailVerification,
  getCurrentUser,
} from '../controllers/auth.controllers.js';
import { validate } from '../middleware/validator.middleware.js';
import {
  userRegistrationValidator,
  userLoginValidator,
  userForgotPasswordValidator,
  userResetPasswordValidator,
  userChangePasswordValidator,
} from '../validators/index.js';
import { verifyJWT } from '../middleware/auth.middleware.js';

//controller ----> route ----> app.js

const router = Router();

//unsecure route
router
  .route('/register')
  .post(userRegistrationValidator(), validate, registerUser);
router.route('/login').post(userLoginValidator(), validate, loginUser);
router.route('/verify-email').get(verifyEmail);
router.route('/refresh-token').post(refreshAccessToken);
router
  .route('/forgot-password')
  .post(userForgotPasswordValidator(), validate, forgotPasswordRequest);
router
  .route('/reset-password/:token')
  .post(userResetPasswordValidator(), validate, resetPassword);



//secure route
router.route('/logout').post(verifyJWT, logOutUser);
router.route('/current-user').get(verifyJWT, getCurrentUser);
router
  .route('/change-password')
  .post(verifyJWT, userChangePasswordValidator(), validate, changePassword);
router
  .route('/resend-email-verification')
  .post(verifyJWT, resendEmailVerification);

//userRegistrationValidator() is middleware for validating the request body
//validate is middleware for checking validation result and sending error response if any validation errors occur
//registerUser is the controller function that handles the registration logic

// Here, the order of middleware is important. First, we validate the request body, then check for validation results, and finally proceed to the controller if everything is valid.

// This ensures that the controller only processes valid data. If validation fails, an error response is sent back to the client without reaching the controller.

export default router;