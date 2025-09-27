import { body } from 'express-validator';

const userRegistrationValidator = () => {
  return [
    body('email')
      .trim()
      .notEmpty()
      .withMessage('Email is required')
      .isEmail()
      .withMessage('Invalid email address'),
    // .normalizeEmail(),
    body('password')
      .trim()
      .notEmpty()
      .withMessage('Password is required')
      .isLength({ min: 5 })
      .withMessage('Password must be at least 5 characters long'),
    body('userName')
      .trim()
      .notEmpty()
      .withMessage('Username is required')
      .isLength({ min: 3 })
      .withMessage('Username must be at least 3 characters long')
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage(
        'Username can only contain letters, numbers, and underscores',
      )
      .toLowerCase(),
    body('fullName').optional().trim(),
  ];
};

const userLoginValidator = () => {
  return [
    body('email')
      .trim()
      .notEmpty()
      .withMessage('Email is required')
      .isEmail()
      .withMessage('Invalid email address'),
    body('password').trim().notEmpty().withMessage('Password is required'),
  ];
};

const userChangePasswordValidator = () => {
  return [
    body('oldPassword')
      .trim()
      .notEmpty()
      .withMessage('Old password is required')
      .isLength({ min: 5 })
      .withMessage('Old password must be at least 5 characters long'),
    body('newPassword')
      .trim()
      .notEmpty()
      .withMessage('New password is required')
      .isLength({ min: 5 })
      .withMessage('New password must be at least 5 characters long'),
  ];
};

const userForgotPasswordValidator = () => {
  return [
    body('email')
      .trim()
      .notEmpty()
      .withMessage('Email is required')
      .isEmail()
      .withMessage('Invalid email address'),
  ];
};

const userResetPasswordValidator = () => {
  return [
    body('newPassword')
      .trim()
      .notEmpty()
      .withMessage('New password is required'),
  ];
};

export {
  userRegistrationValidator,
  userLoginValidator,
  userChangePasswordValidator,
  userResetPasswordValidator,
  userForgotPasswordValidator,
};
