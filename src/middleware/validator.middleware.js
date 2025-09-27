import { validationResult } from 'express-validator';
import { ApiError } from '../utils/api-error.js';

export const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) {
    return next();
  }

  // const extractedErrors = errors.array().map(err => ({
  //   // `err.path` is the modern replacement for `err.param`
  //   field: err.path,
  //   msg: err.msg,
  // }));

  // // Pass the error to the global error handler using next().
  // // This ensures all application errors are formatted consistently.
  // // We use the message from the first validation error for a more specific top-level message.
  // next(new ApiError(422, errors.array({ onlyFirstError: true })[0].msg, extractedErrors));

  const extractedErrors = errors.array().map(err => ({
    param: err.param,
    error: err.msg,
  }));

  return res
    .status(422)
    .json(new ApiError(422, 'Validation failed', extractedErrors));
};