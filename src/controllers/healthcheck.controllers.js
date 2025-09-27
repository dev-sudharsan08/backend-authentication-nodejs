import { ApiResponse } from '../utils/api-response.js';
import asyncHandler from '../utils/async-handler.js';


//controller ----> route ----> app.js
// approach 1

// const healthCheck = (req, res) => {
//   const response = new ApiResponse(200, 'Service is healthy');
//   res.status(200).json(response);
// };

// approach 2

// const healthCheck = async (req, res, next) => {
//   try {
//     const response = new ApiResponse(200, 'Service is healthy');
//     res.status(200).json(response);
//   } catch (error) {
//     next(error);
//   }
// };

// approach 3

const healthCheck = asyncHandler(async (req, res) => {
  const response = new ApiResponse(200, 'Service is healthy');
  res.status(200).json(response);
});

export { healthCheck };