import express from 'express';
import cors from 'cors';
import healthCheckRouter from './routes/healthcheck.routes.js';
import authRouter from './routes/auth.routes.js';
import cookieParser from 'cookie-parser';

const app = express();

// basic middleware configuration
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true, limit: '16kb' })); //To read Forms: Without it, you cannot process <form> submissions.
/* <form action="/update-profile" method="POST">
  <input type="text" name="username" value="johndoe">

  <input type="text" name="address[city]" value="New York">
  <input type="text" name="address[zip]" value="10001">

  <button type="submit">Update</button>
</form>

console.log(req.body);
Output:
{
  username: "johndoe",
  address: {
    city: "New York",
    zip: "10001"
  }
}
*/
app.use(express.static('public'));
app.use(cookieParser());

// cors configuration
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(',') || '*',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  }),
);

// routes
app.use('/api/v1/healthcheck', healthCheckRouter);
app.use('/api/v1/auth', authRouter); // to be replaced with authRouter

app.get('/', (req, res) => {
  res.send('Hello World!');
});

// Add a global error handling middleware.
// It MUST be the last `app.use()` in the file.
// This middleware will catch all errors passed via `next(error)`.
// app.use((err, req, res, next) => {
//   // Check if the error is an instance of our custom ApiError.
//   // This allows us to send a structured, predictable response.
//   if (err instanceof ApiError) {
//     return res
//       .status(err.statusCode)
//       .json(new ApiResponse(err.statusCode, err.message, err.errors));
//   }

//   // For any other unhandled or unexpected errors, send a generic 500 response.
//   // It's crucial to log the original error for debugging.
//   console.error('UNHANDLED ERROR:', err);

//   return res
//     .status(500)
//     .json(new ApiResponse(500, 'Internal Server Error', { error: err.message }));
// });

app.use((err, req, res, next) => {
  const status = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  // Always return errors as an array for consistency
  const errors = Array.isArray(err.errors)
    ? err.errors
    : err.errors
      ? [{ error: err.errors }]
      : [{ error: message }];

  res.status(status).json({
    statusCode: status,
    message,
    errors,
    data: null,
    success: false,
  });
});

export default app;