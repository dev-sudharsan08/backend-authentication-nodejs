import { Router } from 'express';
import { healthCheck } from '../controllers/healthcheck.controllers.js';


//controller ----> route ----> app.js

const router = Router();
router.route('/').get(healthCheck);

export default router;