// Entry point of the Node.js backend application using Express and TypeScript.
// This file sets up environment variables, initializes the Express app,
// configures middleware and routes, and starts the server.

import 'dotenv/config'; // Load environment variables from .env into process.env before other imports

import express, { Request, Response } from 'express'; // Import Express and request/response types
import helloRoutes from './routes/helloRoutes'; // Import our custom hello route
import authRoutes from './routes/authRoutes'; // Import our custom auth route
import { APP_CONFIG } from './constants'; // Import application configuration
import { generalRateLimit } from './middleware/rateLimitMiddleware'; // Import rate limiting middleware
import { startScheduledJobs } from './jobs/scheduler'; // Import scheduled jobs


const app = express(); // Create an instance of an Express application

app.use(generalRateLimit); // Apply general rate limiting to all requests
app.use(express.json()); // Add middleware to automatically parse JSON request bodies
app.use('/api/hello', helloRoutes); // Mount helloRoutes on the /api/hello path
app.use('/api/auth', authRoutes); // Mount authRoutes on the /api/auth path
// Define a basic root endpoint for health checks or root testing
app.get('/', (req: Request, res: Response) => {
  res.send('API root is alive!');
});

// Start the server and listen on the defined port
app.listen(APP_CONFIG.API.PORT, () => {
  console.log(`Server running on http://localhost:${APP_CONFIG.API.PORT}`);
  
  // Start scheduled jobs after server is running
  startScheduledJobs();
});