// Entry point of the Node.js backend application using Express and TypeScript.
// This file sets up environment variables, initializes the Express app,
// configures middleware and routes, and starts the server.

import dotenv from 'dotenv'; // Import dotenv to load environment variables from a .env file
dotenv.config(); // Load environment variables from .env into process.env, before importing any other modules

import express, { Request, Response } from 'express'; // Import Express and request/response types
import helloRoutes from './routes/helloRoutes'; // Import our custom hello route
import authRoutes from './routes/authRoutes'; // Import our custom auth route
import { APP_CONFIG } from './constants'; // Import application configuration


const app = express(); // Create an instance of an Express application

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
});