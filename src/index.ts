// Entry point of the Node.js backend application using Express and TypeScript.
// This file sets up environment variables, initializes the Express app,
// configures middleware and routes, and starts the server.

import express, { Request, Response } from 'express'; // Import Express and request/response types
import dotenv from 'dotenv'; // Import dotenv to load environment variables from a .env file
import helloRoutes from './routes/helloRoutes'; // Import our custom hello route

dotenv.config(); // Load environment variables from .env into process.env

const app = express(); // Create an instance of an Express application
const PORT = process.env.PORT || 3000; // Use PORT from .env or fallback to 3000

app.use(express.json()); // Add middleware to automatically parse JSON request bodies
app.use('/api/hello', helloRoutes); // Mount helloRoutes on the /api/hello path

// Define a basic root endpoint for health checks or root testing
app.get('/', (req: Request, res: Response) => {
  res.send('API root is alive!');
});

// Start the server and listen on the defined port
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});