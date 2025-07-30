// Controller for handling requests to the /api/hello endpoint.
// This file exports the controller function used by the route.

import { Request, Response } from 'express'; // Import Express types for type-safe request and response objects

// Controller function for handling GET requests to /api/hello
// Sends a JSON response with a friendly message
export const sayHello = (req: Request, res: Response): void => {
  res.json({ message: 'Hello, TypeScript world!' }); // Respond with a JSON object
};