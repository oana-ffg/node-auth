// Controller for handling requests to the /api/hello endpoint.
// This file exports the controller function used by the route.

import { Request, Response } from 'express'; // Import Express types for type-safe request and response objects

// Controller function for handling GET requests to /api/hello
// Sends a JSON response with a friendly message
export const sayHello = (req: Request, res: Response): void => {
  res.json({ message: 'Hello, TypeScript world!' }); // Respond with a JSON object
};

// Controller for handling GET requests to /api/teapot
// Responds with HTTP 418 and a playful message
export const iAmATeapot = (req: Request, res: Response): void => {
  res.status(418).json({
    status: 418,
    message: "I'm a teapot 🫖",
    meaning: "This server refuses to brew coffee because it is a teapot."
  });
};