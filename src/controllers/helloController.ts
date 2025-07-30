// Controller for handling requests to the /api/hello endpoint.
// This file exports the controller function used by the route.

import { Request, Response } from 'express'; // Import Express types for type-safe request and response objects

interface HelloRequestBody {
  name: string;
  message: string;
}

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

export const postHello = (req: Request<{}, {}, HelloRequestBody>, res: Response): void => {
  const { name, message } = req.body;

  if (!name || !message) {
    res.status(400).json({ error: 'Both name and message are required.' });
    return;
  }

  const length = message.length;
  res.status(200).json({
    greeting: `Hello ${name}, your message is ${length} characters long!`
  });
};