// Defines the routes for the /api/hello endpoint.
// Routes are connected to their respective controller functions.

import express from 'express'; // Import the express module to create a router
import { sayHello, iAmATeapot, postHello } from '../controllers/helloController'; // Import the controller function that handles the route

const router: express.Router = express.Router(); // Create a new router instance and annotate it with the Router type

router.get('/', sayHello); // Define a GET route for /api/hello that uses the sayHello controller
router.get('/teapot', iAmATeapot); // Define a GET route for /api/teapot that uses the iAmATeapot controller
router.post('/', postHello); // Define a POST route for /api/hello that uses the postHello controller   

export default router; // Export the router to be used in index.ts