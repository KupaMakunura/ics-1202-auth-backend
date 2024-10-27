import { NextFunction, Request, Response } from 'express';
import { verifyAccessToken } from '../utils';
// check if the headers are provided

export const authMiddleware = async (
  request: Request,
  response: Response,
  next: NextFunction
) => {
  if (!request.headers.authorization) {
    response
      .status(401)
      .send({ message: 'Please provide a valid access token' });
    return;
  }

  const jsonWebToken = request.headers.authorization;

  console.log(jsonWebToken);

  // check if the token is provided

  const [, token] = jsonWebToken.split(' ');

  if (!jsonWebToken) {
    response
      .status(401)
      .send({ message: 'Please provide a valid access token' });
    return;
  }

  // verify

  const data = await verifyAccessToken(token);

  if (data === null) {
    response
      .status(401)
      .send({ message: 'Please provide a valid access token' });
    return;
  }

  (request as any).user = data;

  if (request.path === '/api/users/' && request.method === 'GET') {
    if ((request as any).user.role !== 'Admin') {
      response.status(403).send({ message: 'Forbidden' });
      return;
    }

    // pass to the next middleware
    next();

  }

  next();

};
