import express from 'express';
import { comparePassword, createAccessToken, hashPassword, prisma } from './utils';
import { createUserSchema } from './validators';
import { authMiddleware } from './middleware/auth';
import morgan from 'morgan';
import cors from 'cors';

const app = express();
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));
app.use(express.json());

// register a new user
app.post('/api/auth/register/', async (request, response) => {
  const { error } = createUserSchema.validate(request.body);

  if (error) {
    response.status(400).send({ valid: false, message: error.message });
    return;
  }

  const hashedPassword = await hashPassword(request.body.password);

  try {
    // check the user first
    const existingUser = await prisma.user.findUnique({
      where: {
        email: request.body.email
      }
    });

    if (existingUser) {
      response.status(409).send({
        exists: true
      });

      return;
    }

    const user = await prisma.user.create({
      data: {
        email: request.body.email,
        password: hashedPassword,
        role: request.body.role,
        name: request.body.name
      }
    });

    // create access token
    const accessToken = await createAccessToken(user);

    if (!user) {
      response
        .status(500)
        .send({ valid: false, message: 'Failed to create user' });
      return;
    }

    response.status(201).send({ created: true, user: user, accessToken });

    return;
  } catch (error) {
    response.status(500).send({ valid: false, message: error });
    return;
  }
});

// login a user
app.post('/api/auth/login/', async (request, response) => {
  const { email, password } = request.body;

  if (!email || !password) {
    response.status(400).send({ valid: false, message: 'Invalid request' });
    return;
  }

  // find user by email
  try {
    const user = await prisma.user.findUnique({
      where: {
        email: email
      }
    });

    // compare password
    const isPasswordValid = await comparePassword(user?.password!, password);

    if (!isPasswordValid) {
      response
        .status(400)
        .send({ password: false, message: 'Invalid password' });
      return;
    }

    if (!user) {
      response.status(404).send({ valid: false, message: 'User not found' });
      return;
    }

    // create access token
    const accessToken = await createAccessToken(user);

    response
      .status(200)
      .send({ valid: true, user: user, accessToken: accessToken });

    return;

    // compare password
  } catch (error) {
    response.status(500).send({ valid: false, message: error });
    return;
  }
});

// get all users
app.get('/api/users/', async (request, response) => {
  try {
    const users = await prisma.user.findMany();
    response.status(200).send({ valid: true, users: users });
    return;
  } catch (error) {
    response.status(500).send({ valid: false, message: error });
    return;
  }
});

// edit role information
app.put('/api/users/:id/role/', authMiddleware, async (request, response) => {
  const { id } = request.params;

  if (!id) {
    response.status(400).send({ valid: false, message: 'Invalid request' });
    return;
  }

  const { role } = request.body;

  if (!role) {
    response.status(400).send({ valid: false, message: 'Invalid request' });
    return;
  }

  try {
    const user = await prisma.user.update({
      where: {
        id: id
      },
      data: {
        role: role
      }
    });

    if (!user) {
      response.status(500).send({ valid: false, message: 'Failed to update' });
      return;
    }

    response.status(200).send({
      valid: true,
      user: user
    });

    return;
  } catch (error) {
    response.status(500).send({ valid: false, message: error });
    return;
  }
});


app.put('/api/users/:id/', authMiddleware, async (request, response) => {
  const { id } = request.params;

  if (!id) {
    response.status(400).send({ valid: false, message: 'Invalid request' });
    return;
  }

  const { email, name } = request.body;

  if (!email || !name) {
    response.status(400).send({ valid: false, message: 'Invalid request' });
    return;
  }

  try {
    const user = await prisma.user.update({
      where: {
        id: id
      },
      data: {
        email: email,
        name: name,
        password: await hashPassword(request.body.password)
      }
    });

    if (!user) {
      response.status(500).send({ valid: false, message: 'Failed to update' });
      return;
    }

    const accessToken = await createAccessToken(user);

    response.status(200).send({
      valid: true,
      user: user,
      accessToken: accessToken
    });

    return;
  } catch (error) {
    response.status(500).send({ valid: false, message: error });
    return;
  }
});

app.listen(3001, () => {
  console.log('Server is running on http://localhost:3001');
});
