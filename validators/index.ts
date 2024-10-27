import Joi from 'joi';

export const createUserSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  role: Joi.string().valid('Admin', 'User').required(),
  name: Joi.string().min(3).required(),
});
