import {PrismaClient} from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

export const prisma = new PrismaClient();

const saltRounds = 10;

// hash the password
export const hashPassword = async (plainPassword: string): Promise<string> => {
    return await bcrypt.hash(plainPassword, saltRounds);
};

// compare the password
export const comparePassword = async (
    cipheredPassword: string,
    plainPassword: string
): Promise<boolean> => {
    return await bcrypt.compare(plainPassword, cipheredPassword);
};

// create the access token
export const createAccessToken = async (payload: any): Promise<string> => {
    return jwt.sign(payload, process.env.AUTH_SECRET!, {expiresIn: '60 days'});
};

// verify the access token
export const verifyAccessToken = async (accessToken: string) => {
    try {
        return jwt.verify(accessToken, process.env.AUTH_SECRET!);
    } catch (error) {
        return null;
    }
};

// decode the access token
export const decodeAccessToken = async (accessToken: string) => {
    return jwt.decode(accessToken);
};
