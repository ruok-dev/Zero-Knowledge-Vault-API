import { Router } from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const router = Router();
const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET must be defined in environment variables');
}

// 1. Get Salt for Login
router.get('/salt/:username', async (req, res) => {
  const { username } = req.params;
  const user = await prisma.user.findUnique({ where: { username } });

  if (!user) {
    // Return a dummy salt to prevent username enumeration
    const dummySalt = crypto.randomBytes(16).toString('hex');
    return res.json({ salt: dummySalt });
  }

  res.json({ salt: user.salt });
});

// 2. Register
router.post('/register', async (req, res) => {
  const { username, salt, authKey } = req.body;

  try {
    const existingUser = await prisma.user.findUnique({ where: { username } });
    if (existingUser) return res.status(400).json({ error: 'Username already exists' });

    // We hash the authKey before storing it (defense in depth)
    const authKeyHash = await bcrypt.hash(authKey, 12);

    const user = await prisma.user.create({
      data: {
        username,
        salt,
        authKeyHash,
      },
    });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ userId: user.id, token });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 3. Login
router.post('/login', async (req, res) => {
  const { username, authKey } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isValid = await bcrypt.compare(authKey, user.authKeyHash);
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ userId: user.id, token });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
