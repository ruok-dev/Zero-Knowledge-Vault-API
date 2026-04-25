import { Router, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { authenticateToken, AuthRequest } from '../middleware/auth';

const router = Router();
const prisma = new PrismaClient();

// Get all vault items for the user
router.get('/', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    const items = await prisma.vaultItem.findMany({
      where: { userId: req.userId },
      orderBy: { createdAt: 'desc' },
    });
    res.json(items);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch items' });
  }
});

// Create a new vault item
router.post('/', authenticateToken, async (req: AuthRequest, res: Response) => {
  const { title, data, nonce } = req.body;

  try {
    const item = await prisma.vaultItem.create({
      data: {
        userId: req.userId!,
        title,
        data,
        nonce,
      },
    });
    res.json(item);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create item' });
  }
});

// Delete a vault item
router.delete('/:id', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    const { id } = req.params;
    const item = await prisma.vaultItem.findFirst({
      where: { id, userId: req.userId },
    });

    if (!item) return res.status(404).json({ error: 'Item not found' });

    await prisma.vaultItem.delete({ where: { id } });
    res.json({ message: 'Deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete item' });
  }
});

export default router;
