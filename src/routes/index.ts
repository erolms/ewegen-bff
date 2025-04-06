import { Router, Request, Response, NextFunction } from 'express';

const router: Router = Router();

router.get('/', (req: Request, res: Response, next: NextFunction) => {
  const status = {
    status: 'ok',
    message: 'eWegen BFF is running',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
  };
  res.status(200).json(status);
});

export default router;
