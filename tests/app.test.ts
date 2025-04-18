import request from 'supertest';
import app from '../src/app';
import { describe, expect, it } from '@jest/globals';

describe('eWegen BFF App', () => {
  describe('GET /', () => {
    it('should return status 200 and correct JSON response', async () => {
      const response = await request(app).get('/');
      
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('status', 'ok');
      expect(response.body).toHaveProperty('message', 'eWegen BFF is running');
      expect(response.body).toHaveProperty('version');
      expect(response.body).toHaveProperty('timestamp');
      expect(new Date(response.body.timestamp).getTime()).not.toBeNaN();
    });
  });

  describe('Error handling', () => {
    it('should return 404 for non-existent routes', async () => {
      const response = await request(app).get('/non-existent-route');
      
      expect(response.status).toBe(404);
    });
  });
});
