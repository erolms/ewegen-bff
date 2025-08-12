// Ensure required env vars are present before modules import
process.env.COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || 'eu-central-1_testpool123';
process.env.COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID || 'test-client-id';
process.env.AWS_REGION = process.env.AWS_REGION || 'eu-central-1';

import request from 'supertest';
import app from '../../src/app';
import { describe, expect, it } from '@jest/globals';

describe('Index Route', () => {
  describe('GET /', () => {
    it('should return status 200', async () => {
      const response = await request(app).get('/');
      expect(response.status).toBe(200);
    });

    it('should return correct JSON structure', async () => {
      const response = await request(app).get('/');
      
      expect(response.body).toEqual(
        expect.objectContaining({
          status: 'ok',
          message: 'eWegen BFF is running',
          version: expect.stringMatching(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/),
          timestamp: expect.any(String)
        })
      );
    });

    it('should return a valid ISO timestamp', async () => {
      const response = await request(app).get('/');
      const timestamp = response.body.timestamp;
      
      // Check if it's a valid ISO string
      expect(new Date(timestamp).toISOString()).toBe(timestamp);
    });
  });
});
