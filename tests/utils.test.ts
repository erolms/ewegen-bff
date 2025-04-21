import { normalizePort } from '../src/utils/port';
import { describe, expect, it } from '@jest/globals';


describe('Utility Functions', () => {
  describe('normalizePort', () => {
    it('should return a number for valid port strings', () => {
      expect(normalizePort('3000')).toBe(3000);
      expect(normalizePort('8080')).toBe(8080);
      expect(normalizePort('0')).toBe(0);
    });

    it('should return the original string for named pipes', () => {
      expect(normalizePort('pipe')).toBe('pipe');
      expect(normalizePort('\\\\.\\pipe\\myPipe')).toBe('\\\\.\\pipe\\myPipe');
    });

    it('should return false for negative port numbers', () => {
      expect(normalizePort('-1')).toBe(false);
      expect(normalizePort('-3000')).toBe(false);
    });

    it('should return the original string for non-numeric strings', () => {
      expect(normalizePort('abc')).toBe('abc');
    });
  });
});
