import { describe, expect, it } from '@jest/globals';
import HttpException from '../../src/common/http-exception';

describe('HttpException', () => {
    it('should create an instance of HttpException', () => {
        const httpException = new HttpException(500, 'Internal Server Error');
        expect(httpException).toBeInstanceOf(HttpException);
        expect(httpException.statusCode).toBe(500);
        expect(httpException.message).toBe('Internal Server Error');
        expect(httpException.error).toBeNull();
    })
})
