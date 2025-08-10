import { describe, expect, it, beforeEach, jest } from '@jest/globals';
import { errorHandler } from '../../src/middlewares/error-middleware';
import HttpException from '../../src/common/http-exception';
import { Request, Response, NextFunction } from 'express';

describe('Error handler middleware', () => {
    const errorStatusCode: HttpException = {
      name: "error",
      statusCode: 503,
      message: "string",
      error: "string"
    }
    const errorStatus: HttpException = {
        name: "error",
        status: 111,
        message: "string",
        error: "string"
    }
    const errorNoStatus: HttpException = {
        name: "error",
        message: "string",
        error: "string"
    }
    let mockRequest: Partial<Request>
    let mockResponse: Partial<Response>
    const nextFunction: NextFunction = jest.fn()
  
    beforeEach(() => {
      mockRequest = {};
      mockResponse = {
        status: jest.fn().mockReturnThis() as jest.MockedFunction<Response['status']>,
        send: jest.fn() as jest.MockedFunction<Response['send']>
      }
    })
  
    it('handle error when error includes statusCode', async () => {
      errorHandler(
        errorStatusCode as HttpException,
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      )
  
      expect(mockResponse.status).toHaveBeenCalledWith(503);
      expect(mockResponse.send).toHaveBeenCalledWith(errorStatusCode);
      expect(nextFunction).not.toHaveBeenCalled();
    })

    it('handle error when error includes status', async () => {
        errorHandler(
          errorStatus as HttpException,
          mockRequest as Request,
          mockResponse as Response,
          nextFunction
        )
    
        expect(mockResponse.status).toHaveBeenCalledWith(111);
        expect(mockResponse.send).toHaveBeenCalledWith(errorStatus);
        expect(nextFunction).not.toHaveBeenCalled();
    })

    it('handle error when error includes no status codes', async () => {
        errorHandler(
          errorNoStatus as HttpException,
          mockRequest as Request,
          mockResponse as Response,
          nextFunction
        )
    
        expect(mockResponse.status).toHaveBeenCalledWith(500);
        expect(mockResponse.send).toHaveBeenCalledWith(errorNoStatus);
        expect(nextFunction).not.toHaveBeenCalled();
    })  
})
