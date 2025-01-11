import { NextFunction, Request, Response } from 'express';
import Default from '../app/defaults/default';
import { IAuthRecord, IError, IFileUpload, ILog, IResponse } from '../interfaces/interfaces';
import Status from 'http-status-codes';
import { LogStatus, ProfileType } from '../enums/enum';
import { inject, injectable } from 'inversify';
import { LIB_TYPES } from '../di/types';
import { Logger } from '../config/logger';
import { BaseMiddleware } from 'inversify-express-utils';
import jwt, { JwtPayload } from 'jsonwebtoken';
import env from '../config/env';
import { RedisClient } from '../config/redis';
import Redis from 'ioredis';


declare global {
  namespace Express {
    interface Request {
      user?: IAuthRecord;
      uploadedFile?: IFileUpload;
    }
  }
}


@injectable()
export class AuthMiddleware extends BaseMiddleware {
  private _logger: Logger;
  private _redisClient: Redis;

  constructor(
    @inject(LIB_TYPES.Logger) private logger: Logger,
    @inject(LIB_TYPES.RedisClient) private readonly redis: RedisClient
  ) {
    super();
    this._logger = logger;
    this._redisClient = redis.client;
  }

  public async handler(req: Request, res: Response, next: NextFunction) {
    const requestId: string = Default.GENERATE_REQUEST_ID();
    const timestamp: string = new Date().toUTCString();
    const ip: string = String(req.headers['x-forwarded-for']) || req.ip as string;
    const userAgent: string = req.get('User-Agent') as string;


    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      const payload: ILog = {
        action: 'AUTHORIZATION_USER',
        data: undefined,
        description: 'no token provided, authorization denied',
        ipAddress: ip,
        userAgent: userAgent,
        timestamp: timestamp,
        requestId: requestId,
        status: LogStatus.FAILED,
        details: {}
      };

      this._logger.error(payload.description, payload);

      const response: IResponse<any, IError> = {
        statusCode: Status.UNAUTHORIZED,
        success: false,
        message: 'no token provided, authorization denied',
        timestamp: timestamp,
        requestId: requestId,
        error: {
          code: Status.UNAUTHORIZED,
          message: 'no token provided, authorization denied',
          details: {}
        }
      };

      res.status(response.statusCode).json(response);
      return;
    }

    try {
      const payload = jwt.verify(token, env.jwt_access_secret, { ignoreExpiration: true }) as JwtPayload;

      const tokenKey = `${payload.sub}:session-${payload.lastLogin}`;
      const ttl = await this._redisClient.ttl(tokenKey);

      if (ttl > 0) {
        await this._redisClient.expire(tokenKey, 5 * 24 * 60 * 60);
        this._logger.debug(`ttl extended for user: ${payload.sub}`, { tokenKey, newTTL: 5 * 24 * 60 * 60 });
      } else {
        const payload: ILog = {
          action: 'AUTHORIZATION_USER',
          data: undefined,
          description: 'token is expired, authorization denied',
          ipAddress: ip,
          userAgent: userAgent,
          timestamp: timestamp,
          requestId: requestId,
          status: LogStatus.FAILED,
          details: {}
        };

        this._logger.error(payload.description, payload);

        const response: IResponse<any, IError> = {
          statusCode: Status.UNAUTHORIZED,
          success: false,
          message: 'Session has expired. Please, login to continue',
          timestamp: timestamp,
          requestId: requestId,
          error: {
            code: Status.UNAUTHORIZED,
            message: 'Session has expired. Please, login to continue',
            details: {}
          }
        };

        res.status(response.statusCode).json(response);
        return;
      }

      req.user = {
        id: payload.sub as string,
        email: payload.email,
        profileType: payload.profileType as ProfileType,
        lastLogin: payload.lastLogin as number
      };
      next();
    } catch (err: any) {
      const payload: ILog = {
        action: 'AUTHORIZATION_USER',
        data: undefined,
        description: 'no token provided, authorization denied',
        ipAddress: ip,
        userAgent: userAgent,
        timestamp: timestamp,
        requestId: requestId,
        status: LogStatus.FAILED,
        details: {
          error: err
        }
      };

      this._logger.error(payload.description, payload);

      const response: IResponse<any, IError> = {
        statusCode: Status.UNAUTHORIZED,
        success: false,
        message: 'token is expired or not valid, authorization denied',
        timestamp: timestamp,
        requestId: requestId,
        error: {
          code: Status.UNAUTHORIZED,
          message: err.message,
          details: err
        }
      };

      res.status(response.statusCode).json(response);
    }
  }
}
