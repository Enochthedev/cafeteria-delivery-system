import { NextFunction, Request, Response } from 'express';
import Default from '../app/defaults/default';
import { IError, ILog, IResponse } from '../interfaces/interfaces';
import { inject, injectable } from 'inversify';
import { BaseMiddleware } from 'inversify-express-utils';
import { Logger } from '../config/logger';
import { LIB_TYPES } from '../di/types';
import { LogStatus } from '../enums/enum';

@injectable()
export class HeadersMiddleware extends BaseMiddleware {
  private _logger: Logger;
  private _validHeaderClients: string[] = [
    'collabo.ng',
    'www.collabo.ng',
  ];

  constructor(@inject(LIB_TYPES.Logger) private logger: Logger) {
    super();
    this._logger = logger;
  }

  public handler(req: Request, res: Response, next: NextFunction) {
    this._logger.info(`${req.method} ${req.path}`);

    const clientHeader = req.headers['x-collabo-client'] as string;

    if (!clientHeader || !this._validHeaderClients.includes(clientHeader)) {
      const payload: ILog = {
        action: 'AUTHORIZATION_USER',
        data: undefined,
        description: 'Invalid collabo client',
        ipAddress: String(req.headers['x-forwarded-for']) || req.ip,
        userAgent: req.get('User-Agent') as string,
        timestamp: new Date().toUTCString(),
        requestId: Default.GENERATE_REQUEST_ID(),
        status: LogStatus.FAILED,
        details: {},
      };

      this._logger.error(payload.description, payload);

      const response: IResponse<any, IError> = {
        statusCode: 400,
        success: false,
        message: payload.description,
        timestamp: payload.timestamp,
        requestId: payload.requestId,
        error: {
          code: 400,
          message: 'Invalid collabo client',
        },
      }

      res.status(response.statusCode).json(response);
      return
    }

    next();
  }
}
