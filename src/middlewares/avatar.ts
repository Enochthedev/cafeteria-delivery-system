import { NextFunction, Request, Response } from 'express';
import multer, { Multer } from 'multer';
import path from 'path';
import Default from '../app/defaults/default';
import { IError, IFileUploadOptions, ILog, IResponse } from '../interfaces/interfaces';
import Status from 'http-status-codes';
import { LogStatus } from '../enums/enum';
import { inject, injectable } from 'inversify';
import { LIB_TYPES } from '../di/types';
import { Logger } from '../config/logger';
import { BaseMiddleware } from 'inversify-express-utils';

@injectable()
export class FileUploadMiddleware extends BaseMiddleware {
  private _logger: Logger;
  private _upload: Multer;

  constructor(
    @inject(LIB_TYPES.Logger) private logger: Logger,
    private options: IFileUploadOptions = {
      allowedTypes: /jpeg|jpg|png|gif/,
      maxSizeInBytes: 5 * 1024 * 1024
    }
  ) {
    super();
    this._logger = logger;
    this._upload = multer({
      storage: multer.memoryStorage(),
      fileFilter: (req, file, cb) => {
        const extname = this.options.allowedTypes.test(
          path.extname(file.originalname).toLowerCase()
        );
        const mimetype = this.options.allowedTypes.test(file.mimetype);

        if (extname && mimetype) {
          return cb(null, true);
        }
        cb(new Error(`Only ${this.options.allowedTypes} files are allowed`));
      },
      limits: {
        fileSize: this.options.maxSizeInBytes
      }
    });
  }

  public handler = (req: Request, res: Response, next: NextFunction) => {
    const requestId: string = Default.GENERATE_REQUEST_ID();
    const timestamp: string = new Date().toUTCString();
    const ip: string = String(req.headers['x-forwarded-for']) || req.ip as string;
    const userAgent: string = req.get('User-Agent') as string;

    if (!req.user) {
      const payload: ILog = {
        action: 'FILE_UPLOAD',
        data: undefined,
        description: 'User not authenticated',
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
        message: 'User not authenticated',
        timestamp: timestamp,
        requestId: requestId,
        error: {
          code: Status.UNAUTHORIZED,
          message: 'User not authenticated',
          details: {}
        }
      };

      res.status(response.statusCode).json(response);
      return;
    }

    this._upload.single('file')(req, res, (err) => {
      if (err) {
        const payload: ILog = {
          action: 'FILE_UPLOAD',
          data: undefined,
          description: 'File upload failed',
          ipAddress: ip,
          userAgent: userAgent,
          timestamp: timestamp,
          requestId: requestId,
          status: LogStatus.FAILED,
          details: { error: err.message }
        };

        this._logger.error(payload.description, payload);

        const response: IResponse<any, IError> = {
          statusCode: Status.BAD_REQUEST,
          success: false,
          message: err.message || 'File upload failed',
          timestamp: timestamp,
          requestId: requestId,
          error: {
            code: Status.BAD_REQUEST,
            message: err.message || 'File upload failed',
            details: {}
          }
        };

        res.status(response.statusCode).json(response);
        return;
      }

      if (!req.file) {
        const payload: ILog = {
          action: 'FILE_UPLOAD',
          data: undefined,
          description: 'No file uploaded',
          ipAddress: ip,
          userAgent: userAgent,
          timestamp: timestamp,
          requestId: requestId,
          status: LogStatus.FAILED,
          details: {}
        };

        this._logger.error(payload.description, payload);

        const response: IResponse<any, IError> = {
          statusCode: Status.BAD_REQUEST,
          success: false,
          message: 'No file uploaded',
          timestamp: timestamp,
          requestId: requestId,
          error: {
            code: Status.BAD_REQUEST,
            message: 'No file uploaded',
            details: {}
          }
        };

        res.status(response.statusCode).json(response);
        return;
      }

      req.uploadedFile = {
        buffer: req.file.buffer,
        originalName: req.file.originalname,
        fieldName: req.file.fieldname,
        mimetype: req.file.mimetype,
        sizeInBytes: req.file.size,
        extension: path.extname(req.file.originalname)
      };

      next();
    });
  };
}