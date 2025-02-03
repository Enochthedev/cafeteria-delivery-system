import { Request, Response } from 'express';
import { controller, httpPatch, httpPost } from 'inversify-express-utils';
import { inject } from 'inversify';
import { LIB_TYPES, MIDDLEWARE_TYPES, SERVICE_TYPES } from '../../di/types';
import { UserService } from '../users/user.service';
import Default from '../defaults/default';
import { BaseController } from '../../internal/base.controller';
import { Logger } from '../../config/logger';
import { plainToInstance } from 'class-transformer';
import { validateOrReject } from 'class-validator';
import { AuthService } from './services/auth.service';
import { LoginDto } from './dto/login.dto';
import { IAuthRecord } from '../../interfaces/interfaces';
import { ResetPasswordDto, TokenDto, VerifyPasswordResetTokenDto } from './dto/token.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { CreateUserDto } from '../users/dto/user.dto';

@controller('/auth')
export class AuthController extends BaseController {

  constructor(
    @inject(SERVICE_TYPES.AuthService) private readonly _authService: AuthService,
    @inject(SERVICE_TYPES.UserService) private readonly _userService: UserService,
    @inject(LIB_TYPES.Logger) protected readonly _logger: Logger
  ) {
    super(_logger);
  }

  @httpPost('/register')
  public async register(req: Request, res: Response) {
    const requestId: string = Default.GENERATE_REQUEST_ID();
    const timestamp: string = new Date().toUTCString();
    const ipAddress: string = req.ip as string;
    const userAgent: string = req.headers['user-agent'] as string;

    try {
      const dto = plainToInstance(CreateUserDto, req.body);
      await validateOrReject(dto);
      const token = await this._userService.createUser(dto, {ipAddress, userAgent, timestamp, requestId});
      this.sendSuccess(res, token, 'User profile created', 201, timestamp, requestId);
    } catch (err) {
      this.sendError(res, requestId, err);
    }
  }

  @httpPost('/login')
  public async login(req: Request, res: Response) {
    const requestId: string = Default.GENERATE_REQUEST_ID();
    const timestamp: string = new Date().toUTCString();
    const ipAddress: string = req.ip as string;
    const userAgent: string = req.headers['user-agent'] as string;
    try {
      const dto = plainToInstance(LoginDto, req.body);
      await validateOrReject(dto);
      const loginObject = await this._authService.login(dto, {ipAddress, userAgent, timestamp, requestId});
      this.sendSuccess(res, loginObject, 'Login successful', 200, timestamp, requestId);
    } catch (err) {
      this.sendError(res, requestId, err);
    }
  }

  @httpPatch('/start-email-verification', MIDDLEWARE_TYPES.AuthMiddleware)
  public async startEmailVerification(req: Request, res: Response) {
    const requestId: string = Default.GENERATE_REQUEST_ID();
    const timestamp: string = new Date().toUTCString();
    const ipAddress: string = req.ip as string;
    const userAgent: string = req.headers['user-agent'] as string;
    const record = req.user as IAuthRecord;
    try {
      const email = await this._authService.startEmailVerification(record,{ ipAddress, userAgent, timestamp, requestId});
      this.sendSuccess(res, email, 'Email verification started', 200, timestamp, requestId);
    } catch (err) {
      this.sendError(res, requestId, err);
    }
  }

  @httpPatch('/verify-email', MIDDLEWARE_TYPES.AuthMiddleware)
  public async verifyEmail(req: Request, res: Response) {
    const requestId: string = Default.GENERATE_REQUEST_ID();
    const timestamp: string = new Date().toUTCString();
    const ipAddress: string = req.ip as string;
    const userAgent: string = req.headers['user-agent'] as string;
    const record = req.user as IAuthRecord;
    try {
      const dto = plainToInstance(TokenDto, req.body);
      await validateOrReject(dto);
      await this._authService.completeEmailVerification(record, dto, {ipAddress, userAgent, timestamp, requestId});
      this.sendSuccess(res, null, 'Email verified', 200, timestamp, requestId);
    } catch (err) {
      this.sendError(res, requestId, err);
    }
  }

  @httpPost('/forgot-password')
  public async forgotPassword(req: Request, res: Response) {
    const requestId: string = Default.GENERATE_REQUEST_ID();
    const timestamp: string = new Date().toUTCString();
    const ipAddress: string = req.ip as string;
    const userAgent: string = req.headers['user-agent'] as string;
    try {
      const dto = plainToInstance(ForgotPasswordDto, req.body);
      await validateOrReject(dto);
      await this._authService.forgotPassword(dto, {ipAddress, userAgent, timestamp, requestId});
      this.sendSuccess(res, null, 'Password reset link sent', 200, timestamp, requestId);
    } catch (err) {
      this.sendError(res, requestId, err);
    }
  }

  @httpPatch('/verify-reset-token')
  public async verifyResetToken(req: Request, res: Response) {
    const requestId: string = Default.GENERATE_REQUEST_ID();
    const timestamp: string = new Date().toUTCString();
    const userId: string = req.params.userId as string;
    const ipAddress: string = req.ip as string;
    const userAgent: string = req.headers['user-agent'] as string;
    try {
      const dto = plainToInstance(VerifyPasswordResetTokenDto, req.body);
      await validateOrReject(dto);
      await this._authService.verifyPasswordResetToken(dto.token, userId, {ipAddress, userAgent, timestamp, requestId});
      this.sendSuccess(res, null, 'Token verified', 200, timestamp, requestId);
    } catch (err) {
      this.sendError(res, requestId, err);
    }
  }

  @httpPatch('/reset-password')
  public async resetPassword(req: Request, res: Response) {
    const requestId: string = Default.GENERATE_REQUEST_ID();
    const timestamp: string = new Date().toUTCString();
    const ipAddress: string = req.ip as string;
    const userAgent: string = req.headers['user-agent'] as string;
    try {
      const dto = plainToInstance(ResetPasswordDto, req.body);
      await validateOrReject(dto);
      await this._authService.resetPassword(dto, {ipAddress, userAgent, timestamp, requestId});
      this.sendSuccess(res, null, 'Password reset successful', 200, timestamp, requestId);
    } catch (err) {
      this.sendError(res, requestId, err);
    }
  }

  @httpPost('/logout', MIDDLEWARE_TYPES.AuthMiddleware)
  public async logout(req: Request, res: Response) {
    const requestId: string = Default.GENERATE_REQUEST_ID();
    const timestamp: string = new Date().toUTCString();
    const ipAddress: string = req.ip as string;
    const userAgent: string = req.headers['user-agent'] as string;
    try {
      await this._authService.logout(req.user as IAuthRecord, {ipAddress, userAgent, timestamp, requestId});
      this.sendSuccess(res, null, 'Logout successful', 200, timestamp, requestId);
    } catch (err) {
      this.sendError(res, requestId, err);
    }
  }

  @httpPost('/logout-all', MIDDLEWARE_TYPES.AuthMiddleware)
  public async logoutAll(req: Request, res: Response) {
    const requestId: string = Default.GENERATE_REQUEST_ID();
    const timestamp: string = new Date().toUTCString();
    const ipAddress: string = req.ip as string;
    const userAgent: string = req.headers['user-agent'] as string;
    try {
      await this._authService.logoutFromAllDevices(req.user as IAuthRecord, {ipAddress, userAgent, timestamp, requestId});
      this.sendSuccess(res, null, 'Logged out from all devices', 200, timestamp, requestId);
    } catch (err) {
      this.sendError(res, requestId, err);
    }
  }
}

