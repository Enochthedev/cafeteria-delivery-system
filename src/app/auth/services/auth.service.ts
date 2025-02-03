import { inject, injectable } from 'inversify';
import { Connection, Types } from 'mongoose';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

// Config & Utilities
import env from '../../../config/env';
import { Database } from '../../../config/db';
import { Logger } from '../../../config/logger';
import Default from '../../defaults/default';
import { RedisClient } from '../../../config/redis';
import { SecurityUtils } from '../../../common/utils/security.utils';

// Interfaces & Types
import { IAuthRecord, ILog } from '../../../interfaces/interfaces';
import { LogStatus, RedisJob, TokenType } from '../../../enums/enum';

// Services & Models
import { UserService } from '../../users/user.service';
import { TokenService } from './token.service';
import { User, UserDocument } from '../../users/models/user.model';
import { Token, TokenDocument } from '../models/token.model';

// DTOs
import { LoginDto } from '../dto/login.dto';
import { ResetPasswordDto, TokenDto } from '../dto/token.dto';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';

// Constants
import { LIB_TYPES, SERVICE_TYPES } from '../../../di/types';
import { Exception } from '../../../internal/exception';
import { userInfo } from 'os';


@injectable()
export class AuthService {
  private readonly _conn: Connection;

  private readonly SESSION_EXPIRATION = 20 * 60; // 20 minutes in seconds
  private readonly OTP_EXPIRATION_MINUTES = 20;
  private readonly PASSWORD_RESET_EXPIRATION = 20; // minutes 
  private readonly MAX_PASSWORD_RESET_ATTEMPTS = 5;
  constructor(
    @inject(SERVICE_TYPES.UserService) private readonly _userService: UserService,
    @inject(SERVICE_TYPES.TokenService) private readonly _tokenService: TokenService,
    @inject(LIB_TYPES.MongoDB) private readonly _db: Database,
    @inject(LIB_TYPES.RedisClient) private readonly _redis: RedisClient,
    @inject(LIB_TYPES.Logger) private readonly _logger: Logger,
  ) {
    this._conn = this._db.connection;
  }

  private createSession(user: UserDocument) {
    const lastLogin = Date.now();
    const accessToken = Default.GENERATE_ACCESS_TOKEN(
      user.id,
      user.email,
      lastLogin
    );

    const sessionKey = `${user.id}:session-${lastLogin}`;
    this._redis.client.setex(sessionKey, this.SESSION_EXPIRATION, accessToken);

    return { token: accessToken, sessionKey };
  }

  private logSecurityEvent(params: {
    status: LogStatus;
    description: string;
    details: Record<string, any>;
    context: Record<string, any>;
  }) {
    const logEntry: ILog = {
      service: 'auth',
      action: params.context.operation,
      status: params.status,
      timestamp: params.context.timestamp,
      ipAddress: params.context.ipAddress,
      userAgent: params.context.userAgent,
      requestId: params.context.requestId,
      description: params.description,
      details: {
        ...params.details,
        serviceVersion: env.api_version,
        environment: env.node_env
      }
    };

    switch (params.status) {
      case LogStatus.SUCCESS:
        this._logger.info(params.description, logEntry);
        break;
      case LogStatus.FAILED:
        this._logger.warn(params.description, logEntry);
        break;
      default:
        this._logger.debug(params.description, logEntry);
    }
  }

  private handleAuthError(error: any): Error {
    if (error instanceof Exception) return error;
    return new Exception('Authentication failed', Exception.SERVER_ERROR);
  }


  public async login(
    dto: LoginDto,
    context: { ipAddress: string; userAgent: string; timestamp: string; requestId: string }
  ) {
    const logContext = {
      service: 'auth',
      operation: 'login',
      ...context,
      email: dto.email // Never log passwords
    };

    try{
      this._logger.debug('Login attempt initiated', logContext);
      const user: UserDocument | null = await this._userService.findOne({ email: dto.email });
      if (!user) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Authentication failure: User not found',
          details: { email: dto.email },
          context: logContext
        });
        throw new Exception('Invalid email or password', Exception.UNPROCESSABLE_ENTITY);
      }

      const doPasswordsMatch: boolean = await this._userService.comparePassword(dto.password, user.password);
      if (!doPasswordsMatch) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Authentication failure: Invalid credentials',
          details: { userId: user.id },
          context: logContext
        });
        throw new Exception('Invalid credentials', Exception.UNAUTHORIZED);
      }

      const { token, sessionKey } = this.createSession(user);
      
      this.logSecurityEvent({
        status: LogStatus.SUCCESS,
        description: 'Authentication successful',
        details: { userId: user.id },
        context: logContext
      });

      const lastLogin = Date.now();

      return {
        id: user.id,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        matricNumber: user.matricNumber,
        email: user.email,
        profileImage: user.profileImage,
        isVerified: !!user.verifiedAt,
        token: token,
      };
    } catch (error) {
      this.logSecurityEvent({
        status: LogStatus.FAILED,
        description: 'Authentication system error',
        details: { error: error.message },
        context: logContext
      });
      throw this.handleAuthError(error);
    }
  }

  public async startEmailVerification(
    record: IAuthRecord,
    context: { ipAddress: string; userAgent: string; timestamp: string; requestId: string }
  ): Promise<Record<string, string>> {
    const logContext = {
      service: 'auth',
      operation: 'startEmailVerification',
      action: 'START_EMAIL_VERIFICATION',
      ...context
    };
    try{
      const user: UserDocument | null = await this._userService.findOne({ id: record.id });
      if (!user) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'failed to start email verification - user not found',
          details: { userId: record.id },
          context: logContext
        });
        throw new Exception('User does not exist', Exception.NOT_FOUND);
      }

      if (user.verifiedAt) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Email verification failure: User already verified',
          details: { userId: user.id },
          context: logContext
        });
        throw new Exception('User already verified', Exception.CONFLICT);
      }
  
      const otp = Default.GENERATE_OTP();
      const token = await this._tokenService.create(
        user.id,
        otp,
        TokenType.OTP,
        this.OTP_EXPIRATION_MINUTES
      );
      await this._redis.addJob(RedisJob.SEND_VERIFICATION_OTP, {
        data: {
          name: user.firstName,
          username: user.username,
          matricNUmber: user.matricNumber,
          email: user.email,
          otp: token.token,
          expiresIn: this.OTP_EXPIRATION_MINUTES,
        },
          ip: context.ipAddress,
          userAgent: context.userAgent,
          timestamp: context.timestamp,
          requestId: context.requestId
      });

      this.logSecurityEvent({
        status: LogStatus.SUCCESS,
        description: 'Email verification initiated successfully',
        details: { userId: user.id, email: user.email },
        context: logContext
      });

      return { email: user.email };
    }
    catch (error) {
      this.logSecurityEvent({
        status: LogStatus.FAILED,
        description: 'Email verification system error',
        details: { error: error.message },
        context: logContext
      });
      throw this.handleAuthError(error);
    }
  }

  public async completeEmailVerification(
    record: IAuthRecord,
    dto: TokenDto,
    context: { ipAddress: string; userAgent: string; timestamp: string; requestId: string }
  ): Promise<void> {
    const logContext = {
      service: 'auth',
      operation: 'completeEmailVerification',
      ...context,
      userId: record.id
    };
    try {
      this._logger.debug('Completing email verification process', logContext);

      const user: UserDocument | null = await this._userService.findOne({ id: record.id });
      if (!user) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Email verification failure: User not found',
          details: { userId: record.id },
          context: logContext
        });
        throw new Exception('User does not exist', Exception.NOT_FOUND);
      }

      const token = await Token.findOne({ 
        token: dto.otp,
        user: user._id,
        type: TokenType.OTP
      });
      if (!token) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Email verification failure: Invalid OTP',
          details: { userId: user.id },
          context: logContext
        });
        throw new Exception('One-Time Passcode does not exist', Exception.NOT_FOUND);
      }

      if (token.usedAt) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Email verification failure: OTP already used',
          details: { userId: user.id },
          context: logContext
        });
        throw new Exception('Verification code already used', Exception.CONFLICT);
      }

      if (new Date() > token.validTill) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Email verification failure: OTP expired',
          details: { userId: user.id },
          context: logContext
        });
        await Token.deleteOne({ _id: token._id });
        throw new Exception('Verification code expired', Exception.UNAUTHORIZED);
      }

      await this._conn.transaction(async trx => {
        await Promise.all([
          User.updateOne(
            { _id: user._id },
            { $set: { verifiedAt: new Date() } },
            { session: trx }
          ),
          Token.deleteOne({ _id: token._id }, { session: trx })
        ]);
      });

      this.logSecurityEvent({
        status: LogStatus.SUCCESS,
        description: 'Email verification completed successfully',
        details: { userId: user.id },
        context: logContext
      });

      await this._redis.addJob(RedisJob.SEND_WELCOME_EMAIL, {
        data: {
          username: user.username,
          email: user.email,
          verificationDate: new Date().toISOString()
        },
          ip: context.ipAddress,
          userAgent: context.userAgent,
          timestamp: context.timestamp,
          requestId: context.requestId 
      });
  
    } catch (error) {
      this.logSecurityEvent({
        status: LogStatus.FAILED,
        description: 'Email verification system error',
        details: { error: error.message },
        context: logContext
      });
      throw this.handleAuthError(error);
    }
  }

  public async forgotPassword(
    dto: ForgotPasswordDto,
    context: { ipAddress: string; userAgent: string; timestamp: string; requestId: string }
  ): Promise<void> {
    const logContext = {
      service: 'auth',
      operation: 'forgotPassword',
      ...context,
      email: dto.email
    };
    try {
      this._logger.debug('Initiating password reset process', logContext);

      // Rate limiting check
      const attemptKey = `pwd_reset:${dto.email}`;
      const attempts = await this._redis.client.incr(attemptKey);
      if (attempts > this.MAX_PASSWORD_RESET_ATTEMPTS) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Password reset rate limit exceeded',
          details: { attempts },
          context: logContext
        });
        throw new Exception('Too many reset attempts', Exception.TOO_MANY_REQUESTS);
      }
      await this._redis.client.expire(attemptKey, 3600);

      const user: UserDocument | null = await this._userService.findOne({ email: dto.email });
      if (!user) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Password reset request processed',
          details: { email: dto.email },
          context: logContext
        });
        return;
      }

      const rawToken = SecurityUtils.generateSecureToken();
      const hashedToken = await bcrypt.hash(rawToken, 10);
      
      await this._tokenService.create(
        user.id,
        hashedToken,
        TokenType.RESET,
        this.PASSWORD_RESET_EXPIRATION
      );


      // Construct secure reset link
      const resetLink = new URL(dto.redirectUrl);
      resetLink.searchParams.set('token', encodeURIComponent(rawToken));
      resetLink.searchParams.set('userId', user.id);


      await this._redis.addJob(RedisJob.SEND_PASSWORD_RESET_LINK, {
        data: {
          username: user.username,
          email: user.email,
          link: resetLink.toString(),
          expiresIn: this.PASSWORD_RESET_EXPIRATION
        },
        ip: context.ipAddress,
        userAgent: context.userAgent,
        timestamp: context.timestamp,
        requestId: context.requestId
      });

      this.logSecurityEvent({
        status: LogStatus.SUCCESS,
        description: 'Password reset initiated',
        details: { userId: user.id },
        context: logContext
      });
    } catch (error) {
      this.logSecurityEvent({
        status: LogStatus.FAILED,
        description: 'Password reset system error',
        details: { error: error.message },
        context: logContext
      });
      throw this.handleAuthError(error);
    }
  }

  public async verifyPasswordResetToken(
    token: string,
    userId: string,
    context: { ipAddress: string; userAgent: string; timestamp: string; requestId: string }
  ): Promise<void> {
    const logContext = {
      service: 'auth',
      operation: 'verifyPasswordResetToken',
      ...context,
      userId
    };

    try{
      this._logger.debug('Verifying password reset token', logContext);

      const user: UserDocument | null = await this._userService.findOne({ id: userId });
      // const userToken: TokenDocument | null = await Token.findOne({ token: token, type: TokenType.RESET });
      if (!user) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Token verification failure: User not found',
          details: {},
          context: logContext
        });
        throw new Exception('Invalid reset token', Exception.UNAUTHORIZED);
      }

      const tokenDoc = await Token.findOne({
        user: user._id,
        type: TokenType.RESET
      });

      if (!tokenDoc || !(await bcrypt.compare(token, tokenDoc.token))) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Token verification failure: Invalid token',
          details: {},
          context: logContext
        });
        throw new Exception('Invalid reset token', Exception.UNAUTHORIZED);
      }

      if (tokenDoc.usedAt) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Token verification failure: Already used',
          details: {},
          context: logContext
        });
        throw new Exception('Reset token already used', Exception.CONFLICT);
      }

      if (new Date() > tokenDoc.validTill) {
        await Token.deleteOne({ _id: tokenDoc._id });
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Token verification failure: Expired',
          details: {},
          context: logContext
        });
        throw new Exception('Reset token expired', Exception.UNAUTHORIZED);
      }

      await Token.updateOne(
        { _id: tokenDoc._id },
        { $set: { usedAt: new Date() } }
      );

      this.logSecurityEvent({
        status: LogStatus.SUCCESS,
        description: 'Token verification successful',
        details: {},
        context: logContext
      });
    }
    catch (error) {
      this.logSecurityEvent({
        status: LogStatus.FAILED,
        description: 'Token verification system error',
        details: { error: error.message },
        context: logContext
      });
      throw this.handleAuthError(error);
    }
  }

  public async resetPassword(
    dto: ResetPasswordDto,
    context: { ipAddress: string; userAgent: string; timestamp: string; requestId: string }
  ): Promise<void> {
    const logContext = {
      service: 'auth',
      operation: 'resetPassword',
      ...context,
      userId: dto.userId
    };
    try{
      this._logger.debug('Processing password reset', logContext);

      // Validate password complexity
      if (!SecurityUtils.validatePasswordComplexity(dto.newPassword)) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Password reset failure: Weak password',
          details: {},
          context: logContext
        });
        throw new Exception('Password does not meet complexity requirements', Exception.UNPROCESSABLE_ENTITY);
      }

      const user: UserDocument | null = await this._userService.findOne({ id: dto.userId });
      if (!user) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Password reset failure: User not found',
          details: {},
          context: logContext
        });
        throw new Exception('User account not found', Exception.NOT_FOUND);
      }

      // Verify valid token exists
      const tokenDoc = await Token.findOne({
        user: user._id,
        token: dto.token,
        type: TokenType.RESET,
        usedAt: { $exists: true }
      });

      if (!tokenDoc) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Password reset failure: Invalid or unused token',
          details: {},
          context: logContext
        });
        throw new Exception('Reset token not verified', Exception.UNAUTHORIZED);
      }

      // Check for password reuse(history)
      if (await this._userService.isPreviousPassword(dto.userId, dto.newPassword)) {
        this.logSecurityEvent({
          status: LogStatus.FAILED,
          description: 'Password reset failure: Reused password',
          details: {},
          context: logContext
        });
        throw new Exception('Cannot reuse previous passwords', Exception.CONFLICT);
      }


      // Hash new password
      const salt = await bcrypt.genSalt(Number(env.bcrypt_rounds));
      const passwordHash = await bcrypt.hash(dto.newPassword, salt);
      

      await this._conn.transaction(async trx => {
        await Promise.all([
          User.updateOne(
            { _id: user._id },
            { 
              $set: { password: passwordHash },
              $push: { passwordHistory: { $each: [passwordHash], $slice: -5 } }
            },
            { session: trx }
          ),
          this._tokenService.invalidateUserTokens(user.id, [TokenType.RESET], trx),
          this._redis.deleteUserSessions(user.id)
        ]);
      });

      this.logSecurityEvent({
        status: LogStatus.SUCCESS,
        description: 'Password reset successful',
        details: {},
        context: logContext
      });

      await this._redis.addJob(RedisJob.SEND_PASSWORD_RESET_SUCCESS_EMAIL, {
        data: {
          username: user.username,
          email: user.email,
          timestamp: new Date().toISOString(),
          name: user.firstName,
        },
        ip: context.ipAddress,
        userAgent: context.userAgent,
        timestamp: context.timestamp,
        requestId: context.requestId,
      });
  }catch(error){
    this.logSecurityEvent({
      status: LogStatus.FAILED,
      description: 'Password',
      details: { error: error.message },
      context: logContext
    });
  }
}

  public async logout(
    record: IAuthRecord,
    context: { ipAddress: string; userAgent: string; timestamp: string; requestId: string }
  ): Promise<void> {
    const logContext = {
      service: 'auth',
      operation: 'logout',
      ...context,
      userId: record.id
    };
    try{
      this._logger.debug('Logging out user', logContext);

      await this._redis.client.del(`${record.id}:session-${record.lastLogin}`);

      this.logSecurityEvent({
        status: LogStatus.SUCCESS,
        description: 'Logout successful',
        details: { userId: record.id },
        context: logContext
      });

    } catch (error) {
      this.logSecurityEvent({
        status: LogStatus.FAILED,
        description: 'Logout system error',
        details: { error: error.message },
        context: logContext
      });
      throw this.handleAuthError(error);
    }
  }

  public async logoutFromAllDevices(
    record: IAuthRecord,
    context: { ipAddress: string; userAgent: string; timestamp: string; requestId: string }
  ): Promise<void> {
    const logContext = {
      service: 'auth',
      operation: 'logoutFromAllDevices',
      ...context,
      userId: record.id
    };
    try {
      this._logger.debug('Logging out user from all devices', logContext);

      const keys = await this._redis.client.keys(`${record.id}*`);
      for (const key of keys) {
        await this._redis.client.del(key);
      }

      this.logSecurityEvent({
        status: LogStatus.SUCCESS,
        description: 'Logout from all devices successful',
        details: { userId: record.id },
        context: logContext
      });
    } catch (error) {
      this.logSecurityEvent({
        status: LogStatus.FAILED,
        description: 'Logout from all devices system error',
        details: { error: error.message },
        context: logContext
      });
    }
  }
}