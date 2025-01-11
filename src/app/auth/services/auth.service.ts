import { inject, injectable } from 'inversify';
import { LIB_TYPES, SERVICE_TYPES } from '../../../di/types';
import { Database } from '../../../config/db';
import { RedisClient } from '../../../config/redis';
import { Logger } from '../../../config/logger';
import { LoginDto } from '../dto/login.dto';
import { UserService } from '../../users/user.service';
import { IAuthRecord, ILog } from '../../../interfaces/interfaces';
import { LogStatus, RedisJob, TokenType } from '../../../enums/enum';
import { Exception } from '../../../internal/exception';
import bcrypt from 'bcryptjs';
import env from '../../../config/env';
import Default from '../../defaults/default';
import { Token, TokenDocument } from '../models/token.model';
import { ResetPasswordDto, TokenDto } from '../dto/token.dto';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';
import jwt from 'jsonwebtoken';
import { Connection, Types } from 'mongoose';
import { User, UserDocument } from '../../users/models/user.model';
import { TokenService } from './token.service';

@injectable()
export class AuthService {
  private readonly _conn: Connection;

  constructor(
    @inject(SERVICE_TYPES.UserService) private readonly _userService: UserService,
    @inject(SERVICE_TYPES.TokenService) private readonly _tokenService: TokenService,
    @inject(LIB_TYPES.MongoDB) private readonly _db: Database,
    @inject(LIB_TYPES.RedisClient) private readonly _redis: RedisClient,
    @inject(LIB_TYPES.Logger) private readonly _logger: Logger,
  ) {
    this._conn = this._db.connection;
  }

  public async login(
    dto: LoginDto,
    ipAddress: string,
    userAgent: string,
    timestamp: string,
    requestId: string,
  ) {
    const user: UserDocument | null = await this._userService.findOne({ email: dto.email });
    if (!user) {
      const payload: ILog = {
        action: 'LOGIN',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to login - user not found',
        details: { email: dto.email },
      };
      this._logger.error(payload.description, payload);
      throw new Exception('Invalid email or password', Exception.UNPROCESSABLE_ENTITY);
    }

    const doPasswordsMatch: boolean = await this._userService.comparePassword(dto.password, user.password);
    if (!doPasswordsMatch) {
      const payload: ILog = {
        action: 'LOGIN',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to login - invalid password',
        details: { email: dto.email },
      };
      this._logger.error(payload.description, payload);
      throw new Exception('Invalid email or password', Exception.UNPROCESSABLE_ENTITY);
    }

    const lastLogin = Date.now();
    const accessToken = Default.GENERATE_ACCESS_TOKEN(user.id, user.email, lastLogin);

    await this._redis.client.set(`${user.id}:session-${lastLogin}`, accessToken, 'EX', 20 * 60);

    return {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      // avatar: 'avatar_key' in profile && profile.avatar_key !== null ? Default.FORMAT_AWS_S3_URL(env.aws_s3_public_bucket, String(profile.avatar_key)) : null,
      isVerified: user.verifiedAt !== null,
      token: accessToken,
    };
  }

  public async startEmailVerification(
    record: IAuthRecord,
    ipAddress: string,
    userAgent: string,
    timestamp: string,
    requestId: string,
  ): Promise<Record<string, string>> {
    const user: UserDocument | null = await this._userService.findOne({ id: record.id });
    if (!user) {
      const payload: ILog = {
        action: 'START_EMAIL_VERIFICATION',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to start email verification - user not found',
        details: { userId: record.id },
      };
      this._logger.error(payload.description, payload);
      throw new Exception('User does not exist', Exception.NOT_FOUND);
    }

    if (user.verifiedAt !== null) {
      const payload: ILog = {
        action: 'START_EMAIL_VERIFICATION',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to start email verification - user is already verified',
        details: { userId: user.id },
      };
      this._logger.error(payload.description, payload);
      throw new Exception('User is already verified', Exception.UNPROCESSABLE_ENTITY);
    }

    const token = await this._tokenService.create(user.id, Default.GENERATE_OTP(), TokenType.OTP, 20);

    await this._redis.addJob(RedisJob.SEND_VERIFICATION_OTP, {
      data: {
        name: user.firstName,
        email: user.email,
        otp: token.token,
        expiresIn: new Date(token.validTill).getMinutes() - new Date().getMinutes(),
      },
      ip: ipAddress,
      userAgent: userAgent,
      timestamp: timestamp,
      requestId: requestId,
    });

    return { email: user.email };
  }

  public async completeEmailVerification(
    record: IAuthRecord,
    dto: TokenDto,
    ipAddress: string,
    userAgent: string,
    timestamp: string,
    requestId: string,
  ): Promise<void> {
    const user: UserDocument | null = await this._userService.findOne({ id: record.id });
    if (!user) {
      const payload: ILog = {
        action: 'COMPLETE_EMAIL_VERIFICATION',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to complete email verification - user not found',
        details: { userId: record.id },
      };
      this._logger.error(payload.description, payload);
      throw new Exception('User does not exist', Exception.NOT_FOUND);
    }

    const token: TokenDocument | null = await Token.findOne({ token: dto.otp });
    if (!token) {
      const payload: ILog = {
        action: 'COMPLETE_EMAIL_VERIFICATION',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to complete email verification - OTP does not exist',
        details: { userId: user.id },
      };
      this._logger.error(payload.description, payload);
      throw new Exception('One-Time Passcode does not exist', Exception.NOT_FOUND);
    }

    if (new Date(token.validTill) < new Date()) {
      const payload: ILog = {
        action: 'COMPLETE_EMAIL_VERIFICATION',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to complete email verification - token has expired',
        details: { userId: user.id },
      };
      this._logger.error(payload.description, payload);

      await Token.deleteOne({ _id: token._id });

      throw new Exception('One-Time Passcode has expired', Exception.UNAUTHORIZED);
    }

    await this._conn.transaction(async trx => {
      await User.updateOne({ _id: user._id }, { verifiedAt: new Date() }, { session: trx });

      await Token.deleteOne({ _id: token._id }, { session: trx });
    });

    const payload: ILog = {
      action: 'COMPLETE_EMAIL_VERIFICATION',
      data: undefined,
      status: LogStatus.SUCCESS,
      timestamp: timestamp,
      ipAddress: ipAddress,
      userAgent: userAgent,
      requestId: requestId,
      description: 'email verification successful',
      details: { userId: user.id },
    };
    this._logger.debug(payload.description, payload);

    await this._redis.addJob(RedisJob.SEND_WELCOME_EMAIL, {
      data: {
        name: user.firstName,
        email: user.email,
      },
      ip: ipAddress,
      userAgent: userAgent,
      timestamp: timestamp,
      requestId: requestId,
    });
  }

  public async forgotPassword(
    dto: ForgotPasswordDto,
    ipAddress: string,
    userAgent: string,
    timestamp: string,
    requestId: string,
  ): Promise<void> {
    const user: UserDocument | null = await this._userService.findOne({ email: dto.email });
    if (!user) {
      const payload: ILog = {
        action: 'FORGOT_PASSWORD',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to initiate password reset - user not found',
        details: { email: dto.email },
      };
      this._logger.error(payload.description, payload);
      throw new Exception('User does not exist', Exception.NOT_FOUND);
    }

    const expiryInMinutes = 20;
    const resetJwt = Default.GENERATE_PASSWORD_RESET_TOKEN(user.id, user.email, dto.profileType, expiryInMinutes);
    const token: TokenDocument = await this._tokenService.create(user.id, resetJwt, TokenType.RESET, expiryInMinutes);

    await this._redis.addJob(RedisJob.SEND_PASSWORD_RESET_LINK, {
      data: {
        name: user.firstName,
        email: user.email,
        link: dto.redirectUrl + '?token=' + token.token,
        expiresIn: new Date(token.validTill).getMinutes() - new Date().getMinutes(),
      },
      ip: ipAddress,
      userAgent: userAgent,
      timestamp: timestamp,
      requestId: requestId,
    });
  }

  public async verifyPasswordResetToken(
    token: string,
    ipAddress: string,
    userAgent: string,
    timestamp: string,
    requestId: string,
  ): Promise<void> {
    const userToken: TokenDocument | null = await Token.findOne({ token: token, type: TokenType.RESET });
    if (!userToken) {
      const payload: ILog = {
        action: 'VERIFY_PASSWORD_RESET_TOKEN',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to verify password reset token',
        details: { token: token },
      };
      this._logger.error(payload.description, payload);
      throw new Exception('Invalid token issuer', Exception.UNAUTHORIZED);
    }

    if (userToken.usedAt) {
      const payload: ILog = {
        action: 'VERIFY_PASSWORD_RESET_TOKEN',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to verify password reset token - token has already been used',
        details: { token: token },
      };
      this._logger.error(payload.description, payload);
      throw new Exception('Token has already been used', Exception.UNAUTHORIZED);
    }

    if (new Date(userToken.validTill) < new Date()) {
      const payload: ILog = {
        action: 'VERIFY_PASSWORD_RESET_TOKEN',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to verify password reset token - token has expired',
        details: { token: token },
      };
      this._logger.error(payload.description, payload);

      await Token.deleteOne({ _id: userToken._id });

      throw new Exception('Token has expired', Exception.UNAUTHORIZED);
    }

    await Token.updateOne({ _id: userToken._id }, { usedAt: new Date() });
  }

  public async resetPassword(
    dto: ResetPasswordDto,
    ipAddress: string,
    userAgent: string,
    timestamp: string,
    requestId: string,
  ): Promise<void> {
    const decodedToken = jwt.verify(dto.token, env.jwt_password_reset_secret, {
      ignoreExpiration: true,
    }) as jwt.JwtPayload;
    if (!decodedToken || decodedToken.type !== 'password-reset') {
      const payload: ILog = {
        action: 'RESET_PASSWORD',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to reset password - invalid token',
        details: { token: dto.token },
      };
      this._logger.error(payload.description, payload);
      throw new Exception('Invalid token', Exception.UNAUTHORIZED);
    }

    const userToken: TokenDocument | null = await Token.findOne({
      user: Types.ObjectId.createFromHexString(decodedToken.sub!),
      token: dto.token,
      type: TokenType.RESET,
    }).populate('user');
    if (!userToken) {
      const payload: ILog = {
        action: 'RESET_PASSWORD',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to reset password - token does not exist',
        details: { token: dto.token },
      };
      this._logger.error(payload.description, payload);
      throw new Exception('Invalid token', Exception.UNAUTHORIZED);
    }

    if (!userToken.usedAt) {
      const payload: ILog = {
        action: 'RESET_PASSWORD',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to reset password - token has not been verified',
        details: { token: dto.token },
      };
      this._logger.error(payload.description, payload);
      throw new Exception('Token has not been verified', Exception.UNAUTHORIZED);
    }

    const user = userToken.user as UserDocument | null;
    if (!user) {
      const payload: ILog = {
        action: 'RESET_PASSWORD',
        data: undefined,
        status: LogStatus.FAILED,
        timestamp: timestamp,
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        description: 'failed to reset password - user not found',
        details: { userId: userToken.user.id },
      };
      this._logger.error(payload.description, payload);
      throw new Exception('User does not exist', Exception.NOT_FOUND);
    }

    const salt = await bcrypt.genSalt(Number(env.bcrypt_rounds));
    const password = await bcrypt.hash(dto.password, salt);
    await this._conn.transaction(async trx => {
      await User.updateOne({ _id: user._id }, { password: password }, { session: trx });

      await Token.deleteOne({ _id: userToken._id }, { session: trx });
    });

    await this._redis.addJob(RedisJob.SEND_PASSWORD_RESET_SUCCESS_EMAIL, {
      data: {
        name: user.firstName,
        email: user.email,
      },
      ip: ipAddress,
      userAgent: userAgent,
      timestamp: timestamp,
      requestId: requestId,
    });

    const keys = await this._redis.client.keys(`${user.id}*`);
    for (const key of keys) {
      await this._redis.client.del(key);
    }
  }

  public async logout(
    record: IAuthRecord,
    ipAddress: string,
    userAgent: string,
    timestamp: string,
    requestId: string,
  ): Promise<void> {
    await this._redis.client.del(`${record.id}:session-${record.lastLogin}`);

    const payload: ILog = {
      action: 'LOGOUT',
      data: undefined,
      status: LogStatus.SUCCESS,
      timestamp: timestamp,
      ipAddress: ipAddress,
      userAgent: userAgent,
      requestId: requestId,
      description: 'user logged out successfully',
      details: { userId: record.id },
    };
    this._logger.debug(payload.description, payload);
  }

  public async logoutFromAllDevices(
    record: IAuthRecord,
    ipAddress: string,
    userAgent: string,
    timestamp: string,
    requestId: string,
  ): Promise<void> {
    const keys = await this._redis.client.keys(`${record.id}*`);
    for (const key of keys) {
      await this._redis.client.del(key);
    }

    const payload: ILog = {
      action: 'LOGOUT_FROM_ALL_DEVICES',
      data: undefined,
      status: LogStatus.SUCCESS,
      timestamp: timestamp,
      ipAddress: ipAddress,
      userAgent: userAgent,
      requestId: requestId,
      description: 'user logged out from all devices successfully',
      details: { userId: record.id },
    };
    this._logger.debug(payload.description, payload);
  }
}