import { inject, injectable } from 'inversify';
import { LIB_TYPES, SERVICE_TYPES } from '../../di/types';
import { Logger } from '../../config/logger';
import { User, UserDocument } from './models/user.model';
import { Exception } from '../../internal/exception';
import { ILog } from '../../interfaces/interfaces';
import { LogStatus, RedisJob, TokenType } from '../../enums/enum';
import bcrypt from 'bcryptjs';
import env from '../../config/env';
import Default from '../defaults/default';
import { RedisClient } from '../../config/redis';
import { Database } from '../../config/db';
import { CreateUserDto } from './dto/user.dto';
import { ClientSession, Connection, FilterQuery } from 'mongoose';
import { TokenDocument } from '../auth/models/token.model';
import { TokenService } from '../auth/services/token.service';


@injectable()
export class UserService {
  private readonly _conn: Connection;
  private readonly SESSION_EXPIRATION = 20 * 60; // 20 minutes in seconds

  constructor(
    @inject(LIB_TYPES.MongoDB) private readonly _db: Database,
    @inject(LIB_TYPES.RedisClient) private readonly _redis: RedisClient,
    @inject(LIB_TYPES.Logger) private readonly _logger: Logger,
    @inject(SERVICE_TYPES.TokenService) private readonly _tokenService: TokenService,
  ) {
    this._conn = _db.connection;
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
      service: 'user',
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


  public async comparePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  public async isPreviousPassword(
    userId: string,
    newPassword: string
  ): Promise<boolean> {
    const user = await User.findById(userId)
      .select('+passwordHistory')
      .lean()
      .exec();

    if (!user || !user.passwordHistory?.length) {
      return false;
    }

    // Check against all previous passwords
    for (const oldPassword of user.passwordHistory) {
      if (await bcrypt.compare(newPassword, oldPassword)) {
        return true;
      }
    }
    
    return false;
  }

  public async updatePassword(
    userId: string,
    newPassword: string
  ): Promise<void> {
    const salt = await bcrypt.genSalt(Number(env.bcrypt_rounds));
    const newHash = await bcrypt.hash(newPassword, salt);

    await User.findByIdAndUpdate(userId, {
      $set: { password: newHash },
      $push: { 
        passwordHistory: {
          $each: [newHash],
          $slice: -5 // Keep last 5 passwords
        }
      },
      $currentDate: { lastPasswordChange: true }
    });
  }

  public async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(Number(env.bcrypt_rounds));
    return bcrypt.hash(password, salt);
  }

  public async findOne(filters: FilterQuery<UserDocument>, session: ClientSession | null = null): Promise<UserDocument | null> {
    return User.findOne(filters, {}, { session: session });
  }

  public async createUser(
    dto: CreateUserDto,
    context: {ipAddress: string; userAgent: string; timestamp: string; requestId: string }
  ) {
    const logContext = {
      service: 'user',
      operation: 'CREATE_USER',
      ...context
    };
    this._logger.debug('Creating user', logContext);
    let phone: string;
    // try {
    //   phone = Default.FORMAT_PHONE_AS_INTERNATIONAL(dto.callingCode, dto.phoneNumber);
    // } catch (err) {
    //   throw new Exception(`Failed to create an account - Invalid phone number`, Exception.UNPROCESSABLE_ENTITY);
    // }
    
    const existingUser = await this.findOne({ email: dto.email });
    if (existingUser) {
      this.logSecurityEvent({
        status: LogStatus.FAILED,
        description: 'Failed to create user - email already exists',
        details: { email: dto.email },
        context: logContext
      });
      throw new Exception('Oops! an account with this email already exists', Exception.CONFLICT);
    }
    const { token, user } = await this._conn.transaction(async (trx) => {
      const user: UserDocument = await new User({
        firstName: dto.firstName,
        lastName: dto.lastName,
        email: dto.email,
        password: dto.password,
        phone: '',// come back to this line to fix the phone number
      }).save({ session: trx });

      const token: TokenDocument = await this._tokenService.create(user.id, Default.GENERATE_OTP(), TokenType.OTP, 20, trx);

      return { token, user };
    });

    this.logSecurityEvent({
      status: LogStatus.SUCCESS,
      description: 'User created successfully',
      details: { email: user.email },
      context: logContext
    });

    await this._redis.addJob(RedisJob.SEND_VERIFICATION_OTP, {
      data: {
        name: dto.firstName,
        email: user.email,
        otp: token.token,
        expiresIn: new Date(token.validTill).getMinutes() - new Date().getMinutes(),
      },
      ip: context.ipAddress,
      userAgent: context.userAgent,
      timestamp: context.timestamp,
      requestId: context.requestId,
    });

    const lastLogin = Date.now();
    const accessToken = Default.GENERATE_ACCESS_TOKEN(user.id, user.email, lastLogin);

    await this._redis.client.set(`${user.id}:session-${lastLogin}`, accessToken, 'EX', 20 * 60);

    return { token: accessToken };
  }
}
