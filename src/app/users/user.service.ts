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

  constructor(
    @inject(LIB_TYPES.MongoDB) private readonly _db: Database,
    @inject(LIB_TYPES.RedisClient) private readonly _redis: RedisClient,
    @inject(LIB_TYPES.Logger) private readonly _logger: Logger,
    @inject(SERVICE_TYPES.TokenService) private readonly _tokenService: TokenService,
  ) {
    this._conn = _db.connection;
  }

  public async comparePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
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
    ipAddress: string,
    userAgent: string,
    timestamp: string,
    requestId: string,
  ) {
    let phone: string;
    try {
      phone = Default.FORMAT_PHONE_AS_INTERNATIONAL(dto.callingCode, dto.nationalNumber);
    } catch (err) {
      throw new Exception(`Failed to create an account - Invalid phone number`, Exception.UNPROCESSABLE_ENTITY);
    }

    const existingUser = await this.findOne({ email: dto.email });
    if (existingUser) {
      const payload: ILog = {
        action: 'CREATE_USER',
        data: undefined,
        description: 'failed to create user - user already exists',
        ipAddress: ipAddress,
        userAgent: userAgent,
        requestId: requestId,
        timestamp: timestamp,
        status: LogStatus.FAILED,
        details: { userId: existingUser.id },
      };
      this._logger.error(payload.description, payload);
      throw new Exception('Oops! an account with this email already exists', Exception.CONFLICT);
    }
    const { token, user } = await this._conn.transaction(async (trx) => {
      const user: UserDocument = await new User({
        firstName: dto.firstName,
        lastName: dto.lastName,
        email: dto.email,
        password: dto.password,
        phone: phone,
      }).save({ session: trx });

      const token: TokenDocument = await this._tokenService.create(user.id, Default.GENERATE_OTP(), TokenType.OTP, 20, trx);

      return { token, user };
    });

    const payload: ILog = {
      action: 'CREATE_USER',
      data: undefined,
      description: 'user created successfully',
      ipAddress: ipAddress,
      userAgent: userAgent,
      requestId: requestId,
      timestamp: timestamp,
      status: LogStatus.SUCCESS,
      details: { userId: user.id, email: user.email },
    };
    this._logger.debug(payload.description, payload);

    await this._redis.addJob(RedisJob.SEND_VERIFICATION_OTP, {
      data: {
        name: dto.firstName,
        email: user.email,
        otp: token.token,
        expiresIn: new Date(token.validTill).getMinutes() - new Date().getMinutes(),
      },
      ip: ipAddress,
      userAgent: userAgent,
      timestamp: timestamp,
      requestId: requestId,
    });

    const lastLogin = Date.now();
    const accessToken = Default.GENERATE_ACCESS_TOKEN(user.id, user.email, lastLogin);

    await this._redis.client.set(`${user.id}:session-${lastLogin}`, accessToken, 'EX', 20 * 60);

    return { token: accessToken };
  }
}
