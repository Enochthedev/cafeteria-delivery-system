import { inject, injectable } from 'inversify';
import { LIB_TYPES } from '../../../di/types';
import { Database } from '../../../config/db';
import { Logger } from '../../../config/logger';
import { TokenType } from '../../../enums/enum';
import { Token, TokenDocument } from '../models/token.model';
import Default from '../../defaults/default';
import { ClientSession } from 'mongoose';

@injectable()
export class TokenService {
  constructor(
    @inject(LIB_TYPES.MongoDB) private readonly _db: Database,
    @inject(LIB_TYPES.Logger) private readonly _logger: Logger,
  ) {
  }

  public async create(userId: string, code: string, type: TokenType, expiresInMinutes: number, session: ClientSession | null = null): Promise<TokenDocument> {
    return await new Token({
      user: userId,
      type: type,
      token: code,
      validTill: new Date(Date.now() + (expiresInMinutes * 60_000)),
    }).save({ session: session });
  }

  public async invalidateUserTokens(
    userId: string,
    types: TokenType[] = [TokenType.RESET],
    session?: ClientSession
  ): Promise<void> {
    await Token.deleteMany({
      user: userId,
      type: { $in: types }
    }).session(session || null);
  }
}