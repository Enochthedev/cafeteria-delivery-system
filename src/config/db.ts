import * as mongoose from 'mongoose';
import { Connection } from 'mongoose';
import env from './env';
import { Logger } from './logger';
import { inject } from 'inversify';
import { LIB_TYPES } from '../di/types';

export class Database {
  private readonly _connection: Connection;

  constructor(@inject(LIB_TYPES.Logger) private readonly _logger: Logger) {
    this._connection = mongoose.createConnection(env.mongo_uri);

    this._connection.on('connected', (query) => this._logger.debug('connected to database'));

    this._connection.on('error', (err) => this._logger.error(err));

    this._connection.on('disconnected', () => this._logger.info('disconnected from database'));
  }

  get connection(): Connection {
    return this._connection;
  }

  async isHealthy(): Promise<void> {
    try {
      if (this._connection.readyState !== 1) {
        throw new Error('database is not healthy');
      }
    } catch (error) {
      this._logger.error('database is not healthy', { error });
    }
  }

  async close(): Promise<void> {
    await this._connection.destroy();
  }

  async setup(logger: Logger): Promise<Database> {
    return new Database(logger);
  }
}