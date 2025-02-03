import { Job, JobsOptions, Queue, Worker } from 'bullmq';
import { inject, injectable } from 'inversify';
import Redis from 'ioredis';
import { LIB_TYPES } from '../di/types';
import env from './env';
import { Logger } from './logger';
import { JobData, processJobs } from './job.processor';
import { RedisJob } from '../enums/enum';
import { MailClient } from './mail';
import { StorageProvider } from './cloud.storage';


@injectable()
export class RedisClient {
  private readonly _client: Redis;

  private _queue: Queue<JobData> | undefined;
  private _worker: Worker<JobData> | undefined;

  private readonly DEFAULT_EMAIL_QUEUE = 'emailQueue';

  constructor(
    @inject(LIB_TYPES.MailClient) private readonly _mailClient: MailClient,
    @inject(LIB_TYPES.Logger) private readonly _logger: Logger,
    @inject(LIB_TYPES.StorageProvider) private readonly _storageProvider: StorageProvider
  ) {
    this._client = new Redis({
      host: env.redis_host,
      port: env.redis_port,
      db: 1,
      maxRetriesPerRequest: null
    });

    this._client.on('error', (err) => {
      this._logger.error('redis error', { error: err });
    });

    this._client.on('connect', () => {
      this._logger.info('connected to redis');
    });

    this._client.on('ready', () => {
      this._logger.info('redis is ready');
    });

    this.initializeDefaultWorker();
  }

  get client(): Redis {
    return this._client;
  }

  private initializeDefaultWorker(): void {
    const emailJobProcessor =
      (job: Job) => processJobs(job, this._mailClient, this._storageProvider, this._logger);

    this._queue = this.createQueue(this.DEFAULT_EMAIL_QUEUE);
    this._worker = this.createWorker(this.DEFAULT_EMAIL_QUEUE, emailJobProcessor);
  }

  createQueue(queueName: string = this.DEFAULT_EMAIL_QUEUE): Queue {
    const queue = new Queue<JobData>(queueName, {
      connection: this._client,
      defaultJobOptions: { removeOnComplete: true }
    });

    this._logger.info(`queue "${queueName}" created`);

    return queue;
  }

  createWorker(queueName: string, processor: (job: Job) => Promise<void>): Worker {
    const worker = new Worker(queueName, processor, { connection: this._client });
    this._logger.info(`worker for queue "${queueName}" created`);

    worker.on('completed', (job) => {
      this._logger.info(`job ${job.id} on queue "${queueName}" completed`);
    });

    worker.on('failed', (job, err) => {
      this._logger.error(`job ${job?.id} on queue "${queueName}" failed`, { error: err });
    });

    return worker;
  }

  async addJob(jobName: RedisJob, jobData: JobData, options: JobsOptions = {}): Promise<void> {
    if (!this._queue) {
      throw new Error(`queue "${this.DEFAULT_EMAIL_QUEUE}" is not initialized`);
    }

    await this._queue.add(jobName, jobData, options);
    this._logger.info(`job "${jobName}" added to queue "${this.DEFAULT_EMAIL_QUEUE}"`);
  }

  async isHealthy(): Promise<void> {
    try {
      await this._client.ping();
    } catch (error) {
      this._logger.error('redis is not healthy', { error });
    }
  }

  async close(): Promise<void> {
    if (this._worker) {
      await this._worker.close();
      this._logger.info(`worker closed`);
    }

    if (this._queue) {
      await this._queue.close();
      this._logger.info(`queue closed`);
    }

    await this._client.quit();
    this._logger.info('redis connection closed');
  }

  public async deleteUserSessions(userId: string): Promise<number> {
    try {
      const pattern = `${userId}:session-*`;
      const keys = await this._client.keys(pattern);
      
      if (keys.length === 0) return 0;
      
      const deletedCount = await this._client.del(...keys);
      this._logger.info(`Deleted ${deletedCount} sessions for user ${userId}`);
      return deletedCount;
    } catch (error) {
      this._logger.error('Failed to delete user sessions', { error, userId });
      throw new Error('Failed to clear user sessions');
    }
  }

  public async getUserSessionKeys(userId: string): Promise<string[]> {
    try {
      const pattern = `${userId}:session-*`;
      return await this._client.keys(pattern);
    } catch (error) {
      this._logger.error('Failed to get user sessions', { error, userId });
      return [];
    }
  }

}
