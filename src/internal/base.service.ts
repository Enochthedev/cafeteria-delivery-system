import { Logger } from '../config/logger';

export abstract class BaseService {
  constructor(
    protected readonly _logger: Logger
  ) {
  }

  protected logDebug(action: string, message: string, data: any, requestId: string, timestamp: string): void {
    // const pa
    this._logger.debug(message, { data, requestId, timestamp });
  }


}