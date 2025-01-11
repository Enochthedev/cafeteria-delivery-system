import { Container } from 'inversify';
import { Logger } from '../config/logger';
import { Database } from '../config/db';
import { RedisClient } from '../config/redis';
import { LIB_TYPES, MIDDLEWARE_TYPES, SERVICE_TYPES } from './types';
import { BaseMiddleware } from 'inversify-express-utils';
import { AuthMiddleware } from '../middlewares/auth';
import { AuthController } from '../app/auth/auth.controller';
import { HeadersMiddleware } from '../middlewares/headers';
import { MailClient } from '../config/mail';
import { UserService } from '../app/users/user.service';
import { AuthService } from '../app/auth/services/auth.service';
import { FileUploadMiddleware } from '../middlewares/avatar';
import { StorageProvider } from '../config/cloud.storage';
import { ExtractTokenMiddleware } from '../middlewares/extract-token';
import { TokenService } from '../app/auth/services/token.service';

const container = new Container();

container.bind<Logger>(LIB_TYPES.Logger).to(Logger).inSingletonScope();
container.bind<Database>(LIB_TYPES.MongoDB).to(Database).inSingletonScope();
container.bind<RedisClient>(LIB_TYPES.RedisClient).to(RedisClient).inSingletonScope();
container.bind<StorageProvider>(LIB_TYPES.StorageProvider).to(StorageProvider).inSingletonScope();
container.bind<MailClient>(LIB_TYPES.MailClient).to(MailClient).inSingletonScope();

container.bind<BaseMiddleware>(MIDDLEWARE_TYPES.ExtractTokenMiddleware).to(ExtractTokenMiddleware);
container.bind<BaseMiddleware>(MIDDLEWARE_TYPES.AuthMiddleware).to(AuthMiddleware);
container.bind<HeadersMiddleware>(MIDDLEWARE_TYPES.HeadersMiddleware).to(HeadersMiddleware);

const logger = container.get<Logger>(LIB_TYPES.Logger);

container.bind<FileUploadMiddleware>(MIDDLEWARE_TYPES.FileUploadMiddleware).toDynamicValue(() => {
  return new FileUploadMiddleware(logger, {
    allowedTypes: /jpeg|jpg|png|gif/,
    maxSizeInBytes: 5 * 1024 * 1024, // 5MB
  });
});

container.bind<FileUploadMiddleware>(MIDDLEWARE_TYPES.FileUploadMiddlewareForVideos).toDynamicValue(() => {
  return new FileUploadMiddleware(logger, {
    allowedTypes: /mp4|mkv|avi/,
    maxSizeInBytes: 50 * 1024 * 1024, // 50MB
  });
});

container.bind<FileUploadMiddleware>(MIDDLEWARE_TYPES.FileUploadMiddlewareForDocuments).toDynamicValue(() => {
  return new FileUploadMiddleware(logger, {
    allowedTypes: /pdf|docx/,
    maxSizeInBytes: 5 * 1024 * 1024, // 5MB
  });
});

container.bind<FileUploadMiddleware>(MIDDLEWARE_TYPES.FileUploadMiddlewareForLessonFiles).toDynamicValue(() => {
  return new FileUploadMiddleware(logger, {
    allowedTypes: /mp4|mkv|avi|pdf|docx/,
    maxSizeInBytes: 50 * 1024 * 1024, // 50MB
  });
});

container.bind<FileUploadMiddleware>(MIDDLEWARE_TYPES.FileUploadMiddlewareForCoursePublicFiles).toDynamicValue(() => {
  return new FileUploadMiddleware(logger, {
    allowedTypes: /jpeg|jpg|png|gif|mp4|mkv|avi/,
    maxSizeInBytes: 20 * 1024 * 1024, // 20MB
  });
});

container.bind<AuthController>(AuthController).toSelf();

container.bind<AuthService>(SERVICE_TYPES.AuthService).to(AuthService);
container.bind<UserService>(SERVICE_TYPES.UserService).to(UserService);
container.bind<TokenService>(SERVICE_TYPES.TokenService).to(TokenService);

export { container };
