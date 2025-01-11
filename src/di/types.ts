export const LIB_TYPES = {
  Logger: Symbol.for("Logger"),
  MongoDB: Symbol.for("MongoDB"),
  RedisClient: Symbol.for("RedisClient"),
  MailClient: Symbol.for("MailClient"),
  StorageProvider: Symbol.for("StorageProvider"),
};

export const MIDDLEWARE_TYPES = {
  ExtractTokenMiddleware: Symbol.for("ExtractTokenMiddleware"),
  AuthMiddleware: Symbol.for("AuthMiddleware"),
  HeadersMiddleware: Symbol.for("HeadersMiddleware"),
  FileUploadMiddleware: Symbol.for("FileUploadMiddleware"),
  FileUploadMiddlewareForVideos: Symbol.for("FileUploadMiddlewareForVideos"),
  FileUploadMiddlewareForDocuments: Symbol.for("FileUploadMiddlewareForDocuments"),
  FileUploadMiddlewareForCoursePublicFiles: Symbol.for("FileUploadMiddlewareForCoursePublicFiles"),
  FileUploadMiddlewareForLessonFiles: Symbol.for("FileUploadMiddlewareForLessonFiles"),
}

export const SERVICE_TYPES = {
  AuthService: Symbol.for("AuthService"),
  UserService: Symbol.for("UserService"),
  TokenService: Symbol.for("TokenService"),
}
