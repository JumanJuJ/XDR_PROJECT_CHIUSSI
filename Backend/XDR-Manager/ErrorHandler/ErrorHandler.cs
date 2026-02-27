
namespace ErrorHandler
{
    public enum ErrorCode
    {
        // 4xx – Client / Input
        BadRequest = 400,
        Unauthorized = 401,
        Forbidden = 403,
        NotFound = 404,
        Conflict = 409,
        ValidationError = 422,

        // 5xx – Server
        InternalError = 500,
        NotImplemented = 501,
        ServiceUnavailable = 503,

        // Custom app-level
        DatabaseError = 600,
        ExternalServiceError = 601
    }

    public class AppException : Exception
    {
        public ErrorCode Code { get; }

        public AppException(ErrorCode code, string message, Exception? inner = null)
            : base(message, inner)
        {
            Code = code;
        }
    }

    public static class ErrorManager
    {
        // =========================
        // SYNC
        // =========================
        public static TResult Handle<TResult>(
            Func<TResult> action,
            string context)
        {
            try
            {
                return action();
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (AppException)
            {
                throw;
            }
            catch (ArgumentException ex)
            {
               // Log.WriteLog($"Bad request. {context} :: {ex}", "WARN");
                throw new AppException(ErrorCode.BadRequest, ex.Message, ex);
            }
            catch (UnauthorizedAccessException ex)
            {
              //  Log.WriteLog($"Unauthorized. {context} :: {ex}", "WARN");
                throw new AppException(ErrorCode.Unauthorized, "Unauthorized access", ex);
            }
            catch (KeyNotFoundException ex)
            {
               // Log.WriteLog($"Not found. {context} :: {ex}", "WARN");
                throw new AppException(ErrorCode.NotFound, "Resource not found", ex);
            }
            catch (TimeoutException ex)
            {
               // Log.WriteLog($"Timeout. {context} :: {ex}", "WARN");
                throw new AppException(ErrorCode.ServiceUnavailable, "Service timeout", ex);
            }
            catch (Exception ex)
            {
              //  Log.WriteLog($"Internal error. {context} :: {ex}", "ERROR");
                throw new AppException(ErrorCode.InternalError, "Internal server error", ex);
            }
        }

        public static void Handle(
            Action action,
            string context = "")
        {
            Handle(() =>
            {
                action();
                return true;
            }, context);
        }

        // =========================
        // ASYNC
        // =========================
        public static async Task Handle(
            Func<Task> action,
            string context = "")
        {
            try
            {
                await action().ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (AppException)
            {
                throw;
            }
            catch (ArgumentException ex)
            {
               // Log.WriteLog($"Bad request. {context} :: {ex}", "WARN");
                throw new AppException(ErrorCode.BadRequest, ex.Message, ex);
            }
            catch (UnauthorizedAccessException ex)
            {
               // Log.WriteLog($"Unauthorized. {context} :: {ex}", "WARN");
                throw new AppException(ErrorCode.Unauthorized, "Unauthorized access", ex);
            }
            catch (KeyNotFoundException ex)
            {
               // Log.WriteLog($"Not found. {context} :: {ex}", "WARN");
                throw new AppException(ErrorCode.NotFound, "Resource not found", ex);
            }
            catch (TimeoutException ex)
            {
               // Log.WriteLog($"Timeout. {context} :: {ex}", "WARN");
                throw new AppException(ErrorCode.ServiceUnavailable, "Service timeout", ex);
            }
            catch (Exception ex)
            {
              //  Log.WriteLog($"Internal error. {context} :: {ex}", "ERROR");
                throw new AppException(ErrorCode.InternalError, "Internal server error", ex);
            }
        }

        public static async Task<TResult> Handle<TResult>(
            Func<Task<TResult>> action,
            string context = "")
        {
            try
            {
                return await action().ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (AppException)
            {
                throw;
            }
            catch (ArgumentException ex)
            {
               // Log.WriteLog($"Bad request. {context} :: {ex}", "WARN");
                throw new AppException(ErrorCode.BadRequest, ex.Message, ex);
            }
            catch (UnauthorizedAccessException ex)
            {
               // Log.WriteLog($"Unauthorized. {context} :: {ex}", "WARN");
                throw new AppException(ErrorCode.Unauthorized, "Unauthorized access", ex);
            }
            catch (KeyNotFoundException ex)
            {
                //Log.WriteLog($"Not found. {context} :: {ex}", "WARN");
                throw new AppException(ErrorCode.NotFound, "Resource not found", ex);
            }
            catch (TimeoutException ex)
            {
               // Log.WriteLog($"Timeout. {context} :: {ex}", "WARN");
                throw new AppException(ErrorCode.ServiceUnavailable, "Service timeout", ex);
            }
            catch (Exception ex)
            {
                //Log.WriteLog($"Internal error. {context} :: {ex}", "ERROR");
                throw new AppException(ErrorCode.InternalError, "Internal server error", ex);
            }
        }
    }
}
