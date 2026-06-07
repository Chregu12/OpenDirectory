'use strict';

/**
 * Standard service error types for OpenDirectory microservices.
 *
 * Using shared error classes lets services inspect error types consistently
 * when they propagate across service boundaries.
 */

class ServiceError extends Error {
  constructor(message, statusCode = 500) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * A downstream service is unreachable or returned an error response.
 * Maps to HTTP 503 Service Unavailable.
 */
class ServiceUnavailableError extends ServiceError {
  constructor(serviceName, cause) {
    super(
      cause
        ? `${serviceName} is unavailable: ${cause}`
        : `${serviceName} is unavailable`,
      503
    );
    this.serviceName = serviceName;
    this.cause = cause || null;
  }
}

/**
 * The request payload or query parameters failed validation.
 * Maps to HTTP 400 Bad Request.
 */
class ValidationError extends ServiceError {
  constructor(message, field) {
    super(message, 400);
    this.field = field || null;
  }
}

/**
 * A requested resource does not exist.
 * Maps to HTTP 404 Not Found.
 */
class NotFoundError extends ServiceError {
  constructor(resourceType, id) {
    super(
      id
        ? `${resourceType} with id '${id}' not found`
        : `${resourceType} not found`,
      404
    );
    this.resourceType = resourceType;
    this.resourceId = id || null;
  }
}

/**
 * The caller is not authorised to perform the requested operation.
 * Maps to HTTP 403 Forbidden.
 */
class ForbiddenError extends ServiceError {
  constructor(message) {
    super(message || 'Forbidden', 403);
  }
}

/**
 * The operation conflicts with the current resource state.
 * Maps to HTTP 409 Conflict.
 */
class ConflictError extends ServiceError {
  constructor(message) {
    super(message, 409);
  }
}

module.exports = {
  ServiceError,
  ServiceUnavailableError,
  ValidationError,
  NotFoundError,
  ForbiddenError,
  ConflictError
};
