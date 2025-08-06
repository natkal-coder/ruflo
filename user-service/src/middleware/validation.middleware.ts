import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';
import { ValidationError } from '../utils/errors';

export function validateBody(schema: Joi.Schema) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const { error, value } = schema.validate(req.body, { abortEarly: false });
    
    if (error) {
      const messages = error.details.map(detail => detail.message).join(', ');
      return next(new ValidationError(messages));
    }
    
    req.body = value;
    next();
  };
}

export function validateQuery(schema: Joi.Schema) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const { error, value } = schema.validate(req.query, { abortEarly: false });
    
    if (error) {
      const messages = error.details.map(detail => detail.message).join(', ');
      return next(new ValidationError(messages));
    }
    
    req.query = value;
    next();
  };
}

export function validateParams(schema: Joi.Schema) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const { error, value } = schema.validate(req.params, { abortEarly: false });
    
    if (error) {
      const messages = error.details.map(detail => detail.message).join(', ');
      return next(new ValidationError(messages));
    }
    
    req.params = value;
    next();
  };
}