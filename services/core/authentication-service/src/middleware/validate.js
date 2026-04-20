const Joi = require('joi');

const PASSWORD_SCHEMA = Joi.string().min(8).max(128).required();
const USERNAME_SCHEMA = Joi.string().alphanum().min(2).max(64).required();
const EMAIL_SCHEMA    = Joi.string().email().max(254).required();

const schemas = {
  login: Joi.object({
    username: Joi.string().min(1).max(254).required(),
    password: Joi.string().min(1).max(128).required(),
    mfaCode:  Joi.string().length(6).pattern(/^\d+$/).optional(),
    deviceId: Joi.string().max(128).optional(),
    provider: Joi.string().valid('local', 'ldap', 'sso').optional(),
  }),

  register: Joi.object({
    username:  USERNAME_SCHEMA,
    email:     EMAIL_SCHEMA,
    password:  PASSWORD_SCHEMA,
    firstName: Joi.string().max(100).optional(),
    lastName:  Joi.string().max(100).optional(),
  }),

  changePassword: Joi.object({
    currentPassword: Joi.string().min(1).max(128).required(),
    newPassword:     PASSWORD_SCHEMA,
  }),

  mfaVerify: Joi.object({
    code:      Joi.string().length(6).pattern(/^\d+$/).required(),
    tempToken: Joi.string().required(),
  }),
};

function validate(schemaName) {
  return (req, res, next) => {
    const schema = schemas[schemaName];
    if (!schema) return next();

    const { error, value } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
    if (error) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.details.map(d => ({ field: d.path.join('.'), message: d.message })),
      });
    }
    req.body = value;
    next();
  };
}

module.exports = { validate, schemas };
