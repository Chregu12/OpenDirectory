const { schemas } = require('../middleware/validate');

describe('Login schema', () => {
  const schema = schemas.login;

  test('accepts valid credentials', () => {
    const { error } = schema.validate({ username: 'admin', password: 'mypassword' });
    expect(error).toBeUndefined();
  });

  test('rejects missing username', () => {
    const { error } = schema.validate({ password: 'mypassword' });
    expect(error).toBeDefined();
    expect(error.details[0].path).toContain('username');
  });

  test('rejects missing password', () => {
    const { error } = schema.validate({ username: 'admin' });
    expect(error).toBeDefined();
    expect(error.details[0].path).toContain('password');
  });

  test('rejects invalid mfaCode (non-numeric)', () => {
    const { error } = schema.validate({ username: 'admin', password: 'pass', mfaCode: 'abcdef' });
    expect(error).toBeDefined();
  });

  test('rejects invalid mfaCode (wrong length)', () => {
    const { error } = schema.validate({ username: 'admin', password: 'pass', mfaCode: '12345' });
    expect(error).toBeDefined();
  });

  test('accepts valid 6-digit mfaCode', () => {
    const { error } = schema.validate({ username: 'admin', password: 'pass', mfaCode: '123456' });
    expect(error).toBeUndefined();
  });

  test('rejects invalid provider', () => {
    const { error } = schema.validate({ username: 'admin', password: 'pass', provider: 'evil' });
    expect(error).toBeDefined();
  });
});

describe('Register schema', () => {
  const schema = schemas.register;

  test('accepts valid registration data', () => {
    const { error } = schema.validate({
      username: 'newuser',
      email: 'user@example.com',
      password: 'SecurePass123',
    });
    expect(error).toBeUndefined();
  });

  test('rejects non-alphanumeric username', () => {
    const { error } = schema.validate({
      username: 'bad user!',
      email: 'user@example.com',
      password: 'SecurePass123',
    });
    expect(error).toBeDefined();
  });

  test('rejects invalid email', () => {
    const { error } = schema.validate({
      username: 'gooduser',
      email: 'not-an-email',
      password: 'SecurePass123',
    });
    expect(error).toBeDefined();
  });

  test('rejects password shorter than 8 chars', () => {
    const { error } = schema.validate({
      username: 'gooduser',
      email: 'user@example.com',
      password: 'short',
    });
    expect(error).toBeDefined();
  });

  test('strips unknown fields', () => {
    const { value, error } = schema.validate({
      username: 'gooduser',
      email: 'user@example.com',
      password: 'SecurePass123',
      injected: 'hacker',
    }, { stripUnknown: true });
    expect(error).toBeUndefined();
    expect(value.injected).toBeUndefined();
  });
});

describe('Change password schema', () => {
  const schema = schemas.changePassword;

  test('accepts valid password change', () => {
    const { error } = schema.validate({ currentPassword: 'OldPass123', newPassword: 'NewPass456' });
    expect(error).toBeUndefined();
  });

  test('rejects missing currentPassword', () => {
    const { error } = schema.validate({ newPassword: 'NewPass456' });
    expect(error).toBeDefined();
  });

  test('rejects new password shorter than 8 chars', () => {
    const { error } = schema.validate({ currentPassword: 'OldPass123', newPassword: 'short' });
    expect(error).toBeDefined();
  });
});
