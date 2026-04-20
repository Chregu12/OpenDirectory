process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret-for-jest-not-for-production';
process.env.ADMIN_PASSWORD = 'TestAdmin123!';

const request = require('supertest');
const { app, userStore, hashPassword } = require('../server');

// Helper: get a valid auth cookie for admin
async function getAdminCookie() {
  const res = await request(app)
    .post('/api/auth/login')
    .send({ username: 'admin', password: 'TestAdmin123!' });
  if (!res.headers['set-cookie']) throw new Error('Login failed in test helper');
  return res.headers['set-cookie'][0].split(';')[0];
}

describe('POST /api/auth/login', () => {
  test('returns 400 if body is missing', async () => {
    const res = await request(app).post('/api/auth/login').send({});
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  test('returns 400 if username is missing', async () => {
    const res = await request(app).post('/api/auth/login').send({ password: 'test' });
    expect(res.status).toBe(400);
  });

  test('returns 400 if password is missing', async () => {
    const res = await request(app).post('/api/auth/login').send({ username: 'admin' });
    expect(res.status).toBe(400);
  });

  test('returns 401 for wrong credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'wronguser_notexist', password: 'wrongpassword' });
    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('returns 200 and sets httpOnly auth cookie for valid credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'TestAdmin123!' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.token).toBeDefined();
    expect(res.body.data.user.passwordHash).toBeUndefined();
    const cookies = res.headers['set-cookie'];
    expect(cookies).toBeDefined();
    expect(cookies.some(c => c.includes('auth_token') && c.includes('HttpOnly'))).toBe(true);
  });

  test('does not expose passwordHash in user object', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'TestAdmin123!' });
    expect(res.body.data?.user?.passwordHash).toBeUndefined();
  });
});

describe('POST /api/auth/logout', () => {
  test('clears auth cookie', async () => {
    const res = await request(app).post('/api/auth/logout');
    expect(res.status).toBe(200);
    const cookies = res.headers['set-cookie'];
    expect(cookies).toBeDefined();
    expect(cookies.some(c => c.includes('auth_token') && c.includes('Expires=Thu, 01 Jan 1970'))).toBe(true);
  });
});

describe('GET /api/auth/profile', () => {
  test('returns 401 without auth token', async () => {
    const res = await request(app).get('/api/auth/profile');
    expect(res.status).toBe(401);
  });

  test('returns profile with valid cookie', async () => {
    const cookie = await getAdminCookie();
    const res = await request(app).get('/api/auth/profile').set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(res.body.data.username).toBe('admin');
    expect(res.body.data.passwordHash).toBeUndefined();
  });
});

describe('Rate limiting', () => {
  test('blocks after 5 failed login attempts for same username', async () => {
    const badCreds = { username: 'ratelimit_testonly_user', password: 'wrongpassword' };
    let lastRes;
    for (let i = 0; i < 6; i++) {
      lastRes = await request(app).post('/api/auth/login').send(badCreds);
    }
    expect(lastRes.status).toBe(429);
  });
});

describe('POST /api/users (requires auth)', () => {
  let adminCookie;

  beforeAll(async () => {
    adminCookie = await getAdminCookie();
  });

  test('returns 401 without auth', async () => {
    const res = await request(app).post('/api/users').send({ username: 'newuser', password: 'Pass1234!' });
    expect(res.status).toBe(401);
  });

  test('returns 400 for invalid username characters', async () => {
    const res = await request(app)
      .post('/api/users')
      .set('Cookie', adminCookie)
      .send({ username: 'bad user!', password: 'Pass1234!' });
    expect(res.status).toBe(400);
  });

  test('returns 400 for too-short password', async () => {
    const res = await request(app)
      .post('/api/users')
      .set('Cookie', adminCookie)
      .send({ username: 'validuser', password: 'short' });
    expect(res.status).toBe(400);
  });

  test('creates user successfully with valid data', async () => {
    const res = await request(app)
      .post('/api/users')
      .set('Cookie', adminCookie)
      .send({ username: 'testcreateuser', password: 'ValidPass123!' });
    expect(res.status).toBe(201);
    expect(res.body.data.username).toBe('testcreateuser');
    expect(res.body.data.passwordHash).toBeUndefined();
  });
});
