const request = require('supertest');
const express = require('express');
const createApiRouter = require('../routes');
const path = require('path');

const app = express();
app.use(express.json());
app.use('/api', createApiRouter({
  usersFile: path.join(__dirname, '../data/test-users.json'),
  booksFile: path.join(__dirname, '../data/test-books.json'),
  readJSON: (file) => require('fs').existsSync(file) ? JSON.parse(require('fs').readFileSync(file, 'utf-8')) : [],
  writeJSON: (file, data) => require('fs').writeFileSync(file, JSON.stringify(data, null, 2)),
  authenticateToken: (req, res, next) => next(),
  SECRET_KEY: 'test_secret',
  skipRateLimit: true,
}));

describe('Auth API', () => {
  const testUser = { username: 'testuser', password: 'testpass' };

  it('POST /api/register should fail with missing fields', async () => {
    const res = await request(app).post('/api/register').send({ username: '' });
    expect(res.statusCode).toBe(400);
  });

  it('POST /api/register should succeed with valid data', async () => {
    const res = await request(app).post('/api/register').send(testUser);
    // 201 or 409 if already exists
    expect([201, 409]).toContain(res.statusCode);
  });

  it('POST /api/register should fail if user already exists', async () => {
    await request(app).post('/api/register').send(testUser); // ensure exists
    const res = await request(app).post('/api/register').send(testUser);
    expect(res.statusCode).toBe(409);
  });

  it('POST /api/login should succeed with correct credentials', async () => {
    await request(app).post('/api/register').send(testUser); // ensure exists
    const res = await request(app).post('/api/login').send(testUser);
    expect(res.statusCode).toBe(200);
    expect(res.body.token).toBeDefined();
  });

  it('POST /api/login should fail with wrong password', async () => {
    const res = await request(app).post('/api/login').send({ username: testUser.username, password: 'wrong' });
    expect(res.statusCode).toBe(401);
  });

  it('POST /api/login should fail with missing fields', async () => {
    const res = await request(app).post('/api/login').send({ username: '' });
    expect(res.statusCode).toBe(401);
  });
});

// generated-by-copilot: Test suite for rate limiting functionality
describe('Auth API Rate Limiting', () => {
  it('should rate limit login attempts after exceeding the limit', async () => {
    // Create a fresh app for each test to ensure isolation
    const appWithRateLimit = express();
    appWithRateLimit.use(express.json());
    appWithRateLimit.use('/api', createApiRouter({
      usersFile: path.join(__dirname, '../data/test-users.json'),
      booksFile: path.join(__dirname, '../data/test-books.json'),
      readJSON: (file) => require('fs').existsSync(file) ? JSON.parse(require('fs').readFileSync(file, 'utf-8')) : [],
      writeJSON: (file, data) => require('fs').writeFileSync(file, JSON.stringify(data, null, 2)),
      authenticateToken: (req, res, next) => next(),
      SECRET_KEY: 'test_secret',
      skipRateLimit: false, // Enable rate limiting for this test
    }));

    const testCreds = { username: 'ratelimituser', password: 'testpass' };
    
    // Make 5 login attempts (the limit)
    for (let i = 0; i < 5; i++) {
      const res = await request(appWithRateLimit).post('/api/login').send(testCreds);
      expect(res.statusCode).toBe(401); // Invalid credentials
    }
    
    // 6th attempt should be rate limited
    const res = await request(appWithRateLimit).post('/api/login').send(testCreds);
    expect(res.statusCode).toBe(429);
    expect(res.text).toContain('Too many');
  });

  it('should rate limit register attempts after exceeding the limit', async () => {
    // Create a fresh app for this test to ensure isolation
    const appWithRateLimit = express();
    appWithRateLimit.use(express.json());
    appWithRateLimit.use('/api', createApiRouter({
      usersFile: path.join(__dirname, '../data/test-users.json'),
      booksFile: path.join(__dirname, '../data/test-books.json'),
      readJSON: (file) => require('fs').existsSync(file) ? JSON.parse(require('fs').readFileSync(file, 'utf-8')) : [],
      writeJSON: (file, data) => require('fs').writeFileSync(file, JSON.stringify(data, null, 2)),
      authenticateToken: (req, res, next) => next(),
      SECRET_KEY: 'test_secret',
      skipRateLimit: false, // Enable rate limiting for this test
    }));

    // Make 5 register attempts (the limit)
    for (let i = 0; i < 5; i++) {
      const res = await request(appWithRateLimit).post('/api/register').send({ 
        username: `ratelimituser${i}`, 
        password: 'testpass' 
      });
      expect([201, 409]).toContain(res.statusCode); // Created or already exists
    }
    
    // 6th attempt should be rate limited
    const res = await request(appWithRateLimit).post('/api/register').send({ 
      username: 'ratelimituser6', 
      password: 'testpass' 
    });
    expect(res.statusCode).toBe(429);
  });
});
