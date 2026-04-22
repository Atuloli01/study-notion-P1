const request = require('supertest');
const app = require('../index');
const User = require('../models/User');
const OTP = require('../models/OTP');

// Mock the mailSender so we don't send real emails during tests
jest.mock('../utils/mailSender', () => jest.fn().mockResolvedValue({ response: 'Mocked email sent' }));

describe('Authentication API', () => {
  const testUser = {
    firstName: 'Test',
    lastName: 'User',
    email: 'testuser@example.com',
    password: 'password123',
    confirmPassword: 'password123',
    accountType: 'Student',
    contactNumber: '1234567890',
  };

  it('should generate an OTP for signup', async () => {
    const res = await request(app)
      .post('/api/v1/auth/sendotp')
      .send({ email: testUser.email });

    expect(res.statusCode).toEqual(200);
    expect(res.body.success).toBe(true);
    expect(res.body.message).toBe('OTP Sent Successfully');

    // Verify OTP was saved in DB
    const otpRecord = await OTP.findOne({ email: testUser.email });
    expect(otpRecord).toBeTruthy();
    expect(otpRecord.otp).toHaveLength(6);
  });

  it('should successfully register a new user with valid OTP', async () => {
    // 1. First, create an OTP directly in the DB
    const validOtp = '123456';
    await OTP.create({ email: testUser.email, otp: validOtp });

    // 2. Try to signup with that OTP
    const res = await request(app)
      .post('/api/v1/auth/signup')
      .send({ ...testUser, otp: validOtp });

    expect(res.statusCode).toEqual(200);
    expect(res.body.success).toBe(true);
    expect(res.body.message).toBe('User registered successfully');

    // Verify user is in DB
    const userInDb = await User.findOne({ email: testUser.email });
    expect(userInDb).toBeTruthy();
    expect(userInDb.firstName).toBe(testUser.firstName);
    // Password should be hashed
    expect(userInDb.password).not.toBe(testUser.password);
  });

  it('should not register user with invalid OTP', async () => {
    const res = await request(app)
      .post('/api/v1/auth/signup')
      .send({ ...testUser, email: 'another@example.com', otp: '000000' });

    expect(res.statusCode).toEqual(400);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe('The OTP is not valid');
  });

  it('should successfully login an existing user', async () => {
    // 1. Create OTP and signup user
    const validOtp = '654321';
    await OTP.create({ email: testUser.email, otp: validOtp });
    await request(app)
      .post('/api/v1/auth/signup')
      .send({ ...testUser, otp: validOtp });

    // 2. Login user
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: testUser.email, password: testUser.password });

    expect(res.statusCode).toEqual(200);
    expect(res.body.success).toBe(true);
    expect(res.body.token).toBeDefined();
    expect(res.body.message).toBe('User Login Success');
  });

  it('should reject login with wrong password', async () => {
    // 1. Create OTP and signup user
    const validOtp = '987654';
    await OTP.create({ email: testUser.email, otp: validOtp });
    await request(app)
      .post('/api/v1/auth/signup')
      .send({ ...testUser, otp: validOtp });

    // 2. Login user with wrong password
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: testUser.email, password: 'wrongpassword' });

    expect(res.statusCode).toEqual(401);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe('Password is incorrect');
  });
});
