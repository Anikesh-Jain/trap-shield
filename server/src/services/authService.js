/**
 * TRAPSHIELD Authentication Service
 * 
 * Manages user registration, credential verification, and safe profile handling.
 * 
 * SECURITY MANDATE:
 * - Strictly forbids public administrator registration or role selection.
 * - Enforces bcrypt cost factor 12 for password hashing.
 * - Validates password complexity (minimum 8 chars with letter and number).
 */

import { User } from '../models/User.js';
import { generateToken } from '../utils/token.js';

const EMAIL_REGEX = /^\S+@\S+\.\S+$/;

export async function register({ email, password }) {
  if (!email || typeof email !== 'string' || !EMAIL_REGEX.test(email.trim())) {
    const error = new Error('A valid email address is required');
    error.statusCode = 400;
    error.errorCode = 'INVALID_EMAIL';
    throw error;
  }

  if (!password || typeof password !== 'string' || password.length < 8) {
    const error = new Error('Password must be at least 8 characters in length');
    error.statusCode = 400;
    error.errorCode = 'WEAK_PASSWORD';
    throw error;
  }

  // Enforce at least one letter and one number
  if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
    const error = new Error('Password must contain at least one letter and one number');
    error.statusCode = 400;
    error.errorCode = 'WEAK_PASSWORD';
    throw error;
  }

  const normalizedEmail = email.trim().toLowerCase();

  const existing = await User.findOne({ email: normalizedEmail });
  if (existing) {
    const error = new Error('An account with this email address already exists');
    error.statusCode = 409;
    error.errorCode = 'EMAIL_ALREADY_EXISTS';
    throw error;
  }

  const passwordHash = await User.hashPassword(password);

  // STRICT PRIVILEGE ESCALATION PREVENTION: Role is permanently hardcoded to 'user'
  const user = await User.create({
    email: normalizedEmail,
    passwordHash,
    role: 'user',
    isActive: true,
  });

  const token = generateToken(user);
  return { user: user.toSafeJSON(), token };
}

export async function login({ email, password }) {
  if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
    const error = new Error('Email and password are required');
    error.statusCode = 400;
    error.errorCode = 'CREDENTIALS_REQUIRED';
    throw error;
  }

  const normalizedEmail = email.trim().toLowerCase();
  const user = await User.findOne({ email: normalizedEmail }).select('+passwordHash');

  if (!user) {
    const error = new Error('Invalid email or password');
    error.statusCode = 401;
    error.errorCode = 'INVALID_CREDENTIALS';
    throw error;
  }

  if (!user.isActive) {
    const error = new Error('Account has been suspended. Please contact administrator.');
    error.statusCode = 403;
    error.errorCode = 'ACCOUNT_SUSPENDED';
    throw error;
  }

  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    const error = new Error('Invalid email or password');
    error.statusCode = 401;
    error.errorCode = 'INVALID_CREDENTIALS';
    throw error;
  }

  user.lastLoginAt = new Date();
  await user.save();

  const token = generateToken(user);
  return { user: user.toSafeJSON(), token };
}

