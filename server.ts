import express from 'express';
import path from 'path';
import fs from 'fs/promises';
import { webcrypto } from 'crypto';
import { GoogleGenAI, Type, ThinkingLevel } from '@google/genai';
import dotenv from 'dotenv';
import { OAuth2Client } from 'google-auth-library';

// Load environmental variables
dotenv.config();

import { verifyProof } from './src/sandbox/lib/nizkp';
import { 
  recordAccessLog, 
  getAccessLogs, 
  getAccessStats, 
  clearAccessLogs, 
  exportAccessLogsCsv 
} from './src/server/accessLogDb';

// Google OAuth2 Client (Client ID optionally provided via environment variable)
const googleOAuthClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Lazy initialization of Gemini Client to prevent crashing during boot if the key is missing
let aiClient: GoogleGenAI | null = null;

function getGeminiClient(): GoogleGenAI {
  if (!aiClient) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey || apiKey === "MY_GEMINI_API_KEY") {
      throw new Error("GEMINI_API_KEY environment variable is not configured in Secrets.");
    }
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        }
      }
    });
  }
  return aiClient;
}

async function startServer() {
  const app = express();
  const PORT = Number.parseInt(process.env.PORT || '3000', 10) || 3000;

  app.use(express.json());
  app.use(express.raw({ type: 'application/octet-stream', limit: '1mb' }));
