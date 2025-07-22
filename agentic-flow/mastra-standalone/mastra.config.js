// Mastra Configuration for Agentic Flow
import { config } from 'dotenv';
import { mastra } from './src/mastra/index.js';

// Load environment variables
config();

// Export the mastra instance directly as Mastra expects
export default mastra;