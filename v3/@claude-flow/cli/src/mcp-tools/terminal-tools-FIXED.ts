/**
 * Terminal MCP Tools for CLI - SECURITY PATCHED
 *
 * Terminal session management with real command execution.
 *
 * Security fixes applied:
 * - FIND-001: Use SafeExecutor instead of raw execSync (command injection)
 * - FIND-002: Whitelist environment variables (privilege escalation)
 * - FIND-005: Validate working directory paths (path traversal)
 * - FIND-006: Secure file permissions for terminal storage (0o600)
 */

import type { MCPTool } from './types.js';
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { join, normalize, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as os from 'node:os';

const execFileAsync = promisify(execFile);

// FIND-006: Use secure temp directory with restrictive permissions
function getTerminalDir(): string {
  const homeDir = process.env.HOME || os.homedir();
  return join(homeDir, '.claude-flow-secure', 'terminals');
}

function getTerminalPath(): string {
  return join(getTerminalDir(), 'store.json');
}

function ensureTerminalDir(): void {
  const dir = getTerminalDir();
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 }); // rwx------
  }
}

// FIND-002: Whitelist safe environment variables
function getSafeEnvironment(sessionEnv?: Record<string, string>): Record<string, string> {
  const ALLOWED_ENV_VARS = [
    'PATH', 'HOME', 'SHELL', 'TERM', 'LANG', 'LC_ALL',
    'USER', 'LOGNAME', 'PWD', 'TMPDIR',
    'NODE_OPTIONS', 'NODE_ENV' // Safe for Node/dev
  ];

  const safeEnv: Record<string, string> = {};

  // Copy allowed system variables
  for (const key of ALLOWED_ENV_VARS) {
    if (key in process.env && process.env[key]) {
      safeEnv[key] = process.env[key]!;
    }
  }

  // Apply session overrides with validation
  if (sessionEnv) {
    for (const [key, value] of Object.entries(sessionEnv)) {
      // Reject suspicious environment variable names
      if (!key.match(/^[A-Z_][A-Z0-9_]*$/)) {
        console.warn(`Rejected invalid env var name: ${key}`);
        continue;
      }
      // Reject values with null bytes
      if (typeof value === 'string' && value.includes('\0')) {
        console.warn(`Rejected env var with null byte: ${key}`);
        continue;
      }
      // Only allow session overrides for non-critical vars
      if (!['PATH', 'HOME', 'SHELL', 'USER', 'LOGNAME', 'PWD'].includes(key)) {
        safeEnv[key] = value;
      }
    }
  }

  return safeEnv;
}

// FIND-005: Validate and normalize working directory paths
function validateWorkingDir(requestedDir?: string): string {
  const baseDir = process.cwd();
  const defaultDir = requestedDir || baseDir;

  try {
    // Normalize to prevent traversal attacks
    const normalized = normalize(defaultDir);
    const resolved = resolve(baseDir, normalized);

    // Ensure resolved path stays within or at base directory
    // Allow both the current directory and subdirectories
    if (!resolved.startsWith(baseDir) && resolved !== baseDir) {
      console.warn(`Path traversal attempt blocked: ${requestedDir} -> ${resolved}`);
      return baseDir;
    }

    // Verify directory exists or is creatable
    if (existsSync(resolved)) {
      return resolved;
    }

    return baseDir; // Fall back to safe directory
  } catch {
    return baseDir;
  }
}

// FIND-001: SafeCommand executor (allowlist + no shell)
interface CommandExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

// Whitelist of safe commands for execution
const ALLOWED_COMMANDS = new Set([
  'ls', 'cat', 'grep', 'find', 'head', 'tail', 'wc', 'echo',
  'pwd', 'cd', 'mkdir', 'touch', 'cp', 'mv', 'rm', // Use with caution
  'git', 'npm', 'node', 'npm', 'npx', 'yarn', 'pnpm',
  'npm', 'curl', 'wget', 'tar', 'zip', 'unzip',
  'ps', 'top', 'df', 'du', 'free', 'uptime'
]);

async function executeCommand(command: string, cwd: string, timeout: number, env: Record<string, string>): Promise<CommandExecutionResult> {
  // Parse command and arguments
  const parts = command.trim().split(/\s+/);
  if (parts.length === 0) {
    throw new Error('Empty command');
  }

  const cmd = parts[0];
  const args = parts.slice(1);

  // FIND-001: Whitelist check
  if (!ALLOWED_COMMANDS.has(cmd)) {
    throw new Error(`Command not allowed: ${cmd}`);
  }

  // Check for injection attempts in arguments
  for (const arg of args) {
    if (/[;&|`$(){}><\n\r\0]/.test(arg)) {
      throw new Error(`Argument contains shell metacharacters: ${arg}`);
    }
  }

  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, {
      cwd,
      timeout,
      maxBuffer: 5 * 1024 * 1024,
      env,
      shell: false, // CRITICAL: no shell interpretation
    });

    return {
      stdout: stdout || '',
      stderr: stderr || '',
      exitCode: 0,
    };
  } catch (err: any) {
    return {
      stdout: err.stdout || '',
      stderr: err.stderr || err.message || '',
      exitCode: err.code || 1,
    };
  }
}

interface TerminalSession {
  id: string;
  name: string;
  status: 'active' | 'idle' | 'closed';
  createdAt: string;
  lastActivity: string;
  workingDir: string;
  history: Array<{ command: string; output: string; timestamp: string; exitCode: number }>;
  env: Record<string, string>;
}

interface TerminalStore {
  sessions: Record<string, TerminalSession>;
  version: string;
}

function loadTerminalStore(): TerminalStore {
  try {
    const path = getTerminalPath();
    if (existsSync(path)) {
      return JSON.parse(readFileSync(path, 'utf-8'));
    }
  } catch {
    // Return empty store
  }
  return { sessions: {}, version: '3.0.0' };
}

function saveTerminalStore(store: TerminalStore): void {
  ensureTerminalDir();
  const path = getTerminalPath();
  writeFileSync(path, JSON.stringify(store, null, 2), {
    encoding: 'utf-8',
    mode: 0o600, // rw------- (owner read/write only)
  });

  // Extra safety: explicitly set permissions
  try {
    chmodSync(path, 0o600);
  } catch {
    // Ignore if chmod fails
  }
}

export const terminalTools: MCPTool[] = [
  {
    name: 'terminal_create',
    description: 'Create a new terminal session',
    category: 'terminal',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Session name' },
        workingDir: { type: 'string', description: 'Working directory (validated)' },
        env: { type: 'object', description: 'Environment variables (whitelist applied)' },
      },
    },
    handler: async (input) => {
      const store = loadTerminalStore();
      const id = `term-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

      // FIND-005: Validate working directory
      const validatedDir = validateWorkingDir(input.workingDir as string);

      const session: TerminalSession = {
        id,
        name: (input.name as string) || `Terminal ${Object.keys(store.sessions).length + 1}`,
        status: 'active',
        createdAt: new Date().toISOString(),
        lastActivity: new Date().toISOString(),
        workingDir: validatedDir,
        history: [],
        env: getSafeEnvironment(input.env as Record<string, string>),
      };

      store.sessions[id] = session;
      saveTerminalStore(store);

      return {
        success: true,
        sessionId: id,
        name: session.name,
        status: session.status,
        workingDir: session.workingDir,
        createdAt: session.createdAt,
      };
    },
  },
  {
    name: 'terminal_execute',
    description: 'Execute a command in a terminal session',
    category: 'terminal',
    inputSchema: {
      type: 'object',
      properties: {
        sessionId: { type: 'string', description: 'Terminal session ID' },
        command: { type: 'string', description: 'Command to execute (allowlist enforced)' },
        timeout: { type: 'number', description: 'Command timeout in ms' },
        captureOutput: { type: 'boolean', description: 'Capture command output' },
      },
      required: ['command'],
    },
    handler: async (input) => {
      const store = loadTerminalStore();
      const sessionId = input.sessionId as string;
      const command = input.command as string;

      // Find or create default session
      let session = sessionId ? store.sessions[sessionId] : Object.values(store.sessions).find(s => s.status === 'active');

      if (!session) {
        const id = `term-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        session = {
          id,
          name: 'Default Terminal',
          status: 'active',
          createdAt: new Date().toISOString(),
          lastActivity: new Date().toISOString(),
          workingDir: validateWorkingDir(),
          history: [],
          env: getSafeEnvironment(),
        };
        store.sessions[id] = session;
      }

      const timeout = (input.timeout as number) || 30_000;
      const cwd = session.workingDir || process.cwd();
      const startTime = Date.now();
      let output: string = '';
      let exitCode: number = 1;

      try {
        // FIND-001: Use safe command executor instead of raw execSync
        const result = await executeCommand(
          command,
          cwd,
          timeout,
          getSafeEnvironment(session.env)
        );
        output = result.stdout + (result.stderr ? `\n[stderr] ${result.stderr}` : '');
        exitCode = result.exitCode;
      } catch (err: any) {
        output = `[Error] ${err.message}`;
        exitCode = 1;
      }

      const duration = Date.now() - startTime;
      const timestamp = new Date().toISOString();

      // Record in history
      session.history.push({
        command,
        output,
        timestamp,
        exitCode,
      });
      session.lastActivity = timestamp;
      session.status = 'active';

      saveTerminalStore(store);

      return {
        success: exitCode === 0,
        sessionId: session.id,
        command,
        output,
        exitCode,
        executedAt: timestamp,
        duration,
      };
    },
  },
  {
    name: 'terminal_list',
    description: 'List all terminal sessions',
    category: 'terminal',
    inputSchema: {
      type: 'object',
      properties: {
        status: { type: 'string', enum: ['all', 'active', 'idle', 'closed'], description: 'Filter by status' },
        includeHistory: { type: 'boolean', description: 'Include command history' },
      },
    },
    handler: async (input) => {
      const store = loadTerminalStore();
      let sessions = Object.values(store.sessions);

      if (input.status && input.status !== 'all') {
        sessions = sessions.filter(s => s.status === input.status);
      }

      return {
        sessions: sessions.map(s => ({
          id: s.id,
          name: s.name,
          status: s.status,
          workingDir: s.workingDir,
          createdAt: s.createdAt,
          lastActivity: s.lastActivity,
          historyLength: s.history.length,
          ...(input.includeHistory ? { history: s.history.slice(-10) } : {}),
        })),
        total: sessions.length,
        active: sessions.filter(s => s.status === 'active').length,
      };
    },
  },
  {
    name: 'terminal_close',
    description: 'Close a terminal session',
    category: 'terminal',
    inputSchema: {
      type: 'object',
      properties: {
        sessionId: { type: 'string', description: 'Session ID to close' },
        force: { type: 'boolean', description: 'Force close' },
      },
      required: ['sessionId'],
    },
    handler: async (input) => {
      const store = loadTerminalStore();
      const sessionId = input.sessionId as string;
      const session = store.sessions[sessionId];

      if (!session) {
        return { success: false, error: 'Session not found' };
      }

      session.status = 'closed';
      saveTerminalStore(store);

      return {
        success: true,
        sessionId,
        closedAt: new Date().toISOString(),
      };
    },
  },
  {
    name: 'terminal_history',
    description: 'Get command history for a terminal session',
    category: 'terminal',
    inputSchema: {
      type: 'object',
      properties: {
        sessionId: { type: 'string', description: 'Session ID' },
        limit: { type: 'number', description: 'Number of entries to return' },
        offset: { type: 'number', description: 'Offset from latest' },
      },
    },
    handler: async (input) => {
      const store = loadTerminalStore();
      const sessionId = input.sessionId as string;
      const limit = Math.min((input.limit as number) || 50, 100); // Cap at 100
      const offset = (input.offset as number) || 0;

      if (sessionId) {
        const session = store.sessions[sessionId];
        if (!session) {
          return { success: false, error: 'Session not found' };
        }

        const history = session.history.slice(-(limit + offset), offset ? -offset : undefined);
        return {
          sessionId,
          history,
          total: session.history.length,
        };
      }

      // Return combined history from all sessions
      const allHistory = Object.values(store.sessions)
        .flatMap(s => s.history.map(h => ({ ...h, sessionId: s.id })))
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(offset, offset + limit);

      return {
        history: allHistory,
        total: allHistory.length,
      };
    },
  },
];
