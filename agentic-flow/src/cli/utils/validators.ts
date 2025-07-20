export function validateProjectName(name: string): true | string {
  if (!name || name.trim().length === 0) {
    return 'Project name cannot be empty';
  }

  if (name.length > 214) {
    return 'Project name must be less than 214 characters';
  }

  // Check for valid npm package name
  const validName = /^[a-z0-9-._~]+$/;
  if (!validName.test(name)) {
    return 'Project name can only contain lowercase letters, numbers, and -._~';
  }

  // Cannot start with . or _
  if (name.startsWith('.') || name.startsWith('_')) {
    return 'Project name cannot start with . or _';
  }

  // Reserved names
  const reserved = ['node_modules', 'favicon.ico'];
  if (reserved.includes(name.toLowerCase())) {
    return `Project name cannot be ${name}`;
  }

  return true;
}

export function validateAgentName(name: string): true | string {
  if (!name || name.trim().length === 0) {
    return 'Agent name cannot be empty';
  }

  if (name.length > 50) {
    return 'Agent name must be less than 50 characters';
  }

  const validName = /^[a-zA-Z0-9-_]+$/;
  if (!validName.test(name)) {
    return 'Agent name can only contain letters, numbers, hyphens, and underscores';
  }

  return true;
}

export function validateWorkflowName(name: string): true | string {
  if (!name || name.trim().length === 0) {
    return 'Workflow name cannot be empty';
  }

  if (name.length > 100) {
    return 'Workflow name must be less than 100 characters';
  }

  const validName = /^[a-zA-Z0-9-_\s]+$/;
  if (!validName.test(name)) {
    return 'Workflow name can only contain letters, numbers, spaces, hyphens, and underscores';
  }

  return true;
}

export function validateCronExpression(expression: string): true | string {
  // Basic cron expression validation
  const parts = expression.split(' ');
  
  if (parts.length !== 5) {
    return 'Cron expression must have 5 parts (minute hour day month weekday)';
  }

  // More sophisticated validation could be added here
  return true;
}

export function validateUrl(url: string): true | string {
  try {
    new URL(url);
    return true;
  } catch {
    return 'Invalid URL format';
  }
}

export function validateEmail(email: string): true | string {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return 'Invalid email format';
  }
  return true;
}

export function validatePort(port: number): true | string {
  if (!Number.isInteger(port)) {
    return 'Port must be an integer';
  }
  
  if (port < 1 || port > 65535) {
    return 'Port must be between 1 and 65535';
  }
  
  return true;
}