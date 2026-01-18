/**
 * @claude-flow/cache-optimizer - Init Module
 *
 * Exports for project initialization and configuration management.
 */

// Main init functions
export {
  init,
  reset,
  validate,
  status,
  isInitialized,
  getCurrentConfig,
  getProfileOptions,
  type InitOptions,
  type InitResult,
} from './init.js';

// Profiles
export {
  getProfile,
  listProfiles,
  detectRecommendedProfile,
  mergeWithProfile,
  PROFILES,
  type ProfileId,
  type Profile,
  type ProfileCacheConfig,
  type ProfileHandoffConfig,
  type HookConfiguration,
  type HookEntry,
} from './profiles.js';

// Settings management
export {
  SettingsManager,
  createSettingsManager,
  type ClaudeSettings,
  type SettingsManagerConfig,
} from './settings-manager.js';
