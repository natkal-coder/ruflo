/**
 * Test Intelligence Plugin - Validation Script
 * Validates that all MCP tools work correctly with test data.
 */

import {
  testIntelligenceTools,
  selectPredictiveTool,
  flakyDetectTool,
  coverageGapsTool,
  mutationOptimizeTool,
  generateSuggestTool,
} from '../dist/mcp-tools.js';

const PASS = '\x1b[32mPASS\x1b[0m';
const FAIL = '\x1b[31mFAIL\x1b[0m';

interface ValidationResult {
  tool: string;
  passed: boolean;
  error?: string;
}

async function validateTool(
  name: string,
  handler: (input: Record<string, unknown>, context?: unknown) => Promise<{ success: boolean; data?: unknown; error?: string }>,
  input: Record<string, unknown>
): Promise<ValidationResult> {
  try {
    const result = await handler(input);

    if (!result.success && result.error) {
      return { tool: name, passed: false, error: result.error };
    }

    if (typeof result !== 'object') {
      return { tool: name, passed: false, error: 'Result is not an object' };
    }

    return { tool: name, passed: true };
  } catch (err) {
    return { tool: name, passed: false, error: String(err) };
  }
}

async function main() {
  console.log('Test Intelligence Plugin - MCP Tools Validation\n');
  console.log('='.repeat(60));

  const results: ValidationResult[] = [];

  // 1. Select Predictive Tool
  console.log('\n1. Testing test/select-predictive...');
  results.push(await validateTool(
    'test/select-predictive',
    selectPredictiveTool.handler,
    {
      changes: {
        files: ['src/auth/login.ts', 'src/api/users.ts', 'src/utils/validation.ts'],
        gitRef: 'HEAD',
      },
      strategy: 'risk_based',
      budget: {
        maxTests: 20,
        maxDuration: 300,
        confidence: 0.95,
      },
    }
  ));

  // 2. Flaky Detect Tool
  console.log('2. Testing test/flaky-detect...');
  results.push(await validateTool(
    'test/flaky-detect',
    flakyDetectTool.handler,
    {
      scope: {
        testSuite: 'unit',
        historyDepth: 30,
      },
      analysis: ['intermittent_failures', 'timing_sensitive', 'order_dependent'],
      threshold: 0.1,
    }
  ));

  // 3. Coverage Gaps Tool
  console.log('3. Testing test/coverage-gaps...');
  results.push(await validateTool(
    'test/coverage-gaps',
    coverageGapsTool.handler,
    {
      targetPaths: ['src/'],
      coverageType: 'branch',
      prioritization: 'risk',
      minCoverage: 80,
    }
  ));

  // 4. Mutation Optimize Tool
  console.log('4. Testing test/mutation-optimize...');
  results.push(await validateTool(
    'test/mutation-optimize',
    mutationOptimizeTool.handler,
    {
      targetPath: 'src/utils',
      budget: 50,
      strategy: 'ml_guided',
      mutationTypes: ['arithmetic', 'logical', 'boundary', 'null_check'],
    }
  ));

  // 5. Generate Suggest Tool
  console.log('5. Testing test/generate-suggest...');
  results.push(await validateTool(
    'test/generate-suggest',
    generateSuggestTool.handler,
    {
      targetFunction: 'src/services/UserService.createUser',
      testStyle: 'unit',
      framework: 'vitest',
      edgeCases: true,
      mockStrategy: 'minimal',
    }
  ));

  // Summary
  console.log('\n' + '='.repeat(60));
  console.log('VALIDATION SUMMARY\n');

  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;

  for (const result of results) {
    console.log(`  ${result.passed ? PASS : FAIL} ${result.tool}`);
    if (result.error) {
      console.log(`      Error: ${result.error.slice(0, 100)}`);
    }
  }

  console.log('\n' + '='.repeat(60));
  console.log(`Total: ${results.length} | Passed: ${passed} | Failed: ${failed}`);
  console.log('Exported tools:', testIntelligenceTools.length);

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Validation failed:', err);
  process.exit(1);
});
