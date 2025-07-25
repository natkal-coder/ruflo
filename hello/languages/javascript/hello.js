/**
 * @module hello
 * @description Modern JavaScript Hello World implementation with ES6+ features
 */

/**
 * Greeting class that demonstrates ES6 class syntax
 * @class
 */
export class Greeting {
  /**
   * Create a greeting instance
   * @param {string} [name='World'] - The name to greet
   */
  constructor(name = 'World') {
    this.name = name;
  }

  /**
   * Get the greeting message
   * @returns {string} The greeting message
   */
  getMessage() {
    return `Hello, ${this.name}!`;
  }

  /**
   * Print the greeting to console
   * @returns {void}
   */
  greet() {
    console.log(this.getMessage());
  }
}

/**
 * Functional approach to greeting using arrow functions
 * @param {string} [name='World'] - The name to greet
 * @returns {string} The greeting message
 */
export const greetFunction = (name = 'World') => `Hello, ${name}!`;

/**
 * Async greeting with simulated delay
 * @param {string} [name='World'] - The name to greet
 * @param {number} [delay=1000] - Delay in milliseconds
 * @returns {Promise<string>} Promise resolving to greeting message
 */
export const greetAsync = async (name = 'World', delay = 1000) => {
  await new Promise(resolve => setTimeout(resolve, delay));
  return `Hello, ${name}! (after ${delay}ms)`;
};

/**
 * Demonstrate various ES6+ features
 * @returns {void}
 */
export const demonstrateFeatures = () => {
  // Destructuring
  const { name, version } = { name: 'JavaScript', version: 'ES2024' };
  console.log(`Language: ${name}, Version: ${version}`);

  // Spread operator
  const greetings = ['Hello', 'Hi', 'Hey'];
  const moreGreetings = [...greetings, 'Howdy', 'Greetings'];
  console.log('All greetings:', moreGreetings.join(', '));

  // Template literals with expressions
  const items = ['JavaScript', 'TypeScript', 'Node.js'];
  console.log(`Technologies: ${items.map((item, i) => `${i + 1}. ${item}`).join(', ')}`);

  // Array methods
  const numbers = [1, 2, 3, 4, 5];
  const doubled = numbers.map(n => n * 2);
  const sum = numbers.reduce((acc, n) => acc + n, 0);
  console.log(`Numbers doubled: [${doubled}], Sum: ${sum}`);
};

// Main execution when run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  console.log('=== JavaScript Hello World ===\n');

  // Class-based approach
  const greeting1 = new Greeting();
  greeting1.greet();

  const greeting2 = new Greeting('JavaScript Developer');
  greeting2.greet();

  // Functional approach
  console.log(greetFunction());
  console.log(greetFunction('ES6+ User'));

  // Async approach
  console.log('\nAsync greetings:');
  greetAsync('Async World', 500).then(console.log);

  // Demonstrate features
  console.log('\nES6+ Features Demo:');
  demonstrateFeatures();
}