import { Agent, Tool, Workflow } from '@mastra/core';
import { EventEmitter } from 'eventemitter3';
import { v4 } from 'uuid';
import winston from 'winston';
import * as natural from 'natural';
import nlp from 'compromise';
import { EventEmitter as EventEmitter$1 } from 'events';
import { interpret, createMachine } from 'xstate';
import { Database } from 'sqlite3';
import path from 'path';
import fs from 'fs-extra';

var AgentType = /* @__PURE__ */ ((AgentType2) => {
  AgentType2["COORDINATOR"] = "coordinator";
  AgentType2["EXECUTOR"] = "executor";
  AgentType2["ANALYZER"] = "analyzer";
  AgentType2["MONITOR"] = "monitor";
  AgentType2["SPECIALIST"] = "specialist";
  return AgentType2;
})(AgentType || {});
var AgentState = /* @__PURE__ */ ((AgentState2) => {
  AgentState2["IDLE"] = "idle";
  AgentState2["THINKING"] = "thinking";
  AgentState2["EXECUTING"] = "executing";
  AgentState2["COMMUNICATING"] = "communicating";
  AgentState2["COORDINATING"] = "coordinating";
  AgentState2["ERROR"] = "error";
  AgentState2["TERMINATED"] = "terminated";
  return AgentState2;
})(AgentState || {});
var GoalType = /* @__PURE__ */ ((GoalType2) => {
  GoalType2["ACHIEVE"] = "achieve";
  GoalType2["MAINTAIN"] = "maintain";
  GoalType2["QUERY"] = "query";
  GoalType2["PERFORM"] = "perform";
  GoalType2["PREVENT"] = "prevent";
  return GoalType2;
})(GoalType || {});
var GoalPriority = /* @__PURE__ */ ((GoalPriority2) => {
  GoalPriority2["CRITICAL"] = "critical";
  GoalPriority2["HIGH"] = "high";
  GoalPriority2["MEDIUM"] = "medium";
  GoalPriority2["LOW"] = "low";
  return GoalPriority2;
})(GoalPriority || {});
var GoalStatus = /* @__PURE__ */ ((GoalStatus2) => {
  GoalStatus2["PENDING"] = "pending";
  GoalStatus2["ACTIVE"] = "active";
  GoalStatus2["COMPLETED"] = "completed";
  GoalStatus2["FAILED"] = "failed";
  GoalStatus2["SUSPENDED"] = "suspended";
  return GoalStatus2;
})(GoalStatus || {});
var MessageType = /* @__PURE__ */ ((MessageType2) => {
  MessageType2["REQUEST"] = "request";
  MessageType2["RESPONSE"] = "response";
  MessageType2["INFORM"] = "inform";
  MessageType2["QUERY"] = "query";
  MessageType2["COMMAND"] = "command";
  MessageType2["BROADCAST"] = "broadcast";
  MessageType2["NEGOTIATE"] = "negotiate";
  MessageType2["ACKNOWLEDGE"] = "acknowledge";
  return MessageType2;
})(MessageType || {});
var MessagePriority = /* @__PURE__ */ ((MessagePriority2) => {
  MessagePriority2["URGENT"] = "urgent";
  MessagePriority2["HIGH"] = "high";
  MessagePriority2["NORMAL"] = "normal";
  MessagePriority2["LOW"] = "low";
  return MessagePriority2;
})(MessagePriority || {});
var TeamFormation = /* @__PURE__ */ ((TeamFormation2) => {
  TeamFormation2["HIERARCHICAL"] = "hierarchical";
  TeamFormation2["FLAT"] = "flat";
  TeamFormation2["MATRIX"] = "matrix";
  TeamFormation2["DYNAMIC"] = "dynamic";
  return TeamFormation2;
})(TeamFormation || {});
var TeamStatus = /* @__PURE__ */ ((TeamStatus2) => {
  TeamStatus2["FORMING"] = "forming";
  TeamStatus2["ACTIVE"] = "active";
  TeamStatus2["EXECUTING"] = "executing";
  TeamStatus2["DISBANDED"] = "disbanded";
  return TeamStatus2;
})(TeamStatus || {});
var TaskStatus = /* @__PURE__ */ ((TaskStatus2) => {
  TaskStatus2["PENDING"] = "pending";
  TaskStatus2["ASSIGNED"] = "assigned";
  TaskStatus2["IN_PROGRESS"] = "in_progress";
  TaskStatus2["COMPLETED"] = "completed";
  TaskStatus2["FAILED"] = "failed";
  TaskStatus2["CANCELLED"] = "cancelled";
  return TaskStatus2;
})(TaskStatus || {});

function createMastraAgent(agenticFlowAgent) {
  const agentType = agenticFlowAgent.getType();
  const agentName = agenticFlowAgent.getName();
  const modelMapping = {
    [AgentType.COORDINATOR]: { provider: "anthropic", name: "claude-3-opus-20240229" },
    [AgentType.EXECUTOR]: { provider: "anthropic", name: "claude-3-sonnet-20240229" },
    [AgentType.RESEARCHER]: { provider: "openai", name: "gpt-4-turbo" },
    [AgentType.ANALYST]: { provider: "anthropic", name: "claude-3-sonnet-20240229" },
    [AgentType.ARCHITECT]: { provider: "anthropic", name: "claude-3-opus-20240229" },
    [AgentType.CODER]: { provider: "openai", name: "gpt-4-turbo" },
    [AgentType.TESTER]: { provider: "openai", name: "gpt-4" },
    [AgentType.DOCUMENTER]: { provider: "openai", name: "gpt-4" },
    [AgentType.REVIEWER]: { provider: "anthropic", name: "claude-3-sonnet-20240229" },
    [AgentType.MONITOR]: { provider: "openai", name: "gpt-3.5-turbo" },
    [AgentType.OPTIMIZER]: { provider: "anthropic", name: "claude-3-opus-20240229" },
    [AgentType.SPECIALIST]: { provider: "anthropic", name: "claude-3-opus-20240229" }
  };
  const model = modelMapping[agentType] || { provider: "openai", name: "gpt-4" };
  const capabilities = agenticFlowAgent.getCapabilities();
  const instructions = `You are ${agentName}, an ${agentType} agent with the following capabilities:
${capabilities.map((cap) => `- ${cap.name}: ${cap.description}`).join("\n")}

Your role is to work within the agentic-flow system to accomplish tasks assigned to you.
You should collaborate with other agents and use the available tools to complete your objectives.`;
  const tools = [];
  return new Agent({
    name: agentName.toLowerCase().replace(/\s+/g, "-"),
    description: `${agentType} agent: ${agentName}`,
    model,
    instructions,
    tools
  });
}
const researcherAgent = new Agent({
  name: "researcher",
  description: "Research agent for information gathering and analysis",
  model: {
    provider: "openai",
    name: "gpt-4-turbo"
  },
  instructions: `You are a research agent specialized in:
    - Gathering information from various sources
    - Analyzing and synthesizing data
    - Identifying patterns and insights
    - Providing comprehensive research reports
    - Fact-checking and verification`,
  tools: []
});
const architectAgent = new Agent({
  name: "architect",
  description: "Architecture agent for system design and planning",
  model: {
    provider: "anthropic",
    name: "claude-3-opus-20240229"
  },
  instructions: `You are an architecture agent responsible for:
    - Designing system architectures
    - Creating technical specifications
    - Planning implementation strategies
    - Evaluating technology choices
    - Ensuring scalability and performance`,
  tools: []
});
const coderAgent = new Agent({
  name: "coder",
  description: "Coding agent for implementation and development",
  model: {
    provider: "openai",
    name: "gpt-4-turbo"
  },
  instructions: `You are a coding agent specialized in:
    - Writing clean, efficient code
    - Implementing features and functionality
    - Following best practices and patterns
    - Debugging and problem-solving
    - Code optimization and refactoring`,
  tools: []
});
const testerAgent = new Agent({
  name: "tester",
  description: "Testing agent for quality assurance",
  model: {
    provider: "openai",
    name: "gpt-4"
  },
  instructions: `You are a testing agent focused on:
    - Writing comprehensive test cases
    - Performing unit and integration testing
    - Identifying bugs and issues
    - Ensuring code quality
    - Test automation and coverage`,
  tools: []
});
const reviewerAgent = new Agent({
  name: "reviewer",
  description: "Review agent for code and design review",
  model: {
    provider: "anthropic",
    name: "claude-3-sonnet-20240229"
  },
  instructions: `You are a review agent responsible for:
    - Conducting thorough code reviews
    - Ensuring adherence to standards
    - Identifying potential improvements
    - Providing constructive feedback
    - Validating architectural decisions`,
  tools: []
});
const monitorAgent = new Agent({
  name: "monitor",
  description: "Monitoring agent for system observation",
  model: {
    provider: "openai",
    name: "gpt-3.5-turbo"
  },
  instructions: `You are a monitoring agent tasked with:
    - Observing system performance
    - Tracking agent activities
    - Identifying anomalies
    - Generating alerts and reports
    - Ensuring system health`,
  tools: []
});
const coordinatorMastraAgent = new Agent({
  name: "coordinator",
  description: "Coordinator agent for team management and task delegation",
  model: {
    provider: "anthropic",
    name: "claude-3-sonnet-20240229"
  },
  instructions: `You are a coordinator agent responsible for:
    - Forming teams of agents for complex goals
    - Breaking down complex goals into manageable sub-goals
    - Delegating tasks to appropriate agents or teams
    - Monitoring team performance and adjusting strategies
    - Resolving conflicts between agents`,
  tools: []
});
const executorMastraAgent = new Agent({
  name: "executor",
  description: "Executor agent for task execution and implementation",
  model: {
    provider: "anthropic",
    name: "claude-3-sonnet-20240229"
  },
  instructions: `You are an executor agent responsible for:
    - Executing assigned tasks
    - Implementing solutions based on specifications
    - Reporting progress and results
    - Handling errors and retries
    - Collaborating with other agents`,
  tools: []
});
const mastraAgents = {
  coordinator: coordinatorMastraAgent,
  executor: executorMastraAgent,
  researcher: researcherAgent,
  architect: architectAgent,
  coder: coderAgent,
  tester: testerAgent,
  reviewer: reviewerAgent,
  monitor: monitorAgent
};

class Logger {
  winston;
  constructor(context) {
    this.winston = winston.createLogger({
      level: process.env.LOG_LEVEL || "info",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: { context },
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        })
      ]
    });
  }
  debug(message, meta) {
    this.winston.debug(message, meta);
  }
  info(message, meta) {
    this.winston.info(message, meta);
  }
  warn(message, meta) {
    this.winston.warn(message, meta);
  }
  error(message, error, meta) {
    this.winston.error(message, { error, ...meta });
  }
}

class MessageRouter {
  logger;
  agents;
  topics;
  routingRules;
  constructor() {
    this.logger = new Logger("MessageRouter");
    this.agents = /* @__PURE__ */ new Map();
    this.topics = /* @__PURE__ */ new Map();
    this.routingRules = [];
    this.initializeDefaultRules();
  }
  /**
   * Initialize default routing rules
   */
  initializeDefaultRules() {
    this.addRule({
      name: "broadcast",
      condition: (message) => Array.isArray(message.to) && message.to.length === 0,
      route: (message) => Array.from(this.agents.values()).filter(
        (agent) => this.getAgentKey(agent) !== this.getAgentKey(message.from)
      )
    });
    this.addRule({
      name: "direct",
      condition: (message) => !Array.isArray(message.to) && message.to !== null,
      route: (message) => [message.to]
    });
    this.addRule({
      name: "multicast",
      condition: (message) => Array.isArray(message.to) && message.to.length > 0,
      route: (message) => message.to
    });
  }
  /**
   * Register an agent
   */
  registerAgent(agentId) {
    const key = this.getAgentKey(agentId);
    this.agents.set(key, agentId);
    this.logger.debug("Agent registered with router", { agentId: key });
  }
  /**
   * Unregister an agent
   */
  unregisterAgent(agentId) {
    const key = this.getAgentKey(agentId);
    this.agents.delete(key);
    this.topics.forEach((subscribers, topic) => {
      subscribers.delete(key);
    });
    this.logger.debug("Agent unregistered from router", { agentId: key });
  }
  /**
   * Subscribe an agent to a topic
   */
  subscribeTopic(agentId, topic) {
    const key = this.getAgentKey(agentId);
    if (!this.topics.has(topic)) {
      this.topics.set(topic, /* @__PURE__ */ new Set());
    }
    this.topics.get(topic).add(key);
    this.logger.debug("Agent subscribed to topic", { agentId: key, topic });
  }
  /**
   * Unsubscribe an agent from a topic
   */
  unsubscribeTopic(agentId, topic) {
    const key = this.getAgentKey(agentId);
    const subscribers = this.topics.get(topic);
    if (subscribers) {
      subscribers.delete(key);
      if (subscribers.size === 0) {
        this.topics.delete(topic);
      }
    }
    this.logger.debug("Agent unsubscribed from topic", { agentId: key, topic });
  }
  /**
   * Route a message to recipients
   */
  async route(message) {
    try {
      for (const rule of this.routingRules) {
        if (rule.condition(message)) {
          const recipients = rule.route(message);
          const validRecipients = recipients.filter((recipient) => {
            const key = this.getAgentKey(recipient);
            return this.agents.has(key);
          });
          this.logger.debug("Message routed", {
            messageId: message.id,
            rule: rule.name,
            recipients: validRecipients.length
          });
          return validRecipients;
        }
      }
      if (message.content.topic) {
        const topicSubscribers = this.getTopicSubscribersInternal(message.content.topic);
        if (topicSubscribers.length > 0) {
          return topicSubscribers.filter(
            (agent) => this.getAgentKey(agent) !== this.getAgentKey(message.from)
          );
        }
      }
      this.logger.warn("No routing rule matched", { messageId: message.id });
      return [];
    } catch (error) {
      this.logger.error("Failed to route message", error);
      return [];
    }
  }
  /**
   * Add a custom routing rule
   */
  addRule(rule) {
    this.routingRules.push(rule);
    this.logger.info("Added routing rule", { name: rule.name });
  }
  /**
   * Remove a routing rule
   */
  removeRule(name) {
    const index = this.routingRules.findIndex((rule) => rule.name === name);
    if (index >= 0) {
      this.routingRules.splice(index, 1);
      this.logger.info("Removed routing rule", { name });
    }
  }
  /**
   * Get subscribers for a topic (internal)
   */
  getTopicSubscribersInternal(topic) {
    const subscribers = this.topics.get(topic);
    if (!subscribers) {
      return [];
    }
    return Array.from(subscribers).map((key) => this.agents.get(key)).filter(Boolean);
  }
  /**
   * Get agent key for consistent identification
   */
  getAgentKey(agentId) {
    return `${agentId.namespace || "default"}:${agentId.id}`;
  }
  /**
   * Get all registered agents
   */
  getRegisteredAgents() {
    return Array.from(this.agents.values());
  }
  /**
   * Get all topics
   */
  getTopics() {
    return Array.from(this.topics.keys());
  }
  /**
   * Get topic subscribers
   */
  getTopicSubscribers(topic) {
    const subscribers = this.topics.get(topic);
    if (!subscribers) {
      return [];
    }
    return Array.from(subscribers).map((key) => this.agents.get(key)).filter((agent) => agent !== void 0);
  }
}

class MessageQueue {
  agentId;
  logger;
  messages;
  maxSize;
  constructor(agentId, maxSize = 1e3) {
    this.agentId = agentId;
    this.logger = new Logger(`MessageQueue:${agentId.id}`);
    this.messages = new PriorityQueue$1(this.compareMessages);
    this.maxSize = maxSize;
  }
  /**
   * Add a message to the queue
   */
  enqueue(message) {
    if (this.messages.size() >= this.maxSize) {
      this.logger.warn("Queue is full, dropping oldest message");
      const allMessages = this.messages.toArray();
      allMessages.sort(this.compareMessages).reverse();
      allMessages.pop();
      this.messages.clear();
      allMessages.forEach((m) => this.messages.enqueue(m));
    }
    this.messages.enqueue(message);
    this.logger.debug("Message enqueued", { messageId: message.id });
  }
  /**
   * Get the next message without removing it
   */
  peek() {
    return this.messages.toArray();
  }
  /**
   * Remove and return the next message
   */
  dequeue() {
    return this.messages.dequeue();
  }
  /**
   * Remove and return all messages
   */
  dequeueAll() {
    const messages = [];
    while (!this.messages.isEmpty()) {
      const message = this.messages.dequeue();
      if (message) {
        messages.push(message);
      }
    }
    return messages;
  }
  /**
   * Get queue size
   */
  size() {
    return this.messages.size();
  }
  /**
   * Check if queue is empty
   */
  isEmpty() {
    return this.messages.isEmpty();
  }
  /**
   * Clear all messages
   */
  clear() {
    this.messages.clear();
    this.logger.debug("Queue cleared");
  }
  /**
   * Compare messages for priority ordering
   */
  compareMessages(a, b) {
    const priorityWeight = {
      [MessagePriority.URGENT]: 4,
      [MessagePriority.HIGH]: 3,
      [MessagePriority.NORMAL]: 2,
      [MessagePriority.LOW]: 1
    };
    const priorityDiff = priorityWeight[b.priority] - priorityWeight[a.priority];
    if (priorityDiff !== 0) return priorityDiff;
    return a.timestamp.getTime() - b.timestamp.getTime();
  }
  /**
   * Remove expired messages
   */
  removeExpired() {
    const now = Date.now();
    const messages = this.messages.toArray();
    const validMessages = messages.filter((message) => {
      if (message.ttl) {
        const expiryTime = message.timestamp.getTime() + message.ttl;
        return expiryTime > now;
      }
      return true;
    });
    const removedCount = messages.length - validMessages.length;
    if (removedCount > 0) {
      this.messages.clear();
      validMessages.forEach((m) => this.messages.enqueue(m));
      this.logger.info("Removed expired messages", { count: removedCount });
    }
    return removedCount;
  }
  /**
   * Get messages by type
   */
  getByType(type) {
    return this.messages.toArray().filter((m) => m.type === type);
  }
  /**
   * Get messages by priority
   */
  getByPriority(priority) {
    return this.messages.toArray().filter((m) => m.priority === priority);
  }
}
let PriorityQueue$1 = class PriorityQueue {
  items = [];
  compare;
  constructor(compareFunction) {
    this.compare = compareFunction;
  }
  enqueue(item) {
    this.items.push(item);
    this.items.sort(this.compare);
  }
  dequeue() {
    return this.items.shift();
  }
  peek() {
    return this.items[0];
  }
  isEmpty() {
    return this.items.length === 0;
  }
  size() {
    return this.items.length;
  }
  clear() {
    this.items = [];
  }
  toArray() {
    return [...this.items];
  }
};

class MessageBus extends EventEmitter {
  static instance;
  logger;
  router;
  queues;
  subscribers;
  messageHistory;
  maxHistorySize = 1e3;
  constructor() {
    super();
    this.logger = new Logger("MessageBus");
    this.router = new MessageRouter();
    this.queues = /* @__PURE__ */ new Map();
    this.subscribers = /* @__PURE__ */ new Map();
    this.messageHistory = [];
  }
  /**
   * Get singleton instance
   */
  static getInstance() {
    if (!MessageBus.instance) {
      MessageBus.instance = new MessageBus();
    }
    return MessageBus.instance;
  }
  /**
   * Register an agent with the message bus
   */
  async registerAgent(agentId) {
    const key = this.getAgentKey(agentId);
    if (this.queues.has(key)) {
      throw new Error(`Agent already registered: ${key}`);
    }
    const queue = new MessageQueue(agentId);
    this.queues.set(key, queue);
    this.router.registerAgent(agentId);
    this.logger.info("Agent registered", { agentId: key });
    this.emit("agent:registered", agentId);
  }
  /**
   * Unregister an agent from the message bus
   */
  async unregisterAgent(agentId) {
    const key = this.getAgentKey(agentId);
    const queue = this.queues.get(key);
    if (queue) {
      queue.clear();
      this.queues.delete(key);
    }
    this.subscribers.delete(key);
    this.router.unregisterAgent(agentId);
    this.logger.info("Agent unregistered", { agentId: key });
    this.emit("agent:unregistered", agentId);
  }
  /**
   * Subscribe to messages for an agent
   */
  subscribe(agentId, handler) {
    const key = this.getAgentKey(agentId);
    this.subscribers.set(key, handler);
    const queue = this.queues.get(key);
    if (queue) {
      this.processQueuedMessages(agentId, handler);
    }
  }
  /**
   * Unsubscribe from messages
   */
  unsubscribe(agentId) {
    const key = this.getAgentKey(agentId);
    this.subscribers.delete(key);
  }
  /**
   * Send a message
   */
  async send(message) {
    try {
      this.validateMessage(message);
      this.addToHistory(message);
      const recipients = await this.router.route(message);
      if (recipients.length === 0) {
        this.logger.warn("No recipients found for message", { messageId: message.id });
        this.emit("message:undelivered", message);
        return;
      }
      for (const recipient of recipients) {
        await this.deliverMessage(message, recipient);
      }
      this.logger.debug("Message sent", {
        messageId: message.id,
        recipientCount: recipients.length
      });
      this.emit("message:sent", message);
    } catch (error) {
      this.logger.error("Failed to send message", error);
      this.emit("message:error", { message, error });
      throw error;
    }
  }
  /**
   * Broadcast a message to all agents
   */
  async broadcast(from, type, content, priority = MessagePriority.NORMAL) {
    const message = {
      id: v4(),
      from,
      to: [],
      // Empty array indicates broadcast
      type,
      content,
      timestamp: /* @__PURE__ */ new Date(),
      priority
    };
    await this.send(message);
  }
  /**
   * Reply to a message
   */
  async reply(originalMessage, from, type, content, priority) {
    const replyMessage = {
      id: v4(),
      from,
      to: originalMessage.from,
      type,
      content,
      timestamp: /* @__PURE__ */ new Date(),
      replyTo: originalMessage.id,
      priority: priority || originalMessage.priority
    };
    await this.send(replyMessage);
    if (type === MessageType.RESPONSE) {
      this.emit(`response:${originalMessage.id}`, replyMessage);
    }
  }
  /**
   * Enhanced message delivery with coordination tracking
   */
  async deliverMessage(message, recipient) {
    const key = this.getAgentKey(recipient);
    const handler = this.subscribers.get(key);
    if (handler) {
      try {
        await handler(message);
        this.emit("message:delivered", { message, recipient });
        this.emit("message:delivered", message);
      } catch (error) {
        this.logger.error("Handler failed to process message", error);
        this.emit("message:handlerError", { message, recipient, error });
      }
    } else {
      const queue = this.queues.get(key);
      if (queue) {
        queue.enqueue(message);
        this.logger.debug("Message queued for offline agent", {
          messageId: message.id,
          agentId: key
        });
        this.emit("message:queued", { message, recipient });
      } else {
        this.logger.warn("No queue found for recipient", { agentId: key });
        this.emit("message:undeliverable", { message, recipient });
      }
    }
  }
  /**
   * Process queued messages for an agent
   */
  async processQueuedMessages(agentId, handler) {
    const key = this.getAgentKey(agentId);
    const queue = this.queues.get(key);
    if (!queue) return;
    const messages = queue.dequeueAll();
    this.logger.info("Processing queued messages", {
      agentId: key,
      count: messages.length
    });
    for (const message of messages) {
      try {
        await handler(message);
        this.emit("message:delivered", { message, recipient: agentId });
      } catch (error) {
        this.logger.error("Failed to process queued message", error);
        this.emit("message:handlerError", { message, recipient: agentId, error });
      }
    }
  }
  /**
   * Validate message
   */
  validateMessage(message) {
    if (!message.id) {
      throw new Error("Message must have an ID");
    }
    if (!message.from) {
      throw new Error("Message must have a sender");
    }
    if (!message.type) {
      throw new Error("Message must have a type");
    }
    if (!message.content) {
      throw new Error("Message must have content");
    }
  }
  /**
   * Add message to history
   */
  addToHistory(message) {
    this.messageHistory.push(message);
    if (this.messageHistory.length > this.maxHistorySize) {
      this.messageHistory.shift();
    }
  }
  /**
   * Get message history
   */
  getHistory(filter) {
    let history = [...this.messageHistory];
    if (filter) {
      if (filter.from) {
        const fromKey = this.getAgentKey(filter.from);
        history = history.filter((m) => this.getAgentKey(m.from) === fromKey);
      }
      if (filter.to) {
        const toKey = this.getAgentKey(filter.to);
        history = history.filter((m) => {
          if (Array.isArray(m.to)) {
            return m.to.some((t) => this.getAgentKey(t) === toKey);
          }
          return this.getAgentKey(m.to) === toKey;
        });
      }
      if (filter.type) {
        history = history.filter((m) => m.type === filter.type);
      }
      if (filter.since) {
        history = history.filter((m) => m.timestamp >= filter.since);
      }
    }
    return history;
  }
  /**
   * Get agent key for consistent identification
   */
  getAgentKey(agentId) {
    return `${agentId.namespace || "default"}:${agentId.id}`;
  }
  /**
   * Get queue status for an agent
   */
  getQueueStatus(agentId) {
    const key = this.getAgentKey(agentId);
    const queue = this.queues.get(key);
    if (!queue) {
      return { size: 0, messages: [] };
    }
    return {
      size: queue.size(),
      messages: queue.peek()
    };
  }
  /**
   * Clear all messages for an agent
   */
  clearAgentMessages(agentId) {
    const key = this.getAgentKey(agentId);
    const queue = this.queues.get(key);
    if (queue) {
      queue.clear();
    }
  }
  /**
   * Get registered agents
   */
  getRegisteredAgents() {
    return this.router.getRegisteredAgents();
  }
  // ========================
  // ENHANCED COORDINATION FEATURES
  // ========================
  /**
   * Send request and wait for response
   */
  async sendAndWaitForResponse(message, timeoutMs = 3e4) {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.removeListener(`response:${message.id}`, responseHandler);
        reject(new Error(`Response timeout for message ${message.id}`));
      }, timeoutMs);
      const responseHandler = (response) => {
        clearTimeout(timeoutId);
        resolve(response);
      };
      this.once(`response:${message.id}`, responseHandler);
      this.send(message).catch((error) => {
        clearTimeout(timeoutId);
        this.removeListener(`response:${message.id}`, responseHandler);
        reject(error);
      });
    });
  }
  /**
   * Coordinate synchronous message exchange between agents
   */
  async coordinatedExchange(initiator, participants, topic, data, timeoutMs = 6e4) {
    const exchangeId = v4();
    const responses = /* @__PURE__ */ new Map();
    const pendingResponses = new Set(participants.map((p) => this.getAgentKey(p)));
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error(`Coordinated exchange timeout: ${exchangeId}`));
      }, timeoutMs);
      const responseHandler = (message) => {
        if (message.content.topic === `${topic}:response` && message.content.body.exchangeId === exchangeId) {
          const senderKey = this.getAgentKey(message.from);
          responses.set(senderKey, message.content.body);
          pendingResponses.delete(senderKey);
          if (pendingResponses.size === 0) {
            clearTimeout(timeoutId);
            this.removeListener("message:delivered", responseHandler);
            resolve(responses);
          }
        }
      };
      this.on("message:delivered", responseHandler);
      const coordinationMessage = {
        id: v4(),
        from: initiator,
        to: participants,
        type: MessageType.REQUEST,
        content: {
          topic,
          body: {
            exchangeId,
            data,
            requiredResponse: true,
            deadline: new Date(Date.now() + timeoutMs)
          }
        },
        timestamp: /* @__PURE__ */ new Date(),
        priority: MessagePriority.HIGH
      };
      this.send(coordinationMessage).catch((error) => {
        clearTimeout(timeoutId);
        this.removeListener("message:delivered", responseHandler);
        reject(error);
      });
    });
  }
  /**
   * Implement barrier synchronization for coordinated actions
   */
  async barrierSync(participants, barrierName, timeoutMs = 3e4) {
    const barrierId = `${barrierName}_${Date.now()}`;
    const arrivedAgents = /* @__PURE__ */ new Set();
    const requiredCount = participants.length;
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error(`Barrier synchronization timeout: ${barrierId}`));
      }, timeoutMs);
      const arrivalHandler = (message) => {
        if (message.content.topic === "barrier:arrival" && message.content.body.barrierId === barrierId) {
          const agentKey = this.getAgentKey(message.from);
          arrivedAgents.add(agentKey);
          this.logger.debug("Agent arrived at barrier", {
            agentKey,
            barrierId,
            arrived: arrivedAgents.size,
            required: requiredCount
          });
          if (arrivedAgents.size === requiredCount) {
            clearTimeout(timeoutId);
            this.removeListener("message:delivered", arrivalHandler);
            this.broadcast(
              { id: "barrier_coordinator", namespace: "system" },
              MessageType.INFORM,
              {
                topic: "barrier:released",
                body: { barrierId, participants: Array.from(arrivedAgents) }
              },
              MessagePriority.HIGH
            );
            resolve();
          }
        }
      };
      this.on("message:delivered", arrivalHandler);
      const barrierMessage = {
        id: v4(),
        from: { id: "barrier_coordinator", namespace: "system" },
        to: participants,
        type: MessageType.INFORM,
        content: {
          topic: "barrier:setup",
          body: {
            barrierId,
            participants: participants.map((p) => this.getAgentKey(p)),
            deadline: new Date(Date.now() + timeoutMs)
          }
        },
        timestamp: /* @__PURE__ */ new Date(),
        priority: MessagePriority.HIGH
      };
      this.send(barrierMessage).catch((error) => {
        clearTimeout(timeoutId);
        this.removeListener("message:delivered", arrivalHandler);
        reject(error);
      });
    });
  }
  /**
   * Implement consensus mechanism for distributed decision making
   */
  async reachConsensus(participants, proposal, consensusThreshold = 0.67, timeoutMs = 6e4) {
    const consensusId = v4();
    const votes = /* @__PURE__ */ new Map();
    const responses = /* @__PURE__ */ new Map();
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        const success = this.evaluateConsensus(votes, consensusThreshold);
        resolve({ success: false, votes, consensus: success ? proposal : void 0 });
      }, timeoutMs);
      const voteHandler = (message) => {
        if (message.content.topic === "consensus:vote" && message.content.body.consensusId === consensusId) {
          const agentKey = this.getAgentKey(message.from);
          const vote = message.content.body.vote;
          const response = message.content.body.response;
          votes.set(agentKey, vote);
          responses.set(agentKey, response);
          this.logger.debug("Vote received", {
            agentKey,
            vote,
            consensusId,
            totalVotes: votes.size,
            required: participants.length
          });
          if (votes.size === participants.length) {
            clearTimeout(timeoutId);
            this.removeListener("message:delivered", voteHandler);
            const success = this.evaluateConsensus(votes, consensusThreshold);
            const consensus = success ? this.mergeConsensusResponses(responses) : void 0;
            this.broadcast(
              { id: "consensus_coordinator", namespace: "system" },
              MessageType.INFORM,
              {
                topic: "consensus:result",
                body: {
                  consensusId,
                  success,
                  votes: Object.fromEntries(votes),
                  consensus
                }
              },
              MessagePriority.HIGH
            );
            resolve({ success, votes, consensus });
          }
        }
      };
      this.on("message:delivered", voteHandler);
      const proposalMessage = {
        id: v4(),
        from: { id: "consensus_coordinator", namespace: "system" },
        to: participants,
        type: MessageType.REQUEST,
        content: {
          topic: "consensus:proposal",
          body: {
            consensusId,
            proposal,
            threshold: consensusThreshold,
            deadline: new Date(Date.now() + timeoutMs)
          }
        },
        timestamp: /* @__PURE__ */ new Date(),
        priority: MessagePriority.HIGH
      };
      this.send(proposalMessage).catch((error) => {
        clearTimeout(timeoutId);
        this.removeListener("message:delivered", voteHandler);
        reject(error);
      });
    });
  }
  /**
   * Pipeline coordination for sequential task execution
   */
  async coordinatePipeline(stages, initialData, timeoutMs = 12e4) {
    let currentData = initialData;
    for (let i = 0; i < stages.length; i++) {
      const stage = stages[i];
      const stageId = v4();
      try {
        const stageMessage = {
          id: v4(),
          from: { id: "pipeline_coordinator", namespace: "system" },
          to: stage.agentId,
          type: MessageType.COMMAND,
          content: {
            topic: "pipeline:stage",
            body: {
              stageId,
              stageNumber: i + 1,
              totalStages: stages.length,
              task: stage.task,
              inputData: currentData,
              deadline: new Date(Date.now() + timeoutMs / stages.length)
            }
          },
          timestamp: /* @__PURE__ */ new Date(),
          priority: MessagePriority.HIGH
        };
        const response = await this.sendAndWaitForResponse(stageMessage, timeoutMs / stages.length);
        currentData = response.content.body.outputData;
        this.logger.info("Pipeline stage completed", {
          stageId,
          stageNumber: i + 1,
          agentId: this.getAgentKey(stage.agentId)
        });
      } catch (error) {
        this.logger.error("Pipeline stage failed", {
          stageNumber: i + 1,
          agentId: this.getAgentKey(stage.agentId),
          error
        });
        throw new Error(`Pipeline failed at stage ${i + 1}: ${error}`);
      }
    }
    return currentData;
  }
  /**
   * Monitor message flow and detect coordination issues
   */
  getCoordinationMetrics() {
    const now = Date.now();
    const recentMessages = this.messageHistory.filter(
      (m) => now - m.timestamp.getTime() < 6e4
      // Last minute
    );
    const responseMessages = recentMessages.filter((m) => m.replyTo);
    const averageResponseTime = responseMessages.length > 0 ? responseMessages.reduce((sum, m) => {
      const original = this.messageHistory.find((orig) => orig.id === m.replyTo);
      return sum + (original ? m.timestamp.getTime() - original.timestamp.getTime() : 0);
    }, 0) / responseMessages.length : 0;
    const queueSizes = /* @__PURE__ */ new Map();
    for (const [key, queue] of this.queues) {
      queueSizes.set(key, queue.size());
    }
    return {
      messageCount: recentMessages.length,
      averageResponseTime,
      failureRate: 0,
      // Would track actual failures
      activeAgents: this.router.getRegisteredAgents().length,
      queueSizes
    };
  }
  /**
   * Utility methods for consensus and coordination
   */
  evaluateConsensus(votes, threshold) {
    if (votes.size === 0) return false;
    const positiveVotes = Array.from(votes.values()).filter((v) => v).length;
    return positiveVotes / votes.size >= threshold;
  }
  mergeConsensusResponses(responses) {
    const allResponses = Array.from(responses.values());
    if (allResponses.length === 0) return null;
    const responseCount = /* @__PURE__ */ new Map();
    allResponses.forEach((response) => {
      const key = JSON.stringify(response);
      responseCount.set(key, (responseCount.get(key) || 0) + 1);
    });
    let maxCount = 0;
    let consensusResponse = null;
    for (const [responseKey, count] of responseCount) {
      if (count > maxCount) {
        maxCount = count;
        consensusResponse = JSON.parse(responseKey);
      }
    }
    return consensusResponse;
  }
}

class GoalEngine extends EventEmitter {
  agentId;
  logger;
  goals;
  goalDependencies;
  tokenizer;
  classifier;
  goalQueue;
  constructor(agentId) {
    super();
    this.agentId = agentId;
    this.logger = new Logger(`GoalEngine:${agentId.id}`);
    this.goals = /* @__PURE__ */ new Map();
    this.goalDependencies = /* @__PURE__ */ new Map();
    this.tokenizer = new natural.WordTokenizer();
    this.classifier = new natural.BayesClassifier();
    this.goalQueue = new PriorityQueue(this.compareGoals);
    this.initializeClassifier();
  }
  /**
   * Initialize the NLP classifier with training data
   */
  initializeClassifier() {
    this.classifier.addDocument("achieve complete finish accomplish", GoalType.ACHIEVE);
    this.classifier.addDocument("maintain keep preserve sustain", GoalType.MAINTAIN);
    this.classifier.addDocument("query find search discover what how why", GoalType.QUERY);
    this.classifier.addDocument("perform execute run do action", GoalType.PERFORM);
    this.classifier.addDocument("prevent avoid stop block prohibit", GoalType.PREVENT);
    this.classifier.train();
  }
  /**
   * Parse natural language input into a Goal
   */
  async parseGoal(input, context) {
    try {
      this.logger.debug("Parsing goal from input", { input });
      const intent = await this.extractIntent(input);
      const entities = await this.extractEntities(input);
      const goalType = this.classifier.classify(input);
      const priority = this.extractPriority(input);
      const deadline = this.extractDeadline(input);
      const goal = {
        id: v4(),
        description: input,
        type: goalType,
        priority,
        status: GoalStatus.PENDING,
        dependencies: [],
        constraints: this.extractConstraints(input, entities),
        deadline,
        metadata: {
          nlpIntent: intent,
          entities,
          context,
          createdAt: /* @__PURE__ */ new Date()
        }
      };
      this.logger.info("Parsed goal successfully", { goalId: goal.id, type: goalType });
      return goal;
    } catch (error) {
      this.logger.error("Failed to parse goal", error);
      throw error;
    }
  }
  /**
   * Extract intent from natural language input
   */
  async extractIntent(input) {
    const doc = nlp(input);
    const verbs = doc.verbs().out("array");
    const intent = verbs[0] || "unknown";
    const confidence = this.calculateConfidence(input);
    const entities = [];
    doc.people().forEach((term) => {
      entities.push({
        type: "person",
        value: term.text(),
        confidence: 0.9,
        position: [term.offset, term.offset + term.length]
      });
    });
    doc.places().forEach((term) => {
      entities.push({
        type: "place",
        value: term.text(),
        confidence: 0.9,
        position: [term.offset, term.offset + term.length]
      });
    });
    const terms = doc.terms().out("array");
    terms.forEach((term, index) => {
      if (/\d{1,2}[/-]\d{1,2}[/-]\d{2,4}/.test(term)) {
        entities.push({
          type: "date",
          value: term,
          confidence: 0.9,
          position: [index * 10, (index + 1) * 10]
        });
      }
    });
    return {
      intent,
      confidence,
      entities
    };
  }
  /**
   * Extract entities from input
   */
  async extractEntities(input) {
    const doc = nlp(input);
    const entities = [];
    doc.nouns().forEach((noun) => {
      entities.push({
        type: "object",
        value: noun.text(),
        confidence: 0.8,
        position: [noun.offset, noun.offset + noun.length]
      });
    });
    const docTerms = doc.terms().out("array");
    docTerms.forEach((term, index) => {
      if (/^\d+$/.test(term)) {
        entities.push({
          type: "number",
          value: term,
          confidence: 0.95,
          position: [index * 10, (index + 1) * 10]
        });
      }
    });
    return entities;
  }
  /**
   * Extract priority from input
   */
  extractPriority(input) {
    const lowercased = input.toLowerCase();
    if (lowercased.includes("urgent") || lowercased.includes("critical") || lowercased.includes("asap")) {
      return GoalPriority.CRITICAL;
    } else if (lowercased.includes("high priority") || lowercased.includes("important")) {
      return GoalPriority.HIGH;
    } else if (lowercased.includes("low priority") || lowercased.includes("when possible")) {
      return GoalPriority.LOW;
    }
    return GoalPriority.MEDIUM;
  }
  /**
   * Extract deadline from input
   */
  extractDeadline(input) {
    const dateRegex = /\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b/;
    const match = input.match(dateRegex);
    if (match) {
      const parsed = new Date(match[0]);
      if (!isNaN(parsed.getTime())) {
        return parsed;
      }
    }
    return void 0;
  }
  /**
   * Extract constraints from input and entities
   */
  extractConstraints(input, entities) {
    const constraints = [];
    if (input.includes("within") || input.includes("before")) {
      const timeEntity = entities.find((e) => e.type === "date" || e.type === "number");
      if (timeEntity) {
        constraints.push({
          type: "time",
          value: timeEntity.value,
          description: "Time constraint"
        });
      }
    }
    if (input.includes("using") || input.includes("with")) {
      const resourceEntities = entities.filter((e) => e.type === "object");
      resourceEntities.forEach((entity) => {
        constraints.push({
          type: "resource",
          value: entity.value,
          description: "Required resource"
        });
      });
    }
    return constraints;
  }
  /**
   * Calculate confidence score for intent extraction
   */
  calculateConfidence(input) {
    const tokens = this.tokenizer.tokenize(input) || [];
    const sentenceLength = tokens.length;
    if (sentenceLength < 3) return 0.3;
    if (sentenceLength < 5) return 0.5;
    if (sentenceLength < 10) return 0.7;
    return 0.9;
  }
  /**
   * Add a goal to the engine
   */
  async addGoal(goal) {
    try {
      this.logger.info("Adding goal to engine", { goalId: goal.id });
      this.goals.set(goal.id, goal);
      if (goal.dependencies.length > 0) {
        this.goalDependencies.set(goal.id, new Set(goal.dependencies));
      }
      if (this.isGoalReady(goal)) {
        this.goalQueue.enqueue(goal);
      }
      this.emit("goal:added", goal);
    } catch (error) {
      this.logger.error("Failed to add goal", error);
      throw error;
    }
  }
  /**
   * Update goal status
   */
  async updateGoalStatus(goalId, status) {
    const goal = this.goals.get(goalId);
    if (!goal) {
      throw new Error(`Goal not found: ${goalId}`);
    }
    const previousStatus = goal.status;
    goal.status = status;
    this.logger.info("Updated goal status", { goalId, previousStatus, newStatus: status });
    if (status === GoalStatus.COMPLETED || status === GoalStatus.FAILED) {
      this.checkDependentGoals(goalId);
    }
    this.emit("goal:statusChanged", { goal, previousStatus, newStatus: status });
  }
  /**
   * Get next goal to process
   */
  getNextGoal() {
    while (!this.goalQueue.isEmpty()) {
      const goal = this.goalQueue.dequeue();
      if (goal && this.isGoalReady(goal)) {
        return goal;
      }
    }
    return void 0;
  }
  /**
   * Decompose a goal into sub-goals
   */
  async decomposeGoal(goal) {
    try {
      this.logger.debug("Decomposing goal", { goalId: goal.id });
      const subGoals = [];
      const doc = nlp(goal.description);
      const clauses = doc.clauses().out("array");
      if (clauses.length > 1) {
        for (const clause of clauses) {
          const subGoal = await this.parseGoal(clause, goal.metadata);
          subGoal.dependencies = [goal.id];
          subGoals.push(subGoal);
        }
      } else {
        const steps = this.identifySteps(goal.description);
        for (const step of steps) {
          const subGoal = await this.parseGoal(step, goal.metadata);
          subGoal.dependencies = [goal.id];
          subGoals.push(subGoal);
        }
      }
      goal.subGoals = subGoals;
      this.logger.info("Decomposed goal into sub-goals", { goalId: goal.id, count: subGoals.length });
      return subGoals;
    } catch (error) {
      this.logger.error("Failed to decompose goal", error);
      return [];
    }
  }
  /**
   * Convert a goal to executable tasks
   */
  async goalToTasks(goal) {
    try {
      this.logger.debug("Converting goal to tasks", { goalId: goal.id });
      const tasks = [];
      if (goal.subGoals && goal.subGoals.length > 0) {
        for (const subGoal of goal.subGoals) {
          const subTasks = await this.goalToTasks(subGoal);
          tasks.push(...subTasks);
        }
      } else {
        const task = {
          id: v4(),
          goalId: goal.id,
          assignedTo: this.agentId,
          description: goal.description,
          status: TaskStatus.PENDING
        };
        tasks.push(task);
      }
      this.logger.info("Converted goal to tasks", { goalId: goal.id, taskCount: tasks.length });
      return tasks;
    } catch (error) {
      this.logger.error("Failed to convert goal to tasks", error);
      return [];
    }
  }
  /**
   * Check if a goal is ready to be processed
   */
  isGoalReady(goal) {
    if (goal.status !== GoalStatus.PENDING) {
      return false;
    }
    for (const depId of goal.dependencies) {
      const depGoal = this.goals.get(depId);
      if (!depGoal || depGoal.status !== GoalStatus.COMPLETED) {
        return false;
      }
    }
    return true;
  }
  /**
   * Check and activate dependent goals
   */
  checkDependentGoals(completedGoalId) {
    for (const [goalId, deps] of this.goalDependencies) {
      if (deps.has(completedGoalId)) {
        const goal = this.goals.get(goalId);
        if (goal && this.isGoalReady(goal)) {
          this.goalQueue.enqueue(goal);
          this.emit("goal:ready", goal);
        }
      }
    }
  }
  /**
   * Identify steps in a goal description
   */
  identifySteps(description) {
    const steps = [];
    const numberedSteps = description.match(/\d+\.\s+[^.]+/g);
    if (numberedSteps) {
      return numberedSteps.map((step) => step.replace(/^\d+\.\s+/, ""));
    }
    const sequenceWords = ["first", "then", "next", "after", "finally"];
    const doc = nlp(description);
    const sentences = doc.sentences().out("array");
    for (const sentence of sentences) {
      const hasSequence = sequenceWords.some(
        (word) => sentence.toLowerCase().includes(word)
      );
      if (hasSequence) {
        steps.push(sentence);
      }
    }
    return steps.length > 0 ? steps : [description];
  }
  /**
   * Compare goals for priority queue
   */
  compareGoals(a, b) {
    const priorityWeight = {
      [GoalPriority.CRITICAL]: 4,
      [GoalPriority.HIGH]: 3,
      [GoalPriority.MEDIUM]: 2,
      [GoalPriority.LOW]: 1
    };
    const priorityDiff = priorityWeight[b.priority] - priorityWeight[a.priority];
    if (priorityDiff !== 0) return priorityDiff;
    if (a.deadline && b.deadline) {
      return a.deadline.getTime() - b.deadline.getTime();
    } else if (a.deadline) {
      return -1;
    } else if (b.deadline) {
      return 1;
    }
    return 0;
  }
  /**
   * Get all goals
   */
  getAllGoals() {
    return Array.from(this.goals.values());
  }
  /**
   * Get goals by status
   */
  getGoalsByStatus(status) {
    return Array.from(this.goals.values()).filter((goal) => goal.status === status);
  }
  /**
   * Clear all goals
   */
  clearGoals() {
    this.goals.clear();
    this.goalDependencies.clear();
    this.goalQueue.clear();
    this.emit("goals:cleared");
  }
}
class PriorityQueue {
  items = [];
  compare;
  constructor(compareFunction) {
    this.compare = compareFunction;
  }
  enqueue(item) {
    this.items.push(item);
    this.items.sort(this.compare);
  }
  dequeue() {
    return this.items.shift();
  }
  isEmpty() {
    return this.items.length === 0;
  }
  size() {
    return this.items.length;
  }
  clear() {
    this.items = [];
  }
}

class BaseAgent extends EventEmitter {
  id;
  logger;
  profile;
  config;
  hooks;
  messageBus;
  goalEngine;
  activeTasks;
  messageHandlers;
  constructor(name, type, config = {}, hooks = {}) {
    super();
    this.id = {
      id: v4(),
      namespace: "default"
    };
    this.logger = new Logger(`Agent:${name}`);
    this.config = this.mergeConfig(config);
    this.hooks = hooks;
    this.activeTasks = /* @__PURE__ */ new Map();
    this.messageHandlers = /* @__PURE__ */ new Map();
    this.profile = this.createProfile(name, type);
    this.messageBus = MessageBus.getInstance();
    this.goalEngine = new GoalEngine(this.id);
    this.setupMessageHandlers();
    this.setupEventListeners();
  }
  /**
   * Create the agent's profile
   */
  createProfile(name, type) {
    const now = /* @__PURE__ */ new Date();
    return {
      id: this.id,
      name,
      type,
      capabilities: this.defineCapabilities(),
      goals: [],
      state: AgentState.IDLE,
      metadata: {
        createdAt: now,
        updatedAt: now,
        version: "1.0.0",
        tags: [],
        performance: {
          tasksCompleted: 0,
          successRate: 0,
          averageResponseTime: 0,
          resourceUtilization: 0,
          communicationEfficiency: 0
        }
      }
    };
  }
  /**
   * Initialize the agent
   */
  async initialize() {
    try {
      this.logger.info("Initializing agent...", { id: this.id });
      await this.messageBus.registerAgent(this.id);
      if (this.hooks.onInit) {
        await this.hooks.onInit();
      }
      this.updateState(AgentState.IDLE);
      this.emit("initialized", this.profile);
      this.logger.info("Agent initialized successfully", { id: this.id });
    } catch (error) {
      this.logger.error("Failed to initialize agent", error);
      this.updateState(AgentState.ERROR);
      throw error;
    }
  }
  /**
   * Start the agent
   */
  async start() {
    try {
      this.logger.info("Starting agent...", { id: this.id });
      this.messageBus.subscribe(this.id, this.handleMessage.bind(this));
      if (this.hooks.onStart) {
        await this.hooks.onStart();
      }
      this.updateState(AgentState.IDLE);
      this.emit("started", this.profile);
      this.logger.info("Agent started successfully", { id: this.id });
    } catch (error) {
      this.logger.error("Failed to start agent", error);
      this.updateState(AgentState.ERROR);
      throw error;
    }
  }
  /**
   * Stop the agent
   */
  async stop() {
    try {
      this.logger.info("Stopping agent...", { id: this.id });
      for (const [, task] of this.activeTasks) {
        task.status = TaskStatus.CANCELLED;
        this.emit("task:cancelled", task);
      }
      this.activeTasks.clear();
      this.messageBus.unsubscribe(this.id);
      if (this.hooks.onStop) {
        await this.hooks.onStop();
      }
      this.updateState(AgentState.TERMINATED);
      this.emit("stopped", this.profile);
      this.logger.info("Agent stopped successfully", { id: this.id });
    } catch (error) {
      this.logger.error("Failed to stop agent", error);
      throw error;
    }
  }
  /**
   * Add a new goal to the agent
   */
  async addGoal(goal) {
    try {
      this.logger.info("Adding new goal", { goalId: goal.id });
      await this.goalEngine.addGoal(goal);
      this.profile.goals.push(goal);
      if (this.hooks.onGoalReceived) {
        await this.hooks.onGoalReceived(goal);
      }
      this.updateState(AgentState.THINKING);
      await this.processGoal(goal);
      this.emit("goal:added", goal);
    } catch (error) {
      this.logger.error("Failed to add goal", error);
      throw error;
    }
  }
  /**
   * Send a message to another agent or broadcast
   */
  async sendMessage(to, type, content, priority = MessagePriority.NORMAL) {
    const message = {
      id: v4(),
      from: this.id,
      to,
      type,
      content,
      timestamp: /* @__PURE__ */ new Date(),
      priority
    };
    this.updateState(AgentState.COMMUNICATING);
    await this.messageBus.send(message);
    this.updateState(AgentState.IDLE);
    this.emit("message:sent", message);
  }
  /**
   * Reply to a message
   */
  async reply(originalMessage, type, content, priority) {
    const replyMessage = {
      id: v4(),
      from: this.id,
      to: originalMessage.from,
      type,
      content,
      timestamp: /* @__PURE__ */ new Date(),
      replyTo: originalMessage.id,
      priority: priority || originalMessage.priority
    };
    await this.messageBus.send(replyMessage);
    this.emit("message:sent", replyMessage);
  }
  /**
   * Handle incoming messages
   */
  async handleMessage(message) {
    try {
      this.logger.debug("Received message", { messageId: message.id, type: message.type });
      if (this.hooks.onMessage) {
        await this.hooks.onMessage(message);
      }
      const handler = this.messageHandlers.get(message.type);
      if (handler) {
        await handler(message);
      } else {
        await this.handleUnknownMessage(message);
      }
      this.emit("message:received", message);
    } catch (error) {
      this.logger.error("Failed to handle message", error);
      this.emit("message:error", { message, error });
    }
  }
  /**
   * Handle unknown message types
   */
  async handleUnknownMessage(message) {
    this.logger.warn("Received unknown message type", { type: message.type });
  }
  /**
   * Register a message handler
   */
  registerMessageHandler(type, handler) {
    this.messageHandlers.set(type, handler);
  }
  /**
   * Update agent state
   */
  updateState(state) {
    const previousState = this.profile.state;
    this.profile.state = state;
    this.profile.metadata.updatedAt = /* @__PURE__ */ new Date();
    this.emit("state:changed", { previous: previousState, current: state });
  }
  /**
   * Update performance metrics
   */
  updatePerformanceMetrics(updates) {
    Object.assign(this.profile.metadata.performance, updates);
    this.emit("metrics:updated", this.profile.metadata.performance);
  }
  /**
   * Setup message handlers
   */
  setupMessageHandlers() {
    this.registerMessageHandler(MessageType.QUERY, async (message) => {
      await this.handleQueryMessage(message);
    });
    this.registerMessageHandler(MessageType.COMMAND, async (message) => {
      await this.handleCommandMessage(message);
    });
  }
  /**
   * Setup event listeners
   */
  setupEventListeners() {
    this.on("error", (error) => {
      this.logger.error("Agent error", error);
      if (this.hooks.onError) {
        this.hooks.onError(error).catch(
          (err) => this.logger.error("Error in error hook", err)
        );
      }
    });
  }
  /**
   * Handle query messages
   */
  async handleQueryMessage(message) {
    this.logger.debug("Handling query message", { content: message.content });
  }
  /**
   * Handle command messages
   */
  async handleCommandMessage(message) {
    this.logger.debug("Handling command message", { content: message.content });
  }
  /**
   * Merge configuration with defaults
   */
  mergeConfig(config) {
    return {
      maxConcurrentTasks: 5,
      communicationTimeout: 3e4,
      retryAttempts: 3,
      memoryLimit: 100 * 1024 * 1024,
      // 100MB
      learningRate: 0.01,
      ...config
    };
  }
  /**
   * Get agent profile
   */
  getProfile() {
    return { ...this.profile };
  }
  /**
   * Get agent ID
   */
  getId() {
    return { ...this.id };
  }
  /**
   * Get current state
   */
  getState() {
    return this.profile.state;
  }
  /**
   * Get active goals
   */
  getGoals() {
    return [...this.profile.goals];
  }
  /**
   * Get capabilities
   */
  getCapabilities() {
    return [...this.profile.capabilities];
  }
}

class TeamCoordinator extends EventEmitter {
  logger;
  messageBus;
  teams;
  agentTeams;
  // agentId -> teamId
  strategies;
  constructor() {
    super();
    this.logger = new Logger("TeamCoordinator");
    this.messageBus = MessageBus.getInstance();
    this.teams = /* @__PURE__ */ new Map();
    this.agentTeams = /* @__PURE__ */ new Map();
    this.strategies = /* @__PURE__ */ new Map();
    this.initializeStrategies();
  }
  /**
   * Initialize default coordination strategies
   */
  initializeStrategies() {
    this.registerStrategy({
      type: "hierarchical",
      parameters: { levels: 3 },
      evaluate: (context) => {
        const teamSize = context.team.members.length;
        const goalComplexity = context.currentGoals.reduce(
          (sum, g) => sum + (g.subGoals?.length || 1),
          0
        );
        return teamSize > 5 && goalComplexity > 10 ? 0.9 : 0.5;
      }
    });
    this.registerStrategy({
      type: "flat",
      parameters: { maxSize: 10 },
      evaluate: (context) => {
        const teamSize = context.team.members.length;
        const goalComplexity = context.currentGoals.reduce(
          (sum, g) => sum + (g.subGoals?.length || 1),
          0
        );
        return teamSize <= 5 && goalComplexity <= 5 ? 0.9 : 0.3;
      }
    });
    this.registerStrategy({
      type: "matrix",
      parameters: { dimensions: 2 },
      evaluate: (context) => {
        const uniqueCapabilities = /* @__PURE__ */ new Set();
        context.team.members.forEach((memberId) => {
          uniqueCapabilities.add("default");
        });
        return uniqueCapabilities.size > 3 ? 0.8 : 0.4;
      }
    });
    this.registerStrategy({
      type: "dynamic",
      parameters: { adaptationRate: 0.1 },
      evaluate: (context) => {
        return 0.7;
      }
    });
  }
  /**
   * Create a new team
   */
  async createTeam(name, leader, goals, formation = TeamFormation.DYNAMIC) {
    try {
      this.logger.info("Creating new team", { name, leader: leader.id });
      const team = {
        id: v4(),
        name,
        leader,
        members: [leader],
        goals,
        formation,
        status: TeamStatus.FORMING,
        createdAt: /* @__PURE__ */ new Date()
      };
      this.teams.set(team.id, team);
      this.agentTeams.set(this.getAgentKey(leader), team.id);
      await this.notifyTeamUpdate(team, "team:created");
      this.emit("team:created", team);
      return team;
    } catch (error) {
      this.logger.error("Failed to create team", error);
      throw error;
    }
  }
  /**
   * Add member to team
   */
  async addMember(teamId, agentId) {
    const team = this.teams.get(teamId);
    if (!team) {
      throw new Error(`Team not found: ${teamId}`);
    }
    const agentKey = this.getAgentKey(agentId);
    if (this.agentTeams.has(agentKey)) {
      throw new Error(`Agent already in team: ${agentKey}`);
    }
    team.members.push(agentId);
    this.agentTeams.set(agentKey, teamId);
    await this.notifyTeamUpdate(team, "member:added", { newMember: agentId });
    this.logger.info("Added member to team", { teamId, agentId: agentKey });
    this.emit("team:memberAdded", { team, member: agentId });
  }
  /**
   * Remove member from team
   */
  async removeMember(teamId, agentId) {
    const team = this.teams.get(teamId);
    if (!team) {
      throw new Error(`Team not found: ${teamId}`);
    }
    const agentKey = this.getAgentKey(agentId);
    team.members = team.members.filter(
      (m) => this.getAgentKey(m) !== agentKey
    );
    this.agentTeams.delete(agentKey);
    if (team.members.length === 0) {
      await this.disbandTeam(teamId);
      return;
    }
    if (this.getAgentKey(team.leader) === agentKey) {
      team.leader = team.members[0];
      await this.notifyTeamUpdate(team, "leader:changed", { newLeader: team.leader });
    }
    await this.notifyTeamUpdate(team, "member:removed", { removedMember: agentId });
    this.logger.info("Removed member from team", { teamId, agentId: agentKey });
    this.emit("team:memberRemoved", { team, member: agentId });
  }
  /**
   * Assign goal to team
   */
  async assignGoal(teamId, goal) {
    const team = this.teams.get(teamId);
    if (!team) {
      throw new Error(`Team not found: ${teamId}`);
    }
    team.goals.push(goal);
    if (team.status === TeamStatus.ACTIVE) {
      team.status = TeamStatus.EXECUTING;
    }
    await this.notifyTeamUpdate(team, "goal:assigned", { goal });
    await this.coordinateGoalExecution(team, goal);
    this.logger.info("Assigned goal to team", { teamId, goalId: goal.id });
    this.emit("team:goalAssigned", { team, goal });
  }
  /**
   * Coordinate goal execution within team
   */
  async coordinateGoalExecution(team, goal) {
    try {
      const strategy = this.selectStrategy(team, [goal]);
      this.logger.debug("Applying coordination strategy", {
        teamId: team.id,
        strategy: strategy.type
      });
      const taskAssignments = await this.decomposeAndAssign(team, goal, strategy);
      for (const [agentId, tasks] of taskAssignments) {
        await this.messageBus.send({
          id: v4(),
          from: team.leader,
          to: agentId,
          type: MessageType.COMMAND,
          content: {
            topic: "task:assignment",
            body: { tasks, goal, strategy: strategy.type }
          },
          timestamp: /* @__PURE__ */ new Date(),
          priority: MessagePriority.HIGH
        });
      }
      this.emit("coordination:executed", { team, goal, strategy });
    } catch (error) {
      this.logger.error("Failed to coordinate goal execution", error);
      throw error;
    }
  }
  /**
   * Decompose goal and assign tasks to team members using real coordination algorithms
   */
  async decomposeAndAssign(team, goal, strategy) {
    const agentCapabilities = await this.getTeamCapabilities(team);
    const subGoals = goal.subGoals || await this.intelligentGoalDecomposition(goal);
    switch (strategy.type) {
      case "hierarchical":
        return this.hierarchicalAssignment(team, subGoals, agentCapabilities);
      case "flat":
        return this.capabilityBasedAssignment(team, subGoals, agentCapabilities);
      case "matrix":
        return this.matrixAssignment(team, subGoals, agentCapabilities);
      case "dynamic":
        return this.dynamicAssignment(team, subGoals, agentCapabilities);
      default:
        return this.defaultAssignment(team, subGoals);
    }
  }
  /**
   * Get capabilities of all team members
   */
  async getTeamCapabilities(team) {
    const capabilities = /* @__PURE__ */ new Map();
    for (const member of team.members) {
      try {
        const response = await this.messageBus.sendAndWaitForResponse({
          id: v4(),
          from: team.leader,
          to: member,
          type: MessageType.REQUEST,
          content: {
            topic: "capability:query",
            body: { requestId: v4() }
          },
          timestamp: /* @__PURE__ */ new Date(),
          priority: MessagePriority.HIGH
        }, 5e3);
        const agentKey = this.getAgentKey(member);
        capabilities.set(agentKey, response.content.body.capabilities || []);
      } catch (error) {
        this.logger.warn("Failed to get agent capabilities", { member: this.getAgentKey(member), error });
        capabilities.set(this.getAgentKey(member), []);
      }
    }
    return capabilities;
  }
  /**
   * Intelligent goal decomposition
   */
  async intelligentGoalDecomposition(goal) {
    const decomposed = [];
    const complexityScore = this.analyzeGoalComplexity(goal);
    if (complexityScore > 0.7) {
      const phases = this.identifyGoalPhases(goal);
      phases.forEach((phase, index) => {
        decomposed.push({
          id: v4(),
          description: phase.description,
          type: goal.type,
          priority: goal.priority,
          status: GoalStatus.PENDING,
          dependencies: index > 0 ? [decomposed[index - 1].id] : [],
          constraints: phase.constraints || [],
          subGoals: [],
          metadata: {
            parentGoal: goal.id,
            phase: index + 1,
            totalPhases: phases.length
          }
        });
      });
    } else {
      const subTasks = this.identifyParallelTasks(goal);
      subTasks.forEach((task) => {
        decomposed.push({
          id: v4(),
          description: task.description,
          type: goal.type,
          priority: task.priority || goal.priority,
          status: GoalStatus.PENDING,
          dependencies: [],
          constraints: task.constraints || [],
          subGoals: [],
          metadata: {
            parentGoal: goal.id,
            taskType: task.type
          }
        });
      });
    }
    return decomposed.length > 0 ? decomposed : [goal];
  }
  /**
   * Hierarchical task assignment
   */
  async hierarchicalAssignment(team, subGoals, agentCapabilities) {
    const assignments = /* @__PURE__ */ new Map();
    const leaderKey = this.getAgentKey(team.leader);
    agentCapabilities.get(leaderKey) || [];
    const complexTasks = [];
    const simpleTasks = [];
    subGoals.forEach((goal) => {
      if (this.analyzeGoalComplexity(goal) > 0.6) {
        complexTasks.push(goal);
      } else {
        simpleTasks.push(goal);
      }
    });
    if (complexTasks.length > 0) {
      assignments.set(team.leader, complexTasks.map((task) => ({
        goalId: task.id,
        description: task.description,
        type: task.type,
        priority: task.priority,
        role: "coordinator"
      })));
    }
    const otherMembers = team.members.filter((m) => this.getAgentKey(m) !== leaderKey);
    this.distributeTasksByCapability(simpleTasks, otherMembers, agentCapabilities, assignments);
    return assignments;
  }
  /**
   * Capability-based assignment
   */
  async capabilityBasedAssignment(team, subGoals, agentCapabilities) {
    const assignments = /* @__PURE__ */ new Map();
    for (const goal of subGoals) {
      const requiredCapabilities = this.analyzeRequiredCapabilities(goal);
      const bestAgent = this.findBestAgentForTask(team.members, requiredCapabilities, agentCapabilities);
      if (!assignments.has(bestAgent)) {
        assignments.set(bestAgent, []);
      }
      assignments.get(bestAgent).push({
        goalId: goal.id,
        description: goal.description,
        type: goal.type,
        priority: goal.priority,
        requiredCapabilities,
        assignmentReason: "capability-match"
      });
    }
    return assignments;
  }
  /**
   * Matrix assignment for cross-functional collaboration
   */
  async matrixAssignment(team, subGoals, agentCapabilities) {
    const assignments = /* @__PURE__ */ new Map();
    const capabilityMatrix = this.createCapabilityMatrix(team.members, agentCapabilities);
    for (const goal of subGoals) {
      const requiredCapabilities = this.analyzeRequiredCapabilities(goal);
      if (requiredCapabilities.length > 1) {
        const collaborativeAssignment = this.createCollaborativeAssignment(
          goal,
          requiredCapabilities,
          capabilityMatrix
        );
        for (const [agentId, taskPart] of collaborativeAssignment) {
          if (!assignments.has(agentId)) {
            assignments.set(agentId, []);
          }
          assignments.get(agentId).push(taskPart);
        }
      } else {
        const bestAgent = this.findBestAgentForTask(team.members, requiredCapabilities, agentCapabilities);
        if (!assignments.has(bestAgent)) {
          assignments.set(bestAgent, []);
        }
        assignments.get(bestAgent).push({
          goalId: goal.id,
          description: goal.description,
          type: goal.type,
          priority: goal.priority,
          role: "primary"
        });
      }
    }
    return assignments;
  }
  /**
   * Dynamic assignment based on current workload and performance
   */
  async dynamicAssignment(team, subGoals, agentCapabilities) {
    const assignments = /* @__PURE__ */ new Map();
    const workloads = await this.getTeamWorkloads(team);
    const sortedGoals = subGoals.sort((a, b) => {
      const priorityWeight = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1
      };
      return priorityWeight[b.priority] - priorityWeight[a.priority];
    });
    for (const goal of sortedGoals) {
      const requiredCapabilities = this.analyzeRequiredCapabilities(goal);
      const candidateAgents = team.members.filter((agent) => {
        const agentKey = this.getAgentKey(agent);
        const capabilities = agentCapabilities.get(agentKey) || [];
        return this.hasRequiredCapabilities(capabilities, requiredCapabilities);
      });
      if (candidateAgents.length === 0) {
        const leastLoadedAgent = this.getLeastLoadedAgent(team.members, workloads);
        if (!assignments.has(leastLoadedAgent)) {
          assignments.set(leastLoadedAgent, []);
        }
        assignments.get(leastLoadedAgent).push({
          goalId: goal.id,
          description: goal.description,
          type: goal.type,
          priority: goal.priority,
          needsSupport: true,
          supportCapabilities: requiredCapabilities
        });
      } else {
        const bestAgent = this.getLeastLoadedAgent(candidateAgents, workloads);
        if (!assignments.has(bestAgent)) {
          assignments.set(bestAgent, []);
        }
        assignments.get(bestAgent).push({
          goalId: goal.id,
          description: goal.description,
          type: goal.type,
          priority: goal.priority,
          confidence: "high"
        });
        const agentKey = this.getAgentKey(bestAgent);
        workloads.set(agentKey, (workloads.get(agentKey) || 0) + this.estimateTaskLoad(goal));
      }
    }
    return assignments;
  }
  /**
   * Utility methods for assignment algorithms
   */
  analyzeGoalComplexity(goal) {
    let complexity = 0;
    const words = goal.description.toLowerCase().split(" ");
    const complexityIndicators = [
      "analyze",
      "research",
      "implement",
      "design",
      "create",
      "optimize",
      "integrate",
      "coordinate",
      "synthesize"
    ];
    complexity += words.filter(
      (word) => complexityIndicators.some((indicator) => word.includes(indicator))
    ).length * 0.1;
    complexity += (goal.constraints?.length || 0) * 0.05;
    complexity += (goal.subGoals?.length || 0) * 0.1;
    complexity += goal.dependencies.length * 0.05;
    return Math.min(complexity, 1);
  }
  identifyGoalPhases(goal) {
    const phases = [];
    const description = goal.description.toLowerCase();
    if (description.includes("research") || description.includes("analyze")) {
      phases.push({ description: `Research and analysis for: ${goal.description}` });
    }
    if (description.includes("design") || description.includes("plan")) {
      phases.push({ description: `Design and planning for: ${goal.description}` });
    }
    if (description.includes("implement") || description.includes("build") || description.includes("create")) {
      phases.push({ description: `Implementation of: ${goal.description}` });
    }
    if (description.includes("test") || description.includes("verify") || description.includes("validate")) {
      phases.push({ description: `Testing and validation for: ${goal.description}` });
    }
    return phases.length > 0 ? phases : [{ description: goal.description }];
  }
  identifyParallelTasks(goal) {
    const tasks = [];
    const description = goal.description.toLowerCase();
    if (description.includes("data") || description.includes("information")) {
      tasks.push({
        description: `Data collection and preparation for: ${goal.description}`,
        type: "data_task"
      });
    }
    if (description.includes("interface") || description.includes("ui") || description.includes("user")) {
      tasks.push({
        description: `User interface work for: ${goal.description}`,
        type: "ui_task"
      });
    }
    if (description.includes("backend") || description.includes("server") || description.includes("api")) {
      tasks.push({
        description: `Backend development for: ${goal.description}`,
        type: "backend_task"
      });
    }
    if (description.includes("documentation") || description.includes("docs")) {
      tasks.push({
        description: `Documentation for: ${goal.description}`,
        type: "documentation_task",
        priority: GoalPriority.LOW
      });
    }
    return tasks.length > 0 ? tasks : [{ description: goal.description }];
  }
  analyzeRequiredCapabilities(goal) {
    const capabilities = [];
    const description = goal.description.toLowerCase();
    const capabilityMap = {
      "research": ["research", "analysis"],
      "analyze": ["analysis", "data_processing"],
      "code": ["programming", "software_development"],
      "implement": ["programming", "implementation"],
      "design": ["design", "architecture"],
      "write": ["writing", "documentation"],
      "test": ["testing", "quality_assurance"],
      "coordinate": ["coordination", "project_management"],
      "ui": ["ui_design", "frontend_development"],
      "backend": ["backend_development", "server_management"],
      "data": ["data_processing", "database_management"]
    };
    for (const [keyword, caps] of Object.entries(capabilityMap)) {
      if (description.includes(keyword)) {
        capabilities.push(...caps);
      }
    }
    return [...new Set(capabilities)];
  }
  findBestAgentForTask(agents, requiredCapabilities, agentCapabilities) {
    if (requiredCapabilities.length === 0) {
      return agents[0];
    }
    let bestAgent = agents[0];
    let bestScore = -1;
    for (const agent of agents) {
      const agentKey = this.getAgentKey(agent);
      const capabilities = agentCapabilities.get(agentKey) || [];
      const matchingCapabilities = requiredCapabilities.filter(
        (req) => capabilities.some((cap) => cap.toLowerCase().includes(req.toLowerCase()))
      );
      const score = matchingCapabilities.length / requiredCapabilities.length;
      if (score > bestScore) {
        bestScore = score;
        bestAgent = agent;
      }
    }
    return bestAgent;
  }
  distributeTasksByCapability(tasks, agents, agentCapabilities, assignments) {
    for (const task of tasks) {
      const requiredCapabilities = this.analyzeRequiredCapabilities(task);
      const bestAgent = this.findBestAgentForTask(agents, requiredCapabilities, agentCapabilities);
      if (!assignments.has(bestAgent)) {
        assignments.set(bestAgent, []);
      }
      assignments.get(bestAgent).push({
        goalId: task.id,
        description: task.description,
        type: task.type,
        priority: task.priority,
        role: "executor"
      });
    }
  }
  createCapabilityMatrix(agents, agentCapabilities) {
    const matrix = /* @__PURE__ */ new Map();
    for (const agent of agents) {
      const agentKey = this.getAgentKey(agent);
      const capabilities = agentCapabilities.get(agentKey) || [];
      matrix.set(agentKey, new Set(capabilities));
    }
    return matrix;
  }
  createCollaborativeAssignment(goal, requiredCapabilities, capabilityMatrix) {
    const assignment = /* @__PURE__ */ new Map();
    for (const capability of requiredCapabilities) {
      const capableAgents = Array.from(capabilityMatrix.entries()).filter(([_, caps]) => caps.has(capability)).map(([agentKey, _]) => agentKey);
      if (capableAgents.length > 0) {
        const selectedAgentKey = capableAgents[0];
        const agentId = { id: selectedAgentKey.split(":")[1], namespace: selectedAgentKey.split(":")[0] };
        assignment.set(agentId, {
          goalId: goal.id,
          description: `${capability} work for: ${goal.description}`,
          type: goal.type,
          priority: goal.priority,
          role: "collaborator",
          focus: capability
        });
      }
    }
    return assignment;
  }
  async getTeamWorkloads(team) {
    const workloads = /* @__PURE__ */ new Map();
    for (const member of team.members) {
      try {
        const response = await this.messageBus.sendAndWaitForResponse({
          id: v4(),
          from: team.leader,
          to: member,
          type: MessageType.REQUEST,
          content: {
            topic: "state:query",
            body: { requestId: v4() }
          },
          timestamp: /* @__PURE__ */ new Date(),
          priority: MessagePriority.NORMAL
        }, 3e3);
        const agentKey = this.getAgentKey(member);
        workloads.set(agentKey, response.content.body.workload || 0);
      } catch (error) {
        const agentKey = this.getAgentKey(member);
        workloads.set(agentKey, 50);
      }
    }
    return workloads;
  }
  hasRequiredCapabilities(agentCapabilities, requiredCapabilities) {
    return requiredCapabilities.some(
      (required) => agentCapabilities.some((agent) => agent.toLowerCase().includes(required.toLowerCase()))
    );
  }
  getLeastLoadedAgent(agents, workloads) {
    let leastLoadedAgent = agents[0];
    let lowestWorkload = Infinity;
    for (const agent of agents) {
      const agentKey = this.getAgentKey(agent);
      const workload = workloads.get(agentKey) || 0;
      if (workload < lowestWorkload) {
        lowestWorkload = workload;
        leastLoadedAgent = agent;
      }
    }
    return leastLoadedAgent;
  }
  estimateTaskLoad(goal) {
    const complexity = this.analyzeGoalComplexity(goal);
    const priorityWeight = {
      "critical": 1.5,
      "high": 1.2,
      "medium": 1,
      "low": 0.8
    };
    return complexity * priorityWeight[goal.priority] * 20;
  }
  defaultAssignment(team, subGoals) {
    const assignments = /* @__PURE__ */ new Map();
    subGoals.forEach((subGoal, index) => {
      const assignedAgent = team.members[index % team.members.length];
      if (!assignments.has(assignedAgent)) {
        assignments.set(assignedAgent, []);
      }
      assignments.get(assignedAgent).push({
        goalId: subGoal.id,
        description: subGoal.description,
        type: subGoal.type,
        priority: subGoal.priority
      });
    });
    return assignments;
  }
  /**
   * Select best coordination strategy for current context
   */
  selectStrategy(team, goals) {
    let bestStrategy = null;
    let bestScore = -1;
    const context = {
      team,
      currentGoals: goals,
      agentStates: /* @__PURE__ */ new Map(),
      environment: {}
    };
    for (const strategy of this.strategies.values()) {
      const score = strategy.evaluate(context);
      if (score > bestScore) {
        bestScore = score;
        bestStrategy = strategy;
      }
    }
    if (!bestStrategy) {
      bestStrategy = this.strategies.get(team.formation) || this.strategies.get("dynamic");
    }
    return bestStrategy;
  }
  /**
   * Update team status
   */
  async updateTeamStatus(teamId, status) {
    const team = this.teams.get(teamId);
    if (!team) {
      throw new Error(`Team not found: ${teamId}`);
    }
    const previousStatus = team.status;
    team.status = status;
    await this.notifyTeamUpdate(team, "status:changed", { previousStatus, newStatus: status });
    this.logger.info("Updated team status", { teamId, previousStatus, newStatus: status });
    this.emit("team:statusChanged", { team, previousStatus, newStatus: status });
  }
  /**
   * Disband a team
   */
  async disbandTeam(teamId) {
    const team = this.teams.get(teamId);
    if (!team) {
      throw new Error(`Team not found: ${teamId}`);
    }
    team.status = TeamStatus.DISBANDED;
    team.members.forEach((member) => {
      this.agentTeams.delete(this.getAgentKey(member));
    });
    await this.notifyTeamUpdate(team, "team:disbanded");
    this.teams.delete(teamId);
    this.logger.info("Disbanded team", { teamId });
    this.emit("team:disbanded", team);
  }
  /**
   * Notify team members of updates
   */
  async notifyTeamUpdate(team, updateType, data) {
    const message = {
      id: v4(),
      from: team.leader,
      to: team.members,
      type: MessageType.INFORM,
      content: {
        topic: updateType,
        body: {
          teamId: team.id,
          teamName: team.name,
          ...data
        }
      },
      timestamp: /* @__PURE__ */ new Date(),
      priority: MessagePriority.HIGH
    };
    await this.messageBus.send(message);
  }
  /**
   * Register a coordination strategy
   */
  registerStrategy(strategy) {
    this.strategies.set(strategy.type, strategy);
    this.logger.info("Registered coordination strategy", { type: strategy.type });
  }
  /**
   * Get team by ID
   */
  getTeam(teamId) {
    return this.teams.get(teamId);
  }
  /**
   * Get team for agent
   */
  getAgentTeam(agentId) {
    const teamId = this.agentTeams.get(this.getAgentKey(agentId));
    return teamId ? this.teams.get(teamId) : void 0;
  }
  /**
   * Get all teams
   */
  getAllTeams() {
    return Array.from(this.teams.values());
  }
  /**
   * Get teams by status
   */
  getTeamsByStatus(status) {
    return Array.from(this.teams.values()).filter((team) => team.status === status);
  }
  /**
   * Find teams capable of handling specific goal types
   */
  findCapableTeams(requiredCapabilities) {
    return this.getTeamsByStatus(TeamStatus.ACTIVE);
  }
  /**
   * Get agent key for consistent identification
   */
  getAgentKey(agentId) {
    return `${agentId.namespace || "default"}:${agentId.id}`;
  }
  /**
   * Real-time performance-based team optimization
   */
  async optimizeTeamFormation(teamId) {
    const team = this.teams.get(teamId);
    if (!team) {
      throw new Error(`Team not found: ${teamId}`);
    }
    const performanceMetrics = await this.gatherTeamPerformanceMetrics(team);
    const agentStates = await this.getTeamStates(team);
    const context = {
      team,
      currentGoals: team.goals,
      agentStates,
      environment: {
        performance: performanceMetrics,
        timestamp: /* @__PURE__ */ new Date()
      }
    };
    const currentStrategy = this.strategies.get(team.formation);
    if (!currentStrategy) return;
    const currentScore = currentStrategy.evaluate(context);
    let bestFormation = team.formation;
    let bestScore = currentScore;
    let bestStrategy = null;
    for (const [formationType, strategy] of this.strategies) {
      const score = strategy.evaluate(context);
      this.logger.debug("Strategy evaluation", {
        teamId,
        strategy: formationType,
        score,
        currentScore
      });
      if (score > bestScore) {
        bestScore = score;
        bestFormation = formationType;
        bestStrategy = strategy;
      }
    }
    const improvementThreshold = 0.1;
    if (bestFormation !== team.formation && bestScore - currentScore > improvementThreshold) {
      const previousFormation = team.formation;
      team.formation = bestFormation;
      await this.implementFormationChange(team, previousFormation, bestFormation, bestStrategy);
      await this.notifyTeamUpdate(team, "formation:optimized", {
        previousFormation,
        newFormation: bestFormation,
        improvement: bestScore - currentScore,
        performanceMetrics
      });
      this.logger.info("Team formation optimized", {
        teamId,
        previousFormation,
        newFormation: bestFormation,
        improvement: bestScore - currentScore
      });
    } else {
      this.logger.debug("No significant improvement found", {
        teamId,
        currentScore,
        bestScore,
        improvement: bestScore - currentScore
      });
    }
  }
  /**
   * Gather real performance metrics from team members
   */
  async gatherTeamPerformanceMetrics(team) {
    const metrics = {
      completionRate: 0,
      averageResponseTime: 0,
      errorRate: 0,
      collaborationScore: 0,
      workloadBalance: 0
    };
    let successfulResponses = 0;
    for (const member of team.members) {
      try {
        const response = await this.messageBus.sendAndWaitForResponse({
          id: v4(),
          from: team.leader,
          to: member,
          type: MessageType.REQUEST,
          content: {
            topic: "performance:metrics",
            body: { timeframe: "1h" }
          },
          timestamp: /* @__PURE__ */ new Date(),
          priority: MessagePriority.NORMAL
        }, 5e3);
        const agentMetrics = response.content.body;
        metrics.completionRate += agentMetrics.tasksCompleted || 0;
        metrics.averageResponseTime += agentMetrics.averageResponseTime || 0;
        metrics.errorRate += agentMetrics.errorRate || 0;
        successfulResponses++;
      } catch (error) {
        this.logger.warn("Failed to get performance metrics", {
          member: this.getAgentKey(member),
          error
        });
      }
    }
    if (successfulResponses > 0) {
      metrics.completionRate /= successfulResponses;
      metrics.averageResponseTime /= successfulResponses;
      metrics.errorRate /= successfulResponses;
    }
    metrics.collaborationScore = await this.calculateCollaborationScore(team);
    metrics.workloadBalance = await this.calculateWorkloadBalance(team);
    return metrics;
  }
  /**
   * Get current states of all team members
   */
  async getTeamStates(team) {
    const states = /* @__PURE__ */ new Map();
    for (const member of team.members) {
      try {
        const response = await this.messageBus.sendAndWaitForResponse({
          id: v4(),
          from: team.leader,
          to: member,
          type: MessageType.REQUEST,
          content: {
            topic: "state:query",
            body: {}
          },
          timestamp: /* @__PURE__ */ new Date(),
          priority: MessagePriority.NORMAL
        }, 3e3);
        const agentKey = this.getAgentKey(member);
        states.set(agentKey, response.content.body.state || AgentState.IDLE);
      } catch (error) {
        const agentKey = this.getAgentKey(member);
        states.set(agentKey, AgentState.IDLE);
      }
    }
    return states;
  }
  /**
   * Implement formation change with coordination
   */
  async implementFormationChange(team, previousFormation, newFormation, strategy) {
    await this.notifyTeamUpdate(team, "formation:changing", {
      previousFormation,
      newFormation,
      strategy: strategy.type
    });
    switch (newFormation) {
      case TeamFormation.HIERARCHICAL:
        await this.implementHierarchicalStructure(team);
        break;
      case TeamFormation.FLAT:
        await this.implementFlatStructure(team);
        break;
      case TeamFormation.MATRIX:
        await this.implementMatrixStructure(team);
        break;
      case TeamFormation.DYNAMIC:
        await this.implementDynamicStructure(team);
        break;
    }
    await this.updateCoordinationPatterns(team, newFormation);
  }
  /**
   * Calculate collaboration score based on message patterns
   */
  async calculateCollaborationScore(team) {
    const coordinationMetrics = this.messageBus.getCoordinationMetrics();
    const messageCount = coordinationMetrics.messageCount;
    const responseTime = coordinationMetrics.averageResponseTime;
    const activeAgents = coordinationMetrics.activeAgents;
    const messageScore = Math.min(messageCount / 100, 1);
    const responseScore = Math.max(0, 1 - responseTime / 1e4);
    const participationScore = activeAgents / team.members.length;
    return (messageScore + responseScore + participationScore) / 3;
  }
  /**
   * Calculate workload balance across team
   */
  async calculateWorkloadBalance(team) {
    const workloads = await this.getTeamWorkloads(team);
    const workloadValues = Array.from(workloads.values());
    if (workloadValues.length === 0) return 1;
    const average = workloadValues.reduce((sum, val) => sum + val, 0) / workloadValues.length;
    const variance = workloadValues.reduce((sum, val) => sum + Math.pow(val - average, 2), 0) / workloadValues.length;
    const standardDeviation = Math.sqrt(variance);
    return Math.max(0, 1 - standardDeviation / 50);
  }
  /**
   * Formation-specific implementation methods
   */
  async implementHierarchicalStructure(team) {
    await this.messageBus.send({
      id: v4(),
      from: team.leader,
      to: team.members.filter((m) => this.getAgentKey(m) !== this.getAgentKey(team.leader)),
      type: MessageType.INFORM,
      content: {
        topic: "structure:hierarchical",
        body: {
          leader: team.leader,
          reportingStructure: "centralized",
          decisionMaking: "top-down"
        }
      },
      timestamp: /* @__PURE__ */ new Date(),
      priority: MessagePriority.HIGH
    });
  }
  async implementFlatStructure(team) {
    await this.messageBus.send({
      id: v4(),
      from: team.leader,
      to: team.members,
      type: MessageType.INFORM,
      content: {
        topic: "structure:flat",
        body: {
          communicationPattern: "peer-to-peer",
          decisionMaking: "consensus",
          autonomy: "high"
        }
      },
      timestamp: /* @__PURE__ */ new Date(),
      priority: MessagePriority.HIGH
    });
  }
  async implementMatrixStructure(team) {
    await this.messageBus.send({
      id: v4(),
      from: team.leader,
      to: team.members,
      type: MessageType.INFORM,
      content: {
        topic: "structure:matrix",
        body: {
          collaborationPattern: "cross-functional",
          reportingStructure: "dual",
          taskAllocation: "capability-based"
        }
      },
      timestamp: /* @__PURE__ */ new Date(),
      priority: MessagePriority.HIGH
    });
  }
  async implementDynamicStructure(team) {
    await this.messageBus.send({
      id: v4(),
      from: team.leader,
      to: team.members,
      type: MessageType.INFORM,
      content: {
        topic: "structure:dynamic",
        body: {
          adaptationEnabled: true,
          restructuringTriggers: ["performance", "workload", "capabilities"],
          evaluationInterval: "15m"
        }
      },
      timestamp: /* @__PURE__ */ new Date(),
      priority: MessagePriority.HIGH
    });
  }
  async updateCoordinationPatterns(team, formation) {
    const patterns = {
      [TeamFormation.HIERARCHICAL]: "hub-and-spoke",
      [TeamFormation.FLAT]: "mesh",
      [TeamFormation.MATRIX]: "hybrid",
      [TeamFormation.DYNAMIC]: "adaptive"
    };
    await this.messageBus.send({
      id: v4(),
      from: team.leader,
      to: team.members,
      type: MessageType.INFORM,
      content: {
        topic: "coordination:pattern_updated",
        body: {
          pattern: patterns[formation],
          formation,
          effectiveAt: /* @__PURE__ */ new Date()
        }
      },
      timestamp: /* @__PURE__ */ new Date(),
      priority: MessagePriority.HIGH
    });
  }
}

class CoordinatorAgent extends BaseAgent {
  teamCoordinator;
  managedTeams;
  constructor(name = "Coordinator") {
    super(name, AgentType.COORDINATOR, {
      maxConcurrentTasks: 10,
      communicationTimeout: 6e4
    });
    this.teamCoordinator = new TeamCoordinator();
    this.managedTeams = /* @__PURE__ */ new Set();
    this.setupCoordinatorHandlers();
  }
  /**
   * Define coordinator capabilities
   */
  defineCapabilities() {
    return [
      {
        name: "team-formation",
        description: "Form teams of agents for complex goals"
      },
      {
        name: "goal-decomposition",
        description: "Break down complex goals into manageable sub-goals"
      },
      {
        name: "task-delegation",
        description: "Delegate tasks to appropriate agents or teams"
      },
      {
        name: "progress-monitoring",
        description: "Monitor and track progress of delegated tasks"
      },
      {
        name: "conflict-resolution",
        description: "Resolve conflicts between agents or teams"
      },
      {
        name: "resource-allocation",
        description: "Allocate resources optimally across teams"
      }
    ];
  }
  /**
   * Process incoming goals
   */
  async processGoal(goal) {
    try {
      this.logger.info("Processing coordinator goal", { goalId: goal.id });
      const subGoals = await this.goalEngine.decomposeGoal(goal);
      if (subGoals.length > 1) {
        await this.handleComplexGoal(goal, subGoals);
      } else {
        await this.delegateSimpleGoal(goal);
      }
      await this.goalEngine.updateGoalStatus(goal.id, GoalStatus.ACTIVE);
    } catch (error) {
      this.logger.error("Failed to process goal", error);
      await this.goalEngine.updateGoalStatus(goal.id, GoalStatus.FAILED);
      throw error;
    }
  }
  /**
   * Handle complex goals requiring team formation
   */
  async handleComplexGoal(goal, subGoals) {
    const requiredCapabilities = this.analyzeRequiredCapabilities(subGoals);
    let team = this.findSuitableTeam(requiredCapabilities);
    if (!team) {
      team = await this.formTeam(goal, requiredCapabilities);
    }
    await this.teamCoordinator.assignGoal(team.id, goal);
    this.managedTeams.add(team.id);
  }
  /**
   * Form a new team for a goal
   */
  async formTeam(goal, requiredCapabilities) {
    const availableAgents = await this.requestAvailableAgents(requiredCapabilities);
    const formation = this.selectFormationStrategy(goal, availableAgents.length);
    const team = await this.teamCoordinator.createTeam(
      `Team-${goal.id}`,
      this.id,
      [goal],
      formation
    );
    for (const agentId of availableAgents) {
      await this.teamCoordinator.addMember(team.id, agentId);
    }
    await this.teamCoordinator.updateTeamStatus(team.id, TeamStatus.ACTIVE);
    return team;
  }
  /**
   * Execute coordinator-specific tasks
   */
  async executeTask(task) {
    try {
      this.logger.debug("Executing coordinator task", { taskId: task.id });
      switch (task.description) {
        case "monitor-progress":
          return await this.monitorProgress(task);
        case "resolve-conflict":
          return await this.resolveConflict(task);
        case "optimize-teams":
          return await this.optimizeTeams(task);
        default:
          return await this.handleSpecializedTask(task);
      }
    } catch (error) {
      this.logger.error("Task execution failed", error);
      task.status = TaskStatus.FAILED;
      task.error = error;
      throw error;
    }
  }
  /**
   * Monitor progress of teams and agents
   */
  async monitorProgress(_task) {
    const progress = {
      teams: [],
      overallCompletion: 0
    };
    for (const teamId of this.managedTeams) {
      const team = this.teamCoordinator.getTeam(teamId);
      if (team) {
        const teamProgress = await this.getTeamProgress(team);
        progress.teams.push({
          teamId: team.id,
          status: team.status,
          progress: teamProgress
        });
      }
    }
    progress.overallCompletion = progress.teams.reduce(
      (sum, t) => sum + t.progress,
      0
    ) / progress.teams.length;
    return progress;
  }
  /**
   * Get progress for a specific team
   */
  async getTeamProgress(team) {
    const progressReports = await Promise.all(
      team.members.map((member) => this.queryAgentProgress(member))
    );
    return progressReports.reduce((sum, p) => sum + p, 0) / progressReports.length;
  }
  /**
   * Query an agent for progress
   */
  async queryAgentProgress(agentId) {
    return new Promise((resolve) => {
      const timeout = setTimeout(() => resolve(0), 5e3);
      this.once(`progress:${agentId.id}`, (progress) => {
        clearTimeout(timeout);
        resolve(progress);
      });
      this.sendMessage(
        agentId,
        MessageType.QUERY,
        { topic: "progress", body: {} },
        MessagePriority.HIGH
      );
    });
  }
  /**
   * Setup coordinator-specific message handlers
   */
  setupCoordinatorHandlers() {
    this.registerMessageHandler(MessageType.REQUEST, async (message) => {
      if (message.content.topic === "team:join") {
        await this.handleTeamJoinRequest(message);
      }
    });
    this.registerMessageHandler(MessageType.INFORM, async (message) => {
      if (message.content.topic === "progress:report") {
        this.emit(`progress:${message.from.id}`, message.content.body.progress);
      }
    });
  }
  /**
   * Handle team join requests
   */
  async handleTeamJoinRequest(message) {
    const { capabilities } = message.content.body;
    const teams = this.teamCoordinator.findCapableTeams(capabilities);
    if (teams.length > 0) {
      await this.teamCoordinator.addMember(teams[0].id, message.from);
      await this.sendMessage(
        message.from,
        MessageType.RESPONSE,
        {
          topic: "team:joined",
          body: { teamId: teams[0].id, role: "member" }
        }
      );
    } else {
      await this.sendMessage(
        message.from,
        MessageType.RESPONSE,
        {
          topic: "team:unavailable",
          body: { reason: "No suitable team found" }
        }
      );
    }
  }
  /**
   * Delegate simple goals to individual agents
   */
  async delegateSimpleGoal(goal) {
    const agents = await this.requestAvailableAgents([goal.type]);
    if (agents.length > 0) {
      await this.sendMessage(
        agents[0],
        MessageType.COMMAND,
        {
          topic: "goal:execute",
          body: { goal }
        },
        MessagePriority.HIGH
      );
    } else {
      await this.goalEngine.updateGoalStatus(goal.id, GoalStatus.FAILED);
    }
  }
  /**
   * Request available agents with specific capabilities
   */
  async requestAvailableAgents(capabilities) {
    return new Promise((resolve) => {
      const agents = [];
      const timeout = setTimeout(() => resolve(agents), 1e4);
      this.once("agents:available", (availableAgents) => {
        clearTimeout(timeout);
        resolve(availableAgents);
      });
      this.messageBus.broadcast(
        this.id,
        MessageType.REQUEST,
        {
          topic: "agents:needed",
          body: { capabilities, coordinator: this.id }
        },
        MessagePriority.HIGH
      );
    });
  }
  /**
   * Analyze required capabilities from sub-goals
   */
  analyzeRequiredCapabilities(subGoals) {
    const capabilities = /* @__PURE__ */ new Set();
    subGoals.forEach((goal) => {
      switch (goal.type) {
        case GoalType.ACHIEVE:
          capabilities.add("execution");
          break;
        case GoalType.QUERY:
          capabilities.add("analysis");
          break;
        case GoalType.MAINTAIN:
          capabilities.add("monitoring");
          break;
        default:
          capabilities.add("general");
      }
    });
    return Array.from(capabilities);
  }
  /**
   * Select best team formation strategy
   */
  selectFormationStrategy(_goal, teamSize) {
    if (teamSize <= 3) {
      return TeamFormation.FLAT;
    } else if (teamSize <= 7) {
      return TeamFormation.HIERARCHICAL;
    } else {
      return TeamFormation.MATRIX;
    }
  }
  /**
   * Find suitable existing team
   */
  findSuitableTeam(requiredCapabilities) {
    const teams = this.teamCoordinator.findCapableTeams(requiredCapabilities);
    return teams.find(
      (team) => team.status === TeamStatus.ACTIVE && team.members.length < 10
    );
  }
  /**
   * Resolve conflicts between agents or teams
   */
  async resolveConflict(task) {
    this.logger.info("Resolving conflict", { taskId: task.id });
    return { resolved: true };
  }
  /**
   * Optimize team formations
   */
  async optimizeTeams(_task) {
    const optimizations = [];
    for (const teamId of this.managedTeams) {
      await this.teamCoordinator.optimizeTeamFormation(teamId);
      optimizations.push({ teamId, optimized: true });
    }
    return { optimizations };
  }
  /**
   * Handle specialized coordinator tasks
   */
  async handleSpecializedTask(task) {
    this.logger.warn("Unhandled task type", { taskId: task.id, description: task.description });
    return { handled: false };
  }
}

class ExecutorAgent extends BaseAgent {
  executionQueue;
  executionHistory;
  constructor(name = "Executor") {
    super(name, AgentType.EXECUTOR, {
      maxConcurrentTasks: 3,
      communicationTimeout: 3e4
    });
    this.executionQueue = [];
    this.executionHistory = /* @__PURE__ */ new Map();
    this.setupExecutorHandlers();
  }
  /**
   * Define executor capabilities
   */
  defineCapabilities() {
    return [
      {
        name: "task-execution",
        description: "Execute assigned tasks"
      },
      {
        name: "resource-management",
        description: "Manage execution resources"
      },
      {
        name: "status-reporting",
        description: "Report execution status and progress"
      },
      {
        name: "error-handling",
        description: "Handle execution errors gracefully"
      }
    ];
  }
  /**
   * Process incoming goals
   */
  async processGoal(goal) {
    try {
      this.logger.info("Processing executor goal", { goalId: goal.id });
      const tasks = await this.goalEngine.goalToTasks(goal);
      tasks.forEach((task) => {
        task.status = TaskStatus.ASSIGNED;
        this.executionQueue.push(task);
        this.activeTasks.set(task.id, task);
      });
      await this.processExecutionQueue();
      await this.goalEngine.updateGoalStatus(goal.id, GoalStatus.ACTIVE);
    } catch (error) {
      this.logger.error("Failed to process goal", error);
      await this.goalEngine.updateGoalStatus(goal.id, GoalStatus.FAILED);
      throw error;
    }
  }
  /**
   * Execute a specific task
   */
  async executeTask(task) {
    try {
      this.logger.debug("Executing task", { taskId: task.id });
      task.status = TaskStatus.IN_PROGRESS;
      task.startedAt = /* @__PURE__ */ new Date();
      const result = await this.performTaskExecution(task);
      task.status = TaskStatus.COMPLETED;
      task.completedAt = /* @__PURE__ */ new Date();
      task.result = result;
      this.executionHistory.set(task.id, result);
      await this.reportTaskCompletion(task);
      this.updatePerformanceMetrics({
        tasksCompleted: this.profile.metadata.performance.tasksCompleted + 1,
        successRate: this.calculateSuccessRate()
      });
      if (this.hooks.onTaskCompleted) {
        await this.hooks.onTaskCompleted(task);
      }
      return result;
    } catch (error) {
      this.logger.error("Task execution failed", error);
      task.status = TaskStatus.FAILED;
      task.error = error;
      task.completedAt = /* @__PURE__ */ new Date();
      await this.reportTaskFailure(task);
      throw error;
    }
  }
  /**
   * Perform actual task execution
   */
  async performTaskExecution(task) {
    const executionTime = Math.random() * 5e3 + 1e3;
    await new Promise((resolve) => setTimeout(resolve, executionTime));
    if (task.description.includes("calculate")) {
      return { calculation: Math.random() * 100 };
    } else if (task.description.includes("analyze")) {
      return { analysis: "Completed analysis", confidence: 0.85 };
    } else if (task.description.includes("process")) {
      return { processed: true, items: Math.floor(Math.random() * 50) };
    }
    return { executed: true, timestamp: /* @__PURE__ */ new Date() };
  }
  /**
   * Process execution queue
   */
  async processExecutionQueue() {
    while (this.executionQueue.length > 0 && this.activeTasks.size < this.config.maxConcurrentTasks) {
      const task = this.executionQueue.shift();
      if (task) {
        this.executeTask(task).catch((error) => {
          this.logger.error("Queue processing error", error);
        });
      }
    }
  }
  /**
   * Report task completion
   */
  async reportTaskCompletion(task) {
    await this.sendMessage(
      task.assignedTo,
      MessageType.INFORM,
      {
        topic: "task:completed",
        body: {
          taskId: task.id,
          goalId: task.goalId,
          result: task.result,
          executionTime: task.completedAt.getTime() - task.startedAt.getTime()
        }
      }
    );
  }
  /**
   * Report task failure
   */
  async reportTaskFailure(task) {
    await this.sendMessage(
      task.assignedTo,
      MessageType.INFORM,
      {
        topic: "task:failed",
        body: {
          taskId: task.id,
          goalId: task.goalId,
          error: task.error?.message,
          executionTime: task.completedAt.getTime() - task.startedAt.getTime()
        }
      }
    );
  }
  /**
   * Calculate success rate
   */
  calculateSuccessRate() {
    const completed = Array.from(this.executionHistory.keys()).length;
    const failed = Array.from(this.activeTasks.values()).filter((t) => t.status === TaskStatus.FAILED).length;
    const total = completed + failed;
    return total > 0 ? completed / total : 0;
  }
  /**
   * Setup executor-specific message handlers
   */
  setupExecutorHandlers() {
    this.registerMessageHandler(MessageType.COMMAND, async (message) => {
      if (message.content.topic === "task:assignment") {
        await this.handleTaskAssignment(message);
      }
    });
    this.registerMessageHandler(MessageType.QUERY, async (message) => {
      if (message.content.topic === "status") {
        await this.handleStatusQuery(message);
      } else if (message.content.topic === "progress") {
        await this.handleProgressQuery(message);
      }
    });
  }
  /**
   * Handle task assignment from coordinator
   */
  async handleTaskAssignment(message) {
    const { tasks, goal } = message.content.body;
    if (goal) {
      await this.addGoal(goal);
    }
    for (const taskData of tasks) {
      const task = {
        id: taskData.id || v4(),
        goalId: taskData.goalId,
        assignedTo: this.id,
        description: taskData.description,
        status: TaskStatus.ASSIGNED
      };
      this.executionQueue.push(task);
      this.activeTasks.set(task.id, task);
    }
    await this.processExecutionQueue();
    await this.reply(
      message,
      MessageType.ACKNOWLEDGE,
      {
        topic: "task:acknowledged",
        body: { tasksReceived: tasks.length }
      }
    );
  }
  /**
   * Handle status query
   */
  async handleStatusQuery(message) {
    const status = {
      state: this.getState(),
      activeTasks: this.activeTasks.size,
      queuedTasks: this.executionQueue.length,
      completedTasks: this.executionHistory.size,
      performance: this.profile.metadata.performance
    };
    await this.reply(
      message,
      MessageType.RESPONSE,
      {
        topic: "status:report",
        body: status
      }
    );
  }
  /**
   * Handle progress query
   */
  async handleProgressQuery(message) {
    const totalTasks = this.activeTasks.size + this.executionQueue.length + this.executionHistory.size;
    const progress = totalTasks > 0 ? this.executionHistory.size / totalTasks : 0;
    await this.reply(
      message,
      MessageType.INFORM,
      {
        topic: "progress:report",
        body: { progress }
      }
    );
  }
  /**
   * Get execution history
   */
  getExecutionHistory() {
    return new Map(this.executionHistory);
  }
  /**
   * Clear execution history
   */
  clearHistory() {
    this.executionHistory.clear();
  }
  /**
   * Get queue status
   */
  getQueueStatus() {
    return {
      queued: this.executionQueue.length,
      active: this.activeTasks.size,
      completed: this.executionHistory.size
    };
  }
}

class SQLiteWorkflowStateStore {
  db;
  initialized = false;
  constructor(dbPath = ":memory:") {
    this.db = new Database(dbPath);
  }
  async initialize() {
    if (this.initialized) return;
    await this.createTables();
    this.initialized = true;
  }
  createTables() {
    return new Promise((resolve, reject) => {
      const createTablesSQL = `
        -- Workflow definitions table
        CREATE TABLE IF NOT EXISTS workflow_definitions (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          description TEXT,
          version TEXT NOT NULL,
          definition TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- Workflow executions table
        CREATE TABLE IF NOT EXISTS workflow_executions (
          id TEXT PRIMARY KEY,
          workflow_id TEXT NOT NULL,
          status TEXT NOT NULL,
          start_time DATETIME NOT NULL,
          end_time DATETIME,
          current_step TEXT,
          variables TEXT,
          results TEXT,
          error_message TEXT,
          parent_execution_id TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (workflow_id) REFERENCES workflow_definitions(id)
        );

        -- Workflow snapshots table
        CREATE TABLE IF NOT EXISTS workflow_snapshots (
          id TEXT PRIMARY KEY,
          execution_id TEXT NOT NULL,
          timestamp DATETIME NOT NULL,
          state TEXT NOT NULL,
          checksum TEXT NOT NULL,
          metadata TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (execution_id) REFERENCES workflow_executions(id)
        );

        -- Workflow logs table
        CREATE TABLE IF NOT EXISTS workflow_logs (
          id TEXT PRIMARY KEY,
          execution_id TEXT NOT NULL,
          timestamp DATETIME NOT NULL,
          level TEXT NOT NULL,
          message TEXT NOT NULL,
          step_id TEXT,
          data TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (execution_id) REFERENCES workflow_executions(id)
        );

        -- Create indexes for better performance
        CREATE INDEX IF NOT EXISTS idx_executions_workflow_id ON workflow_executions(workflow_id);
        CREATE INDEX IF NOT EXISTS idx_executions_status ON workflow_executions(status);
        CREATE INDEX IF NOT EXISTS idx_snapshots_execution_id ON workflow_snapshots(execution_id);
        CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON workflow_snapshots(timestamp);
        CREATE INDEX IF NOT EXISTS idx_logs_execution_id ON workflow_logs(execution_id);
        CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON workflow_logs(timestamp);
      `;
      this.db.exec(createTablesSQL, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
  async saveExecution(execution) {
    await this.initialize();
    return new Promise((resolve, reject) => {
      const sql = `
        INSERT INTO workflow_executions (
          id, workflow_id, status, start_time, end_time, current_step,
          variables, results, error_message, parent_execution_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      const params = [
        execution.id,
        execution.workflowId,
        execution.status,
        execution.startTime.toISOString(),
        execution.endTime?.toISOString() || null,
        execution.currentStep || null,
        JSON.stringify(execution.variables),
        JSON.stringify(execution.results),
        null,
        // error_message will be updated separately
        null
        // parent_execution_id
      ];
      this.db.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve();
      });
    });
  }
  async updateExecution(execution) {
    await this.initialize();
    return new Promise((resolve, reject) => {
      const sql = `
        UPDATE workflow_executions 
        SET status = ?, end_time = ?, current_step = ?, variables = ?, 
            results = ?, error_message = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `;
      const params = [
        execution.status,
        execution.endTime?.toISOString() || null,
        execution.currentStep || null,
        JSON.stringify(execution.variables),
        JSON.stringify(execution.results),
        execution.logs.find((l) => l.level === "error")?.message || null,
        execution.id
      ];
      this.db.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve();
      });
    });
  }
  async getExecution(executionId) {
    await this.initialize();
    return new Promise((resolve, reject) => {
      const sql = `
        SELECT * FROM workflow_executions WHERE id = ?
      `;
      this.db.get(sql, [executionId], (err, row) => {
        if (err) {
          reject(err);
        } else if (!row) {
          resolve(null);
        } else {
          const execution = {
            id: row.id,
            workflowId: row.workflow_id,
            status: row.status,
            startTime: new Date(row.start_time),
            endTime: row.end_time ? new Date(row.end_time) : void 0,
            currentStep: row.current_step,
            variables: JSON.parse(row.variables || "{}"),
            results: JSON.parse(row.results || "{}"),
            logs: []
            // Logs are loaded separately
          };
          resolve(execution);
        }
      });
    });
  }
  async deleteExecution(executionId) {
    await this.initialize();
    return new Promise((resolve, reject) => {
      const deleteStatements = [
        "DELETE FROM workflow_logs WHERE execution_id = ?",
        "DELETE FROM workflow_snapshots WHERE execution_id = ?",
        "DELETE FROM workflow_executions WHERE id = ?"
      ];
      let completed = 0;
      const total = deleteStatements.length;
      deleteStatements.forEach((sql) => {
        this.db.run(sql, [executionId], (err) => {
          if (err) {
            reject(err);
            return;
          }
          completed++;
          if (completed === total) {
            resolve();
          }
        });
      });
    });
  }
  async saveSnapshot(snapshot) {
    await this.initialize();
    return new Promise((resolve, reject) => {
      const sql = `
        INSERT INTO workflow_snapshots (
          id, execution_id, timestamp, state, checksum, metadata
        ) VALUES (?, ?, ?, ?, ?, ?)
      `;
      const params = [
        snapshot.id,
        snapshot.executionId,
        snapshot.timestamp.toISOString(),
        JSON.stringify(snapshot.state),
        snapshot.checksum,
        JSON.stringify(snapshot.metadata || {})
      ];
      this.db.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve();
      });
    });
  }
  async getLatestSnapshot(executionId) {
    await this.initialize();
    return new Promise((resolve, reject) => {
      const sql = `
        SELECT * FROM workflow_snapshots 
        WHERE execution_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 1
      `;
      this.db.get(sql, [executionId], (err, row) => {
        if (err) {
          reject(err);
        } else if (!row) {
          resolve(null);
        } else {
          const snapshot = {
            id: row.id,
            executionId: row.execution_id,
            timestamp: new Date(row.timestamp),
            state: JSON.parse(row.state),
            checksum: row.checksum,
            metadata: JSON.parse(row.metadata || "{}")
          };
          resolve(snapshot);
        }
      });
    });
  }
  async getSnapshot(snapshotId) {
    await this.initialize();
    return new Promise((resolve, reject) => {
      const sql = `SELECT * FROM workflow_snapshots WHERE id = ?`;
      this.db.get(sql, [snapshotId], (err, row) => {
        if (err) {
          reject(err);
        } else if (!row) {
          resolve(null);
        } else {
          const snapshot = {
            id: row.id,
            executionId: row.execution_id,
            timestamp: new Date(row.timestamp),
            state: JSON.parse(row.state),
            checksum: row.checksum,
            metadata: JSON.parse(row.metadata || "{}")
          };
          resolve(snapshot);
        }
      });
    });
  }
  async deleteSnapshots(executionId) {
    await this.initialize();
    return new Promise((resolve, reject) => {
      const sql = `DELETE FROM workflow_snapshots WHERE execution_id = ?`;
      this.db.run(sql, [executionId], function(err) {
        if (err) reject(err);
        else resolve();
      });
    });
  }
  async saveWorkflowDefinition(workflow) {
    await this.initialize();
    return new Promise((resolve, reject) => {
      const sql = `
        INSERT OR REPLACE INTO workflow_definitions (
          id, name, description, version, definition, updated_at
        ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      `;
      const params = [
        workflow.id,
        workflow.name,
        workflow.description,
        workflow.version,
        JSON.stringify(workflow)
      ];
      this.db.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve();
      });
    });
  }
  async getWorkflowDefinition(workflowId) {
    await this.initialize();
    return new Promise((resolve, reject) => {
      const sql = `SELECT definition FROM workflow_definitions WHERE id = ?`;
      this.db.get(sql, [workflowId], (err, row) => {
        if (err) {
          reject(err);
        } else if (!row) {
          resolve(null);
        } else {
          resolve(JSON.parse(row.definition));
        }
      });
    });
  }
  async saveLogs(logs, executionId) {
    await this.initialize();
    if (logs.length === 0) return;
    return new Promise((resolve, reject) => {
      const sql = `
        INSERT INTO workflow_logs (
          id, execution_id, timestamp, level, message, step_id, data
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `;
      const stmt = this.db.prepare(sql);
      let completed = 0;
      logs.forEach((log) => {
        const params = [
          v4(),
          executionId,
          log.timestamp.toISOString(),
          log.level,
          log.message,
          log.stepId || null,
          JSON.stringify(log.data || {})
        ];
        stmt.run(params, (err) => {
          if (err) {
            reject(err);
            return;
          }
          completed++;
          if (completed === logs.length) {
            stmt.finalize(() => resolve());
          }
        });
      });
    });
  }
  async getLogs(executionId, limit = 1e3) {
    await this.initialize();
    return new Promise((resolve, reject) => {
      const sql = `
        SELECT * FROM workflow_logs 
        WHERE execution_id = ? 
        ORDER BY timestamp ASC 
        LIMIT ?
      `;
      this.db.all(sql, [executionId, limit], (err, rows) => {
        if (err) {
          reject(err);
        } else {
          const logs = rows.map((row) => ({
            timestamp: new Date(row.timestamp),
            level: row.level,
            message: row.message,
            stepId: row.step_id,
            data: JSON.parse(row.data || "{}")
          }));
          resolve(logs);
        }
      });
    });
  }
  async close() {
    return new Promise((resolve, reject) => {
      this.db.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
}
class WorkflowStateManager extends EventEmitter$1 {
  store;
  snapshotTimers = /* @__PURE__ */ new Map();
  constructor(store) {
    super();
    this.store = store;
  }
  async saveExecution(execution) {
    await this.store.saveExecution(execution);
    this.emit("execution:saved", { executionId: execution.id });
  }
  async updateExecution(execution) {
    await this.store.updateExecution(execution);
    if (execution.logs.length > 0) {
      await this.store.saveLogs(execution.logs, execution.id);
      execution.logs = [];
    }
    this.emit("execution:updated", { executionId: execution.id });
  }
  async getExecution(executionId) {
    const execution = await this.store.getExecution(executionId);
    if (execution) {
      execution.logs = await this.store.getLogs(executionId);
    }
    return execution;
  }
  async createSnapshot(executionId, state) {
    const snapshot = {
      id: v4(),
      executionId,
      timestamp: /* @__PURE__ */ new Date(),
      state,
      checksum: this.calculateChecksum(state)
    };
    await this.store.saveSnapshot(snapshot);
    this.emit("snapshot:created", { snapshotId: snapshot.id, executionId });
    return snapshot.id;
  }
  async restoreFromSnapshot(snapshotId) {
    const snapshot = await this.store.getSnapshot(snapshotId);
    if (!snapshot) return null;
    return snapshot.state;
  }
  async enableAutoSnapshots(executionId, intervalMs = 6e4) {
    const existingTimer = this.snapshotTimers.get(executionId);
    if (existingTimer) {
      clearInterval(existingTimer);
    }
    const timer = setInterval(async () => {
      try {
        const execution = await this.getExecution(executionId);
        if (execution && execution.status === "running") {
          await this.createSnapshot(executionId, execution);
        } else {
          this.disableAutoSnapshots(executionId);
        }
      } catch (error) {
        this.emit("error", { error, executionId, operation: "auto-snapshot" });
      }
    }, intervalMs);
    this.snapshotTimers.set(executionId, timer);
    this.emit("auto-snapshots:enabled", { executionId, intervalMs });
  }
  disableAutoSnapshots(executionId) {
    const timer = this.snapshotTimers.get(executionId);
    if (timer) {
      clearInterval(timer);
      this.snapshotTimers.delete(executionId);
      this.emit("auto-snapshots:disabled", { executionId });
    }
  }
  async saveWorkflow(workflow) {
    await this.store.saveWorkflowDefinition(workflow);
    this.emit("workflow:saved", { workflowId: workflow.id });
  }
  async getWorkflow(workflowId) {
    return this.store.getWorkflowDefinition(workflowId);
  }
  async cleanup(executionId) {
    this.disableAutoSnapshots(executionId);
    await this.cleanupOldSnapshots(executionId);
    this.emit("cleanup:completed", { executionId });
  }
  async cleanupOldSnapshots(executionId, keepCount = 10) {
  }
  calculateChecksum(state) {
    const stateString = JSON.stringify(state);
    let hash = 0;
    for (let i = 0; i < stateString.length; i++) {
      const char = stateString.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return hash.toString(16);
  }
  async shutdown() {
    for (const timer of this.snapshotTimers.values()) {
      clearInterval(timer);
    }
    this.snapshotTimers.clear();
    if ("close" in this.store && typeof this.store.close === "function") {
      await this.store.close();
    }
    this.removeAllListeners();
  }
}

class WorkflowEngine extends EventEmitter$1 {
  workflows = /* @__PURE__ */ new Map();
  executions = /* @__PURE__ */ new Map();
  machines = /* @__PURE__ */ new Map();
  stateManager;
  enablePersistence;
  constructor(options = {}) {
    super();
    this.enablePersistence = options.enablePersistence ?? true;
    if (this.enablePersistence) {
      const store = new SQLiteWorkflowStateStore(options.dbPath);
      this.stateManager = new WorkflowStateManager(store);
      this.setupStateManagerEvents();
    }
  }
  async createWorkflow(definition) {
    this.validateWorkflow(definition);
    const machine = this.createStateMachine(definition);
    this.workflows.set(definition.id, definition);
    this.machines.set(definition.id, machine);
    if (this.enablePersistence) {
      await this.stateManager.saveWorkflow(definition);
    }
    this.emit("workflow:created", { workflowId: definition.id });
  }
  async executeWorkflow(workflowId, variables = {}) {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) {
      throw new Error(`Workflow ${workflowId} not found`);
    }
    const executionId = v4();
    const execution = {
      id: executionId,
      workflowId,
      status: "pending",
      startTime: /* @__PURE__ */ new Date(),
      variables: { ...workflow.variables, ...variables },
      results: {},
      logs: []
    };
    this.executions.set(executionId, execution);
    if (this.enablePersistence) {
      await this.stateManager.saveExecution(execution);
    }
    this.startExecution(execution);
    return executionId;
  }
  async startExecution(execution) {
    const workflow = this.workflows.get(execution.workflowId);
    const machine = this.machines.get(execution.workflowId);
    execution.status = "running";
    this.logExecution(execution, "info", `Starting workflow execution`);
    try {
      const service = interpret(machine).onTransition((state) => {
        this.handleStateTransition(execution, state);
      });
      service.start();
      const firstStep = workflow.steps[0];
      if (firstStep) {
        await this.executeStep(execution, firstStep);
      }
    } catch (error) {
      execution.status = "failed";
      execution.endTime = /* @__PURE__ */ new Date();
      this.logExecution(execution, "error", `Workflow failed: ${error.message}`);
      this.emit("workflow:failed", { executionId: execution.id, error });
    }
  }
  async executeStep(execution, step) {
    execution.currentStep = step.id;
    this.logExecution(execution, "info", `Executing step: ${step.name}`, step.id);
    try {
      let result;
      switch (step.type) {
        case "agent-task":
          result = await this.executeAgentTask(execution, step);
          break;
        case "parallel":
          result = await this.executeParallel(execution, step);
          break;
        case "condition":
          result = await this.executeCondition(execution, step);
          break;
        case "loop":
          result = await this.executeLoop(execution, step);
          break;
        case "http":
          result = await this.executeHttpRequest(execution, step);
          break;
        case "script":
          result = await this.executeScript(execution, step);
          break;
        default:
          throw new Error(`Unknown step type: ${step.type}`);
      }
      execution.results[step.id] = result;
      this.logExecution(execution, "info", `Step completed: ${step.name}`, step.id);
      if (this.enablePersistence) {
        await this.stateManager.updateExecution(execution);
      }
      await this.executeNextSteps(execution, step, result);
    } catch (error) {
      this.logExecution(execution, "error", `Step failed: ${error.message}`, step.id);
      if (step.onFailure) {
        await this.executeNextStep(execution, step.onFailure);
      } else {
        throw error;
      }
    }
  }
  async executeAgentTask(execution, step) {
    const { StepExecutorFactory } = await import('./step-executors-Cd2WVYMn.js');
    const executor = StepExecutorFactory.getExecutor("agent-task");
    const context = {
      execution,
      step,
      variables: execution.variables,
      results: execution.results,
      logger: (level, message, stepId) => {
        this.logExecution(execution, level, message, stepId);
      }
    };
    const result = await executor.execute(context);
    if (!result.success) {
      throw result.error || new Error("Agent task execution failed");
    }
    return result.result;
  }
  async executeParallel(execution, step) {
    const { StepExecutorFactory } = await import('./step-executors-Cd2WVYMn.js');
    const executor = StepExecutorFactory.getExecutor("parallel");
    const context = {
      execution,
      step,
      variables: execution.variables,
      results: execution.results,
      logger: (level, message, stepId) => {
        this.logExecution(execution, level, message, stepId);
      }
    };
    const result = await executor.execute(context);
    if (!result.success) {
      throw result.error || new Error("Parallel execution failed");
    }
    return result.result;
  }
  async executeCondition(execution, step) {
    const { StepExecutorFactory } = await import('./step-executors-Cd2WVYMn.js');
    const executor = StepExecutorFactory.getExecutor("condition");
    const context = {
      execution,
      step,
      variables: execution.variables,
      results: execution.results,
      logger: (level, message, stepId) => {
        this.logExecution(execution, level, message, stepId);
      }
    };
    const result = await executor.execute(context);
    if (!result.success) {
      throw result.error || new Error("Condition evaluation failed");
    }
    const { nextStep } = result.result;
    if (nextStep) {
      await this.executeNextStep(execution, nextStep);
    }
    return result.result;
  }
  async executeLoop(execution, step) {
    const { StepExecutorFactory } = await import('./step-executors-Cd2WVYMn.js');
    const executor = StepExecutorFactory.getExecutor("loop");
    const context = {
      execution,
      step,
      variables: execution.variables,
      results: execution.results,
      logger: (level, message, stepId) => {
        this.logExecution(execution, level, message, stepId);
      }
    };
    const result = await executor.execute(context);
    if (!result.success) {
      throw result.error || new Error("Loop execution failed");
    }
    return result.result;
  }
  async executeHttpRequest(execution, step) {
    const { StepExecutorFactory } = await import('./step-executors-Cd2WVYMn.js');
    const executor = StepExecutorFactory.getExecutor("http");
    const context = {
      execution,
      step,
      variables: execution.variables,
      results: execution.results,
      logger: (level, message, stepId) => {
        this.logExecution(execution, level, message, stepId);
      }
    };
    const result = await executor.execute(context);
    if (!result.success) {
      throw result.error || new Error("HTTP request failed");
    }
    return result.result;
  }
  async executeScript(execution, step) {
    const { StepExecutorFactory } = await import('./step-executors-Cd2WVYMn.js');
    const executor = StepExecutorFactory.getExecutor("script");
    const context = {
      execution,
      step,
      variables: execution.variables,
      results: execution.results,
      logger: (level, message, stepId) => {
        this.logExecution(execution, level, message, stepId);
      }
    };
    const result = await executor.execute(context);
    if (!result.success) {
      throw result.error || new Error("Script execution failed");
    }
    return result.result;
  }
  async executeNextSteps(execution, step, result) {
    if (step.next) {
      for (const nextStepId of step.next) {
        await this.executeNextStep(execution, nextStepId);
      }
    } else if (step.onSuccess) {
      await this.executeNextStep(execution, step.onSuccess);
    } else {
      execution.status = "completed";
      execution.endTime = /* @__PURE__ */ new Date();
      this.logExecution(execution, "info", "Workflow completed successfully");
      if (this.enablePersistence) {
        await this.stateManager.updateExecution(execution);
        await this.stateManager.cleanup(execution.id);
      }
      this.emit("workflow:completed", { executionId: execution.id });
    }
  }
  async executeNextStep(execution, stepId) {
    const workflow = this.workflows.get(execution.workflowId);
    const nextStep = workflow.steps.find((s) => s.id === stepId);
    if (!nextStep) {
      throw new Error(`Next step ${stepId} not found`);
    }
    return this.executeStep(execution, nextStep);
  }
  evaluateCondition(condition, execution) {
    const context = {
      variables: execution.variables,
      results: execution.results
    };
    try {
      return new Function("context", `with(context) { return ${condition}; }`)(context);
    } catch (error) {
      this.logExecution(execution, "warn", `Condition evaluation failed: ${error.message}`);
      return false;
    }
  }
  createStateMachine(workflow) {
    const states = {};
    workflow.steps.forEach((step) => {
      states[step.id] = {
        on: {
          COMPLETE: step.next ? step.next[0] : "completed",
          FAIL: step.onFailure || "failed"
        }
      };
    });
    states.completed = { type: "final" };
    states.failed = { type: "final" };
    return createMachine({
      id: workflow.id,
      initial: workflow.steps[0]?.id || "completed",
      states
    });
  }
  handleStateTransition(execution, state) {
    this.logExecution(execution, "info", `State transition: ${state.value}`);
    this.emit("workflow:state-change", {
      executionId: execution.id,
      state: state.value
    });
  }
  validateWorkflow(workflow) {
    if (!workflow.id || !workflow.name || !workflow.steps.length) {
      throw new Error("Invalid workflow definition");
    }
    const stepIds = new Set(workflow.steps.map((s) => s.id));
    workflow.steps.forEach((step) => {
      if (step.next) {
        step.next.forEach((nextId) => {
          if (!stepIds.has(nextId)) {
            throw new Error(`Invalid step reference: ${nextId}`);
          }
        });
      }
    });
  }
  logExecution(execution, level, message, stepId) {
    const log = {
      timestamp: /* @__PURE__ */ new Date(),
      level,
      message,
      stepId
    };
    execution.logs.push(log);
    this.emit("workflow:log", { executionId: execution.id, log });
    if (this.enablePersistence && execution.logs.length % 10 === 0) {
      this.stateManager.updateExecution(execution).catch((error) => {
        console.error("Failed to persist execution logs:", error);
      });
    }
  }
  // Public API methods
  getWorkflow(id) {
    return this.workflows.get(id);
  }
  getExecution(id) {
    return this.executions.get(id);
  }
  listWorkflows() {
    return Array.from(this.workflows.values());
  }
  listExecutions(workflowId) {
    const executions = Array.from(this.executions.values());
    return workflowId ? executions.filter((e) => e.workflowId === workflowId) : executions;
  }
  async cancelExecution(executionId) {
    const execution = this.executions.get(executionId);
    if (!execution) {
      throw new Error(`Execution ${executionId} not found`);
    }
    execution.status = "cancelled";
    execution.endTime = /* @__PURE__ */ new Date();
    this.logExecution(execution, "info", "Execution cancelled");
    if (this.enablePersistence) {
      await this.stateManager.updateExecution(execution);
      await this.stateManager.cleanup(execution.id);
    }
    this.emit("workflow:cancelled", { executionId });
  }
  // Workflow resume capability
  async resumeWorkflow(executionId) {
    if (!this.enablePersistence) {
      throw new Error("Persistence is disabled, cannot resume workflow");
    }
    const execution = await this.stateManager.getExecution(executionId);
    if (!execution) {
      throw new Error(`Execution ${executionId} not found`);
    }
    if (execution.status !== "paused" && execution.status !== "failed") {
      throw new Error(`Cannot resume workflow in status ${execution.status}`);
    }
    const workflow = await this.stateManager.getWorkflow(execution.workflowId);
    if (!workflow) {
      throw new Error(`Workflow definition ${execution.workflowId} not found`);
    }
    this.workflows.set(execution.workflowId, workflow);
    this.executions.set(executionId, execution);
    const machine = this.createStateMachine(workflow);
    this.machines.set(execution.workflowId, machine);
    execution.status = "running";
    await this.stateManager.updateExecution(execution);
    if (execution.currentStep) {
      const currentStep = workflow.steps.find((s) => s.id === execution.currentStep);
      if (currentStep) {
        this.logExecution(execution, "info", `Resuming workflow from step: ${currentStep.name}`);
        await this.executeStep(execution, currentStep);
      }
    }
    this.emit("workflow:resumed", { executionId });
  }
  // Pause workflow execution
  async pauseWorkflow(executionId) {
    const execution = this.executions.get(executionId);
    if (!execution) {
      throw new Error(`Execution ${executionId} not found`);
    }
    if (execution.status !== "running") {
      throw new Error(`Cannot pause workflow in status ${execution.status}`);
    }
    execution.status = "paused";
    this.logExecution(execution, "info", "Workflow paused");
    if (this.enablePersistence) {
      await this.stateManager.updateExecution(execution);
      await this.stateManager.createSnapshot(executionId, execution);
    }
    this.emit("workflow:paused", { executionId });
  }
  // Enable auto-snapshots for running workflows
  async enableAutoSnapshots(executionId, intervalMs = 6e4) {
    if (!this.enablePersistence) {
      throw new Error("Persistence is disabled, cannot enable auto-snapshots");
    }
    await this.stateManager.enableAutoSnapshots(executionId, intervalMs);
  }
  // Setup state manager event handlers
  setupStateManagerEvents() {
    if (!this.stateManager) return;
    this.stateManager.on("execution:saved", (data) => {
      this.emit("persistence:execution-saved", data);
    });
    this.stateManager.on("execution:updated", (data) => {
      this.emit("persistence:execution-updated", data);
    });
    this.stateManager.on("snapshot:created", (data) => {
      this.emit("persistence:snapshot-created", data);
    });
    this.stateManager.on("workflow:saved", (data) => {
      this.emit("persistence:workflow-saved", data);
    });
    this.stateManager.on("error", (data) => {
      this.emit("persistence:error", data);
    });
  }
  // Cleanup and shutdown
  async shutdown() {
    for (const [executionId, execution] of this.executions) {
      if (execution.status === "running") {
        await this.cancelExecution(executionId);
      }
    }
    if (this.stateManager) {
      await this.stateManager.shutdown();
    }
    this.workflows.clear();
    this.executions.clear();
    this.machines.clear();
    this.removeAllListeners();
  }
  // Get workflow execution metrics
  getExecutionMetrics(executionId) {
    const execution = this.executions.get(executionId);
    if (!execution) return null;
    const totalSteps = execution.results ? Object.keys(execution.results).length : 0;
    const duration = execution.endTime ? execution.endTime.getTime() - execution.startTime.getTime() : Date.now() - execution.startTime.getTime();
    return {
      executionId,
      status: execution.status,
      totalSteps,
      duration,
      startTime: execution.startTime,
      endTime: execution.endTime,
      currentStep: execution.currentStep,
      logs: execution.logs.length,
      errors: execution.logs.filter((l) => l.level === "error").length
    };
  }
  // List all executions with optional filtering
  listExecutions(filter) {
    let executions = Array.from(this.executions.values());
    if (filter) {
      if (filter.status) {
        executions = executions.filter((e) => e.status === filter.status);
      }
      if (filter.workflowId) {
        executions = executions.filter((e) => e.workflowId === filter.workflowId);
      }
    }
    return executions;
  }
}

const logDir = path.join(process.cwd(), ".agentic-flow", "logs");
fs.ensureDirSync(logDir);
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: "agentic-flow" },
  transports: [
    // Write all logs to file
    new winston.transports.File({
      filename: path.join(logDir, "error.log"),
      level: "error"
    }),
    new winston.transports.File({
      filename: path.join(logDir, "combined.log")
    })
  ]
});
if (process.env.NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
      silent: process.env.QUIET === "true"
    })
  );
}

class AgentManager extends EventEmitter$1 {
  agents = /* @__PURE__ */ new Map();
  runningAgents = /* @__PURE__ */ new Set();
  constructor() {
    super();
  }
  async createAgent(config) {
    const agent = {
      id: config.id || v4(),
      name: config.name || `agent-${Date.now()}`,
      type: config.type || "generic",
      status: "idle",
      capabilities: config.capabilities || [],
      model: config.model || "claude-3",
      priority: config.priority || "medium",
      createdAt: (/* @__PURE__ */ new Date()).toISOString(),
      metrics: {
        tasksCompleted: 0,
        successRate: 100,
        avgResponseTime: 0
      },
      ...config
    };
    this.agents.set(agent.id, agent);
    this.emit("agent:created", agent);
    logger.info("Agent created", { agentId: agent.id, name: agent.name });
    return agent;
  }
  async startAgent(agentId) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }
    if (agent.status === "running") {
      throw new Error(`Agent ${agent.name} is already running`);
    }
    agent.status = "running";
    agent.startedAt = (/* @__PURE__ */ new Date()).toISOString();
    this.runningAgents.add(agentId);
    this.emit("agent:started", agent);
    logger.info("Agent started", { agentId, name: agent.name });
    await this.simulateAgentWork(agent);
  }
  async stopAgent(agentId, force = false) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }
    if (agent.status !== "running") {
      throw new Error(`Agent ${agent.name} is not running`);
    }
    if (!force) {
      this.emit("agent:stopping", agent);
      await this.waitForTaskCompletion(agent);
    }
    agent.status = "stopped";
    agent.stoppedAt = (/* @__PURE__ */ new Date()).toISOString();
    this.runningAgents.delete(agentId);
    this.emit("agent:stopped", agent);
    logger.info("Agent stopped", { agentId, name: agent.name, force });
  }
  async removeAgent(agentId) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }
    if (agent.status === "running") {
      await this.stopAgent(agentId, true);
    }
    this.agents.delete(agentId);
    this.emit("agent:removed", agent);
    logger.info("Agent removed", { agentId, name: agent.name });
  }
  getAgent(agentId) {
    return this.agents.get(agentId);
  }
  getAllAgents() {
    return Array.from(this.agents.values());
  }
  getRunningAgents() {
    return Array.from(this.runningAgents).map((id) => this.agents.get(id)).filter((agent) => agent !== void 0);
  }
  async assignTask(agentId, task) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }
    if (agent.status !== "running") {
      throw new Error(`Agent ${agent.name} is not running`);
    }
    this.emit("task:assigned", { agent, task });
    logger.info("Task assigned to agent", { agentId, task });
    const startTime = Date.now();
    try {
      const result = await this.executeTask(agent, task);
      agent.lastTaskAt = (/* @__PURE__ */ new Date()).toISOString();
      agent.metrics.tasksCompleted++;
      const responseTime = Date.now() - startTime;
      agent.metrics.avgResponseTime = (agent.metrics.avgResponseTime * (agent.metrics.tasksCompleted - 1) + responseTime) / agent.metrics.tasksCompleted;
      this.emit("task:completed", { agent, task, result });
      logger.info("Task completed", { agentId, duration: responseTime });
      return result;
    } catch (error) {
      agent.metrics.successRate = agent.metrics.successRate * agent.metrics.tasksCompleted / (agent.metrics.tasksCompleted + 1);
      this.emit("task:failed", { agent, task, error });
      logger.error("Task failed", { agentId, error: error.message });
      throw error;
    }
  }
  async simulateAgentWork(agent) {
    const interval = setInterval(() => {
      if (agent.status !== "running") {
        clearInterval(interval);
        return;
      }
      this.emit("agent:heartbeat", agent);
    }, 5e3);
  }
  async waitForTaskCompletion(agent) {
    return new Promise((resolve) => {
      setTimeout(resolve, 1e3);
    });
  }
  async executeTask(agent, task) {
    await new Promise((resolve) => setTimeout(resolve, Math.random() * 2e3 + 1e3));
    switch (agent.type) {
      case "researcher":
        return {
          success: true,
          findings: [`Research result for: ${task.description || task}`],
          sources: ["source1", "source2"]
        };
      case "developer":
        return {
          success: true,
          code: `// Generated code for: ${task.description || task}
function solution() { return true; }`,
          language: "javascript"
        };
      case "analyst":
        return {
          success: true,
          analysis: `Analysis of: ${task.description || task}`,
          insights: ["insight1", "insight2"],
          recommendations: ["recommendation1"]
        };
      default:
        return {
          success: true,
          result: `Task completed: ${task.description || task}`
        };
    }
  }
}

let messageBus;
let agentManager;
let workflowEngine;
const getMessageBus = () => {
  if (!messageBus) {
    messageBus = MessageBus.getInstance();
  }
  return messageBus;
};
const getAgentManager = () => {
  if (!agentManager) {
    agentManager = new AgentManager();
  }
  return agentManager;
};
const getWorkflowEngine = () => {
  if (!workflowEngine) {
    workflowEngine = new WorkflowEngine();
  }
  return workflowEngine;
};
const createTeamTool = new Tool({
  name: "createTeam",
  description: "Create a new team of agents for a specific goal",
  inputSchema: {
    type: "object",
    properties: {
      teamName: { type: "string" },
      goal: { type: "string" },
      agentTypes: {
        type: "array",
        items: {
          type: "string",
          enum: ["coordinator", "executor", "researcher", "analyst", "architect", "coder", "tester", "documenter", "reviewer", "monitor", "optimizer", "specialist"]
        }
      },
      teamSize: { type: "number", minimum: 1, maximum: 10 }
    },
    required: ["teamName", "goal", "agentTypes"]
  },
  execute: async ({ teamName, goal, agentTypes, teamSize = 3 }) => {
    try {
      const manager = getAgentManager();
      const coordinator = new CoordinatorAgent(teamName);
      await manager.registerAgent(coordinator);
      const teamMembers = [];
      for (const agentType of agentTypes.slice(0, teamSize - 1)) {
        let agent;
        switch (agentType) {
          case "executor":
            agent = new ExecutorAgent(`${teamName}-executor`);
            break;
          default:
            agent = new ExecutorAgent(`${teamName}-${agentType}`);
        }
        await manager.registerAgent(agent);
        teamMembers.push(agent.getId());
      }
      return {
        teamId: coordinator.getId(),
        coordinator: coordinator.getId(),
        members: teamMembers,
        status: "created",
        message: `Team ${teamName} created successfully with ${teamMembers.length + 1} agents`,
        goal
      };
    } catch (error) {
      return {
        status: "error",
        message: `Failed to create team: ${error.message}`
      };
    }
  }
});
const executeWorkflowTool = new Tool({
  name: "executeWorkflow",
  description: "Execute an agentic-flow workflow",
  inputSchema: {
    type: "object",
    properties: {
      workflowId: { type: "string" },
      input: { type: "object" },
      priority: {
        type: "string",
        enum: ["low", "medium", "high", "critical"]
      }
    },
    required: ["workflowId"]
  },
  execute: async ({ workflowId, input = {}, priority = "medium" }) => {
    try {
      const engine = getWorkflowEngine();
      const execution = await engine.executeWorkflow(workflowId, input);
      return {
        executionId: execution.id,
        workflowId: execution.workflowId,
        status: execution.status,
        startTime: execution.startTime,
        priority,
        message: `Workflow ${workflowId} execution started successfully`
      };
    } catch (error) {
      return {
        status: "error",
        message: `Failed to execute workflow: ${error.message}`
      };
    }
  }
});
const sendMessageTool = new Tool({
  name: "sendMessage",
  description: "Send a message through the agentic-flow message bus",
  inputSchema: {
    type: "object",
    properties: {
      type: { type: "string" },
      payload: { type: "object" },
      recipientId: { type: "string" },
      priority: {
        type: "string",
        enum: ["low", "medium", "high", "critical"]
      }
    },
    required: ["type", "payload"]
  },
  execute: async ({ type, payload, recipientId = "broadcast", priority = "medium" }) => {
    try {
      const bus = getMessageBus();
      const message = {
        type,
        senderId: "mastra-integration",
        recipientId,
        payload,
        timestamp: /* @__PURE__ */ new Date(),
        priority
      };
      await bus.publish(message);
      return {
        messageId: `msg-${Date.now()}`,
        status: "sent",
        type,
        recipientId,
        priority,
        message: `Message of type ${type} published successfully`
      };
    } catch (error) {
      return {
        status: "error",
        message: `Failed to send message: ${error.message}`
      };
    }
  }
});
const getAgentStatusTool = new Tool({
  name: "getAgentStatus",
  description: "Get the status of agents in the agentic-flow system",
  inputSchema: {
    type: "object",
    properties: {
      agentId: { type: "string" },
      teamId: { type: "string" },
      includeMetrics: { type: "boolean" }
    }
  },
  execute: async ({ agentId, teamId, includeMetrics = false }) => {
    try {
      const manager = getAgentManager();
      if (agentId) {
        const agent = await manager.getAgent(agentId);
        if (!agent) {
          return { status: "error", message: "Agent not found" };
        }
        return {
          agentId: agent.getId(),
          name: agent.getName(),
          type: agent.getType(),
          status: agent.getStatus(),
          currentTask: agent.getCurrentTask()?.id || null,
          capabilities: agent.getCapabilities(),
          ...includeMetrics && {
            metrics: {
              tasksCompleted: 0,
              // Would need to implement metrics tracking
              averageResponseTime: 0,
              successRate: 1
            }
          }
        };
      } else {
        const agents = await manager.listAgents();
        return {
          totalAgents: agents.length,
          agents: agents.map((agent) => ({
            agentId: agent.getId(),
            name: agent.getName(),
            type: agent.getType(),
            status: agent.getStatus()
          }))
        };
      }
    } catch (error) {
      return {
        status: "error",
        message: `Failed to get agent status: ${error.message}`
      };
    }
  }
});
const createGoalTool = new Tool({
  name: "createGoal",
  description: "Create a new goal in the agentic-flow system",
  inputSchema: {
    type: "object",
    properties: {
      description: { type: "string" },
      priority: {
        type: "string",
        enum: ["low", "medium", "high", "critical"]
      },
      deadline: { type: "string", format: "date-time" },
      assignedTeam: { type: "string" },
      requirements: {
        type: "array",
        items: { type: "string" }
      }
    },
    required: ["description"]
  },
  execute: async ({ description, priority = "medium", deadline, assignedTeam, requirements = [] }) => {
    try {
      const goalId = `goal-${Date.now()}`;
      return {
        goalId,
        description,
        priority,
        deadline,
        assignedTeam,
        requirements,
        status: "created",
        createdAt: (/* @__PURE__ */ new Date()).toISOString(),
        message: "Goal created successfully"
      };
    } catch (error) {
      return {
        status: "error",
        message: `Failed to create goal: ${error.message}`
      };
    }
  }
});
const monitorSystemTool = new Tool({
  name: "monitorSystem",
  description: "Monitor the agentic-flow system health and performance",
  inputSchema: {
    type: "object",
    properties: {
      includeAgents: { type: "boolean" },
      includeWorkflows: { type: "boolean" },
      includeMessages: { type: "boolean" }
    }
  },
  execute: async ({ includeAgents = true, includeWorkflows = true, includeMessages = true }) => {
    try {
      const systemStatus = {
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        status: "healthy",
        uptime: process.uptime(),
        memory: process.memoryUsage()
      };
      if (includeAgents) {
        const manager = getAgentManager();
        const agents = await manager.listAgents();
        systemStatus["agents"] = {
          total: agents.length,
          active: agents.filter((a) => a.getStatus() === "active").length,
          idle: agents.filter((a) => a.getStatus() === "idle").length
        };
      }
      if (includeWorkflows) {
        getWorkflowEngine();
        systemStatus["workflows"] = {
          total: 0,
          running: 0,
          completed: 0,
          failed: 0
        };
      }
      if (includeMessages) {
        getMessageBus();
        systemStatus["messages"] = {
          sent: 0,
          received: 0,
          pending: 0
        };
      }
      return systemStatus;
    } catch (error) {
      return {
        status: "error",
        message: `Failed to monitor system: ${error.message}`
      };
    }
  }
});
const mastraTools = {
  createTeam: createTeamTool,
  executeWorkflow: executeWorkflowTool,
  sendMessage: sendMessageTool,
  getAgentStatus: getAgentStatusTool,
  createGoal: createGoalTool,
  monitorSystem: monitorSystemTool
};

const softwareDevelopmentWorkflow = new Workflow({
  name: "softwareDevelopment",
  description: "Complete software development workflow with research, architecture, coding, testing, and review",
  steps: [
    {
      id: "create-dev-team",
      type: "tool",
      tool: createTeamTool,
      input: {
        teamName: "dev-team-{{timestamp}}",
        goal: "{{requirement}}",
        agentTypes: ["coordinator", "architect", "coder", "tester", "reviewer"],
        teamSize: 5
      }
    },
    {
      id: "research-phase",
      type: "agent",
      agent: researcherAgent,
      prompt: `Research the following requirement and provide insights:
      Requirement: {{requirement}}
      
      Please provide:
      1. Technical feasibility analysis
      2. Similar solutions or patterns
      3. Potential challenges and risks
      4. Recommended technologies or approaches
      5. Timeline estimation`,
      dependsOn: ["create-dev-team"]
    },
    {
      id: "architecture-design",
      type: "agent",
      agent: architectAgent,
      prompt: `Based on the research findings, create a technical architecture:
      Research: {{outputs.research-phase.response}}
      Requirement: {{requirement}}
      
      Please provide:
      1. System architecture diagram (text description)
      2. Component breakdown
      3. Technology stack recommendations
      4. Database design considerations
      5. API design specifications
      6. Scalability and performance considerations`,
      dependsOn: ["research-phase"]
    },
    {
      id: "create-goal",
      type: "tool",
      tool: createGoalTool,
      input: {
        description: "Implement {{requirement}} based on architectural design",
        priority: "high",
        assignedTeam: "{{outputs.create-dev-team.teamId}}",
        requirements: ["{{outputs.architecture-design.response}}"]
      },
      dependsOn: ["architecture-design"]
    },
    {
      id: "implementation",
      type: "agent",
      agent: coderAgent,
      prompt: `Implement the following requirement based on the architecture:
      Architecture: {{outputs.architecture-design.response}}
      Requirement: {{requirement}}
      
      Please provide:
      1. Main implementation code
      2. Configuration files
      3. Database schemas/migrations
      4. API endpoints
      5. Error handling
      6. Documentation comments`,
      dependsOn: ["create-goal"]
    },
    {
      id: "testing",
      type: "agent",
      agent: testerAgent,
      prompt: `Create comprehensive tests for the implementation:
      Implementation: {{outputs.implementation.response}}
      Architecture: {{outputs.architecture-design.response}}
      
      Please provide:
      1. Unit tests
      2. Integration tests
      3. End-to-end test scenarios
      4. Performance test considerations
      5. Edge cases and error scenarios
      6. Test data setup`,
      dependsOn: ["implementation"]
    },
    {
      id: "code-review",
      type: "agent",
      agent: reviewerAgent,
      prompt: `Review the implementation and tests:
      Implementation: {{outputs.implementation.response}}
      Tests: {{outputs.testing.response}}
      Architecture: {{outputs.architecture-design.response}}
      
      Please provide:
      1. Code quality assessment
      2. Architecture adherence review
      3. Security considerations
      4. Performance implications
      5. Maintainability evaluation
      6. Recommendations for improvements`,
      dependsOn: ["testing"]
    },
    {
      id: "notify-completion",
      type: "tool",
      tool: sendMessageTool,
      input: {
        type: "workflow.completed",
        payload: {
          workflowName: "softwareDevelopment",
          requirement: "{{requirement}}",
          teamId: "{{outputs.create-dev-team.teamId}}",
          research: "{{outputs.research-phase.response}}",
          architecture: "{{outputs.architecture-design.response}}",
          implementation: "{{outputs.implementation.response}}",
          testing: "{{outputs.testing.response}}",
          review: "{{outputs.code-review.response}}"
        },
        priority: "high"
      },
      dependsOn: ["code-review"]
    }
  ]
});
const problemSolutionWorkflow = new Workflow({
  name: "problemSolution",
  description: "Analyze problems and create comprehensive solutions",
  steps: [
    {
      id: "problem-analysis",
      type: "agent",
      agent: coordinatorMastraAgent,
      prompt: `Analyze the following problem and break it down:
      Problem: {{problem}}
      
      Please provide:
      1. Problem decomposition into sub-problems
      2. Priority ranking of issues
      3. Dependencies between sub-problems
      4. Resource requirements estimation
      5. Recommended team composition
      6. Success criteria definition`
    },
    {
      id: "create-solution-team",
      type: "tool",
      tool: createTeamTool,
      input: {
        teamName: "solution-team-{{timestamp}}",
        goal: "Solve: {{problem}}",
        agentTypes: ["coordinator", "executor", "researcher", "specialist"],
        teamSize: 4
      },
      dependsOn: ["problem-analysis"]
    },
    {
      id: "solution-design",
      type: "agent",
      agent: executorMastraAgent,
      prompt: `Design a comprehensive solution based on the analysis:
      Analysis: {{outputs.problem-analysis.response}}
      Problem: {{problem}}
      Team: {{outputs.create-solution-team.teamId}}
      
      Please provide:
      1. Detailed solution approach
      2. Step-by-step implementation plan
      3. Risk mitigation strategies
      4. Timeline and milestones
      5. Required resources and tools
      6. Success metrics and KPIs`,
      dependsOn: ["create-solution-team"]
    },
    {
      id: "solution-validation",
      type: "agent",
      agent: reviewerAgent,
      prompt: `Validate the proposed solution:
      Solution: {{outputs.solution-design.response}}
      Original Problem: {{problem}}
      Analysis: {{outputs.problem-analysis.response}}
      
      Please provide:
      1. Solution completeness assessment
      2. Feasibility evaluation
      3. Potential issues identification
      4. Alternative approaches consideration
      5. Recommendations for improvement
      6. Implementation readiness assessment`,
      dependsOn: ["solution-design"]
    },
    {
      id: "monitor-solution",
      type: "tool",
      tool: monitorSystemTool,
      input: {
        includeAgents: true,
        includeWorkflows: true,
        includeMessages: true
      },
      dependsOn: ["solution-validation"]
    },
    {
      id: "notify-solution-ready",
      type: "tool",
      tool: sendMessageTool,
      input: {
        type: "solution.ready",
        payload: {
          problem: "{{problem}}",
          analysis: "{{outputs.problem-analysis.response}}",
          solution: "{{outputs.solution-design.response}}",
          validation: "{{outputs.solution-validation.response}}",
          teamId: "{{outputs.create-solution-team.teamId}}",
          systemStatus: "{{outputs.monitor-solution}}"
        },
        priority: "high"
      },
      dependsOn: ["monitor-solution"]
    }
  ]
});
const agentCoordinationWorkflow = new Workflow({
  name: "agentCoordination",
  description: "Coordinate multiple agents for complex task execution",
  steps: [
    {
      id: "task-decomposition",
      type: "agent",
      agent: coordinatorMastraAgent,
      prompt: `Decompose the following complex task:
      Task: {{complexTask}}
      
      Break it down into:
      1. Individual subtasks
      2. Dependencies between tasks
      3. Agent role assignments
      4. Execution order and timing
      5. Communication requirements
      6. Success criteria for each subtask`
    },
    {
      id: "create-coordination-team",
      type: "tool",
      tool: createTeamTool,
      input: {
        teamName: "coord-team-{{timestamp}}",
        goal: "{{complexTask}}",
        agentTypes: ["coordinator", "executor", "researcher", "analyst", "monitor"],
        teamSize: 5
      },
      dependsOn: ["task-decomposition"]
    },
    {
      id: "parallel-execution-1",
      type: "parallel",
      steps: [
        {
          id: "research-subtask",
          type: "agent",
          agent: researcherAgent,
          prompt: "Research subtask: {{outputs.task-decomposition.subtask1}}"
        },
        {
          id: "analysis-subtask",
          type: "agent",
          agent: coordinatorMastraAgent,
          prompt: "Analyze subtask: {{outputs.task-decomposition.subtask2}}"
        }
      ],
      dependsOn: ["create-coordination-team"]
    },
    {
      id: "execution-coordination",
      type: "agent",
      agent: executorMastraAgent,
      prompt: `Coordinate the execution of parallel results:
      Research Results: {{outputs.parallel-execution-1.research-subtask.response}}
      Analysis Results: {{outputs.parallel-execution-1.analysis-subtask.response}}
      Original Task: {{complexTask}}
      Team: {{outputs.create-coordination-team.teamId}}
      
      Provide:
      1. Integrated execution plan
      2. Resource allocation
      3. Timeline coordination
      4. Quality assurance steps
      5. Communication protocol`,
      dependsOn: ["parallel-execution-1"]
    },
    {
      id: "monitor-progress",
      type: "tool",
      tool: getAgentStatusTool,
      input: {
        teamId: "{{outputs.create-coordination-team.teamId}}",
        includeMetrics: true
      },
      dependsOn: ["execution-coordination"]
    },
    {
      id: "final-coordination",
      type: "tool",
      tool: sendMessageTool,
      input: {
        type: "coordination.completed",
        payload: {
          complexTask: "{{complexTask}}",
          decomposition: "{{outputs.task-decomposition.response}}",
          coordination: "{{outputs.execution-coordination.response}}",
          teamStatus: "{{outputs.monitor-progress}}",
          teamId: "{{outputs.create-coordination-team.teamId}}"
        },
        priority: "high"
      },
      dependsOn: ["monitor-progress"]
    }
  ]
});
const systemMonitoringWorkflow = new Workflow({
  name: "systemMonitoring",
  description: "Monitor system health and generate comprehensive reports",
  steps: [
    {
      id: "initial-health-check",
      type: "tool",
      tool: monitorSystemTool,
      input: {
        includeAgents: true,
        includeWorkflows: true,
        includeMessages: true
      }
    },
    {
      id: "agent-status-check",
      type: "tool",
      tool: getAgentStatusTool,
      input: {
        includeMetrics: true
      },
      dependsOn: ["initial-health-check"]
    },
    {
      id: "health-analysis",
      type: "agent",
      agent: coordinatorMastraAgent,
      prompt: `Analyze the system health data:
      System Status: {{outputs.initial-health-check}}
      Agent Status: {{outputs.agent-status-check}}
      
      Provide:
      1. Overall system health assessment
      2. Performance bottlenecks identification
      3. Agent utilization analysis
      4. Workflow efficiency evaluation
      5. Recommendations for optimization
      6. Alert conditions and thresholds`,
      dependsOn: ["agent-status-check"]
    },
    {
      id: "generate-health-report",
      type: "tool",
      tool: sendMessageTool,
      input: {
        type: "system.health.report",
        payload: {
          timestamp: "{{timestamp}}",
          systemStatus: "{{outputs.initial-health-check}}",
          agentStatus: "{{outputs.agent-status-check}}",
          analysis: "{{outputs.health-analysis.response}}"
        },
        priority: "medium"
      },
      dependsOn: ["health-analysis"]
    }
  ]
});
const mastraWorkflows = {
  softwareDevelopment: softwareDevelopmentWorkflow,
  problemSolution: problemSolutionWorkflow,
  agentCoordination: agentCoordinationWorkflow,
  systemMonitoring: systemMonitoringWorkflow
};

var mastra$1 = mastra;
const server = {
  port: process.env.MASTRA_PORT ? parseInt(process.env.MASTRA_PORT) : 4111,
  baseUrl: process.env.MASTRA_BASE_URL || "http://localhost:4111"
};

export { CoordinatorAgent as C, ExecutorAgent as E, architectAgent as a, coderAgent as b, createMastraAgent as c, reviewerAgent as d, monitorAgent as e, coordinatorMastraAgent as f, executorMastraAgent as g, mastraAgents as h, createTeamTool as i, executeWorkflowTool as j, sendMessageTool as k, getAgentStatusTool as l, mastra$1 as m, createGoalTool as n, monitorSystemTool as o, mastraTools as p, softwareDevelopmentWorkflow as q, researcherAgent as r, server as s, testerAgent as t, problemSolutionWorkflow as u, agentCoordinationWorkflow as v, systemMonitoringWorkflow as w, mastraWorkflows as x };
//# sourceMappingURL=index-54CDt8_U.js.map
