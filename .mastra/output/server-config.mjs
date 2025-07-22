var mastra$1 = mastra;
const server = {
  port: process.env.MASTRA_PORT ? parseInt(process.env.MASTRA_PORT) : 4111,
  baseUrl: process.env.MASTRA_BASE_URL || "http://localhost:4111"
};

export { mastra$1 as default, server };
//# sourceMappingURL=server-config.mjs.map
