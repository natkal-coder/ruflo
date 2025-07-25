import React, { useState, useMemo, useEffect } from 'react'
import { Search, Terminal, Brain, Database, Activity, Workflow, Github, Settings, ChevronRight, Play, Copy, Check, AlertCircle, Loader } from 'lucide-react'
import { MCPBridge, MCPTool, ToolExecutionResult } from '../../api/mcp-bridge'

// Tool categories - empty initially, will be populated from API
const toolCategories = {
  neural: {
    name: 'Neural Network Tools',
    icon: Brain,
    color: 'text-purple-400',
    tools: [] // Will be populated from API
  },
  memory: {
    name: 'Memory & Persistence',
    icon: Database,
    color: 'text-blue-400',
    tools: [
      { name: 'memory_usage', description: 'Store/retrieve memory', params: [{ name: 'action', type: 'select', options: ['store', 'retrieve', 'list'], required: true }, { name: 'key', type: 'string' }, { name: 'value', type: 'json' }] },
      { name: 'memory_search', description: 'Search memory patterns', params: [{ name: 'query', type: 'string', required: true }] },
      { name: 'memory_clear', description: 'Clear memory storage', params: [{ name: 'pattern', type: 'string' }] },
      { name: 'memory_export', description: 'Export memory database', params: [{ name: 'format', type: 'select', options: ['json', 'sqlite'] }] },
      { name: 'memory_import', description: 'Import memory data', params: [{ name: 'path', type: 'string', required: true }] },
      { name: 'memory_stats', description: 'Memory usage statistics', params: [] },
      { name: 'memory_compact', description: 'Compact memory storage', params: [] },
      { name: 'memory_backup', description: 'Backup memory database', params: [{ name: 'destination', type: 'string' }] },
      { name: 'memory_restore', description: 'Restore memory backup', params: [{ name: 'source', type: 'string', required: true }] },
      { name: 'memory_sync', description: 'Sync memory across agents', params: [] }
    ]
  },
  monitoring: {
    name: 'Monitoring & Analysis',
    icon: Activity,
    color: 'text-green-400',
    tools: [
      { name: 'swarm_monitor', description: 'Monitor swarm activity', params: [{ name: 'interval', type: 'number' }] },
      { name: 'agent_metrics', description: 'Get agent performance metrics', params: [{ name: 'agent_id', type: 'string' }] },
      { name: 'task_status', description: 'Check task progress', params: [{ name: 'task_id', type: 'string' }] },
      { name: 'benchmark_run', description: 'Run performance benchmarks', params: [{ name: 'type', type: 'select', options: ['speed', 'memory', 'tokens'] }] },
      { name: 'bottleneck_detect', description: 'Detect performance bottlenecks', params: [] },
      { name: 'performance_report', description: 'Generate performance report', params: [{ name: 'format', type: 'select', options: ['text', 'json', 'html'] }] },
      { name: 'token_usage', description: 'Analyze token consumption', params: [{ name: 'period', type: 'string' }] },
      { name: 'real_time_view', description: 'Real-time activity monitor', params: [] },
      { name: 'swarm_status', description: 'Get swarm status overview', params: [] },
      { name: 'agent_list', description: 'List active agents', params: [] },
      { name: 'task_results', description: 'View task results', params: [{ name: 'task_id', type: 'string', required: true }] },
      { name: 'error_logs', description: 'View error logs', params: [{ name: 'limit', type: 'number' }] },
      { name: 'metrics_export', description: 'Export metrics data', params: [{ name: 'format', type: 'select', options: ['csv', 'json'] }] }
    ]
  },
  workflow: {
    name: 'Workflow & Automation',
    icon: Workflow,
    color: 'text-yellow-400',
    tools: [
      { name: 'workflow_create', description: 'Create new workflow', params: [{ name: 'name', type: 'string', required: true }, { name: 'steps', type: 'json' }] },
      { name: 'workflow_execute', description: 'Execute workflow', params: [{ name: 'workflow_id', type: 'string', required: true }] },
      { name: 'workflow_export', description: 'Export workflow definition', params: [{ name: 'workflow_id', type: 'string', required: true }] },
      { name: 'auto_agent', description: 'Auto-spawn optimal agents', params: [{ name: 'task', type: 'string', required: true }] },
      { name: 'smart_spawn', description: 'Intelligently spawn agents', params: [{ name: 'context', type: 'string' }] },
      { name: 'workflow_select', description: 'Select best workflow', params: [{ name: 'task', type: 'string', required: true }] },
      { name: 'parallel_execute', description: 'Execute tasks in parallel', params: [{ name: 'tasks', type: 'json', required: true }] },
      { name: 'cache_manage', description: 'Manage workflow cache', params: [{ name: 'action', type: 'select', options: ['clear', 'optimize', 'stats'] }] },
      { name: 'topology_optimize', description: 'Optimize swarm topology', params: [] },
      { name: 'workflow_list', description: 'List available workflows', params: [] },
      { name: 'workflow_delete', description: 'Delete workflow', params: [{ name: 'workflow_id', type: 'string', required: true }] }
    ]
  },
  github: {
    name: 'GitHub Integration',
    icon: Github,
    color: 'text-orange-400',
    tools: [
      { name: 'github_swarm', description: 'Create GitHub management swarm', params: [{ name: 'repository', type: 'string', required: true }, { name: 'agents', type: 'number' }] },
      { name: 'repo_analyze', description: 'Deep repository analysis', params: [{ name: 'deep', type: 'boolean' }, { name: 'include', type: 'json' }] },
      { name: 'pr_enhance', description: 'Enhance pull request', params: [{ name: 'pr_number', type: 'number', required: true }, { name: 'add_tests', type: 'boolean' }] },
      { name: 'issue_triage', description: 'Triage GitHub issues', params: [{ name: 'labels', type: 'json' }] },
      { name: 'code_review', description: 'Automated code review', params: [{ name: 'pr_number', type: 'number', required: true }] },
      { name: 'pr_create', description: 'Create pull request', params: [{ name: 'title', type: 'string', required: true }, { name: 'body', type: 'string' }] },
      { name: 'issue_create', description: 'Create GitHub issue', params: [{ name: 'title', type: 'string', required: true }, { name: 'body', type: 'string' }] },
      { name: 'release_notes', description: 'Generate release notes', params: [{ name: 'tag', type: 'string' }] }
    ]
  },
  system: {
    name: 'System & Utilities',
    icon: Settings,
    color: 'text-cyan-400',
    tools: [
      { name: 'features_detect', description: 'Detect available features', params: [] },
      { name: 'system_info', description: 'Get system information', params: [] },
      { name: 'config_get', description: 'Get configuration', params: [{ name: 'key', type: 'string' }] },
      { name: 'config_set', description: 'Set configuration', params: [{ name: 'key', type: 'string', required: true }, { name: 'value', type: 'json' }] },
      { name: 'version_info', description: 'Get version information', params: [] },
      { name: 'health_check', description: 'System health check', params: [] }
    ]
  },
  coordination: {
    name: 'Swarm Coordination',
    icon: Terminal,
    color: 'text-red-400',
    tools: [
      { name: 'swarm_init', description: 'Initialize swarm topology', params: [{ name: 'topology', type: 'select', options: ['mesh', 'hierarchical', 'ring', 'star'], required: true }, { name: 'maxAgents', type: 'number' }] },
      { name: 'agent_spawn', description: 'Spawn specialized agent', params: [{ name: 'type', type: 'select', options: ['architect', 'coder', 'analyst', 'tester', 'researcher', 'coordinator'], required: true }, { name: 'name', type: 'string' }] },
      { name: 'task_orchestrate', description: 'Orchestrate complex task', params: [{ name: 'task', type: 'string', required: true }, { name: 'strategy', type: 'select', options: ['parallel', 'sequential', 'adaptive'] }] },
      { name: 'swarm_reset', description: 'Reset swarm state', params: [] },
      { name: 'agent_communicate', description: 'Send message between agents', params: [{ name: 'from', type: 'string' }, { name: 'to', type: 'string' }, { name: 'message', type: 'string' }] },
      { name: 'task_split', description: 'Split task into subtasks', params: [{ name: 'task', type: 'string', required: true }] }
    ]
  }
}

interface Tool {
  name: string
  description: string
  params: Array<{
    name: string
    type: string
    required?: boolean
    options?: string[]
  }>
}

const MCPTools: React.FC = () => {
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null)
  const [selectedTool, setSelectedTool] = useState<MCPTool | null>(null)
  const [paramValues, setParamValues] = useState<Record<string, any>>({})
  const [executionResult, setExecutionResult] = useState<ToolExecutionResult | null>(null)
  const [copiedResult, setCopiedResult] = useState(false)
  const [loading, setLoading] = useState(false)
  const [realTools, setRealTools] = useState<MCPTool[]>([])
  const [toolsLoaded, setToolsLoaded] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [executing, setExecuting] = useState(false)
  const [wsConnected, setWsConnected] = useState(false)
  
  // Real MCP Bridge
  const mcpBridge = new MCPBridge()
  
  // Load real MCP tools on component mount
  useEffect(() => {
    const loadTools = async () => {
      setLoading(true)
      setError(null)
      try {
        const tools = await mcpBridge.getAvailableTools()
        setRealTools(tools)
        setToolsLoaded(true)
        console.log(`Loaded ${tools.length} real MCP tools`, tools)
        // Log tool names to debug
        console.log('Tool names:', tools.map(t => t.name))
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load MCP tools')
        console.error('Failed to load MCP tools:', err)
      } finally {
        setLoading(false)
      }
    }
    
    loadTools()
    
    // Check WebSocket connection status periodically
    const checkWsStatus = setInterval(() => {
      setWsConnected(mcpBridge.isWebSocketConnected())
    }, 1000)
    
    return () => clearInterval(checkWsStatus)
  }, [])
  
  // Helper function to get category info
  const getCategoryInfo = (category: string) => {
    const categoryMap: Record<string, any> = {
      coordination: { name: 'Swarm Coordination', icon: Terminal, color: 'text-red-400' },
      monitoring: { name: 'Monitoring & Analysis', icon: Activity, color: 'text-green-400' },
      memory: { name: 'Memory & Persistence', icon: Database, color: 'text-blue-400' },
      neural: { name: 'Neural Network Tools', icon: Brain, color: 'text-purple-400' },
      github: { name: 'GitHub Integration', icon: Github, color: 'text-orange-400' },
      workflow: { name: 'Workflow & Automation', icon: Workflow, color: 'text-yellow-400' },
      system: { name: 'System & Utilities', icon: Settings, color: 'text-cyan-400' },
      daa: { name: 'Dynamic Agent Architecture', icon: Terminal, color: 'text-pink-400' },
      sparc: { name: 'SPARC Development', icon: Terminal, color: 'text-indigo-400' }
    }
    return categoryMap[category] || { name: category, icon: Terminal, color: 'text-gray-400' }
  }
  
  // Helper function to convert MCP parameters to component params
  const convertParametersToParams = (parameters: any) => {
    if (!parameters || !parameters.properties) return []
    
    return Object.entries(parameters.properties).map(([name, prop]: [string, any]) => ({
      name,
      type: prop.type === 'array' ? 'json' : prop.type,
      required: parameters.required?.includes(name),
      options: prop.enum
    }))
  }
  
  // Convert real tools to categories for display
  const realToolCategories = useMemo(() => {
    if (!toolsLoaded || realTools.length === 0) return toolCategories
    
    console.log('Building realToolCategories from', realTools.length, 'tools')
    const categories: typeof toolCategories = {}
    
    // Group real tools by category
    const toolsByCategory: Record<string, MCPTool[]> = {}
    for (const tool of realTools) {
      if (!toolsByCategory[tool.category]) {
        toolsByCategory[tool.category] = []
      }
      toolsByCategory[tool.category].push(tool)
    }
    
    // Map to category structure
    for (const [category, tools] of Object.entries(toolsByCategory)) {
      const categoryInfo = getCategoryInfo(category)
      categories[category as keyof typeof toolCategories] = {
        name: categoryInfo.name,
        icon: categoryInfo.icon,
        color: categoryInfo.color,
        tools: tools.map(tool => ({
          name: tool.name,
          description: tool.description,
          params: convertParametersToParams(tool.parameters)
        }))
      }
    }
    
    return categories
  }, [realTools, toolsLoaded])

  // Filter tools based on search (use real tools if available)
  const filteredCategories = useMemo(() => {
    const categoriesToFilter = toolsLoaded ? realToolCategories : toolCategories
    if (!searchQuery) return categoriesToFilter

    const filtered: typeof toolCategories = {}
    
    Object.entries(categoriesToFilter).forEach(([key, category]) => {
      const matchingTools = category.tools.filter(tool => 
        tool.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        tool.description.toLowerCase().includes(searchQuery.toLowerCase())
      )
      
      if (matchingTools.length > 0 || category.name.toLowerCase().includes(searchQuery.toLowerCase())) {
        filtered[key as keyof typeof toolCategories] = {
          ...category,
          tools: matchingTools.length > 0 ? matchingTools : category.tools
        }
      }
    })
    
    return filtered
  }, [searchQuery, toolsLoaded, realToolCategories])

  // Count total tools
  const categoriesToCount = toolsLoaded ? realToolCategories : toolCategories
  const totalTools = Object.values(categoriesToCount).reduce((sum, cat) => sum + cat.tools.length, 0)
  const filteredToolsCount = Object.values(filteredCategories).reduce((sum, cat) => sum + cat.tools.length, 0)

  const handleToolSelect = (tool: any, categoryKey: string) => {
    // Find the real MCP tool
    const realTool = realTools.find(t => t.name === tool.name)
    if (realTool) {
      // Add params property for the UI
      setSelectedTool({
        ...realTool,
        params: convertParametersToParams(realTool.parameters)
      } as any)
    } else {
      // Fallback to mock tool structure
      setSelectedTool({
        name: tool.name,
        description: tool.description,
        parameters: { properties: {}, required: [] },
        params: tool.params || [],
        category: categoryKey as any
      } as any)
    }
    setSelectedCategory(categoryKey)
    setParamValues({})
    setExecutionResult(null)
    setError(null)
  }

  const handleParamChange = (paramName: string, value: any) => {
    setParamValues(prev => ({ ...prev, [paramName]: value }))
  }

  const handleExecute = async () => {
    if (!selectedTool) return
    
    setExecuting(true)
    setError(null)
    setExecutionResult(null)
    setCopiedResult(false)
    
    try {
      // Validate parameters
      const validation = await mcpBridge.validateParameters(selectedTool.name, paramValues)
      if (!validation.valid) {
        setError(`Parameter validation failed: ${validation.errors?.join(', ')}`)
        return
      }
      
      // Execute the real MCP tool
      const result = await mcpBridge.executeTool(selectedTool.name, paramValues, {
        trackMetrics: true,
        cacheResult: true
      })
      
      setExecutionResult(result)
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Tool execution failed')
      console.error('Tool execution error:', err)
    } finally {
      setExecuting(false)
    }
  }

  const handleCopyResult = () => {
    if (executionResult) {
      const resultText = formatExecutionResult(executionResult)
      navigator.clipboard.writeText(resultText)
      setCopiedResult(true)
      setTimeout(() => setCopiedResult(false), 2000)
    }
  }
  
  const formatExecutionResult = (result: ToolExecutionResult): string => {
    const status = result.success ? 'SUCCESS' : 'FAILED'
    const statusIcon = result.success ? '✅' : '❌'
    
    return `
╔════════════════════════════════════════════════════════════════╗
║ MCP TOOL EXECUTION RESULT                                      ║
╠════════════════════════════════════════════════════════════════╣
║ Tool: mcp__claude-flow__${selectedTool?.name}                  ║
║ Category: ${selectedCategory}                                   ║
║ Status: ${status} ${statusIcon}                                ║
║ Execution Time: ${result.executionTime}ms                      ║
║                                                                ║
║ Parameters:                                                    ║
${Object.entries(paramValues).map(([key, value]) => 
  `║   ${key}: ${JSON.stringify(value)}`.slice(0, 64).padEnd(65) + '║'
).join('\n')}
║                                                                ║
║ ${result.success ? 'Output:' : 'Error:'}                                                       ║
║   ${(result.success ? JSON.stringify(result.data, null, 2) : result.error || 'Unknown error')
  .split('\n').map(line => line.slice(0, 60).padEnd(60)).join(' ║\n║   ')} ║
║                                                                ║
║ Metadata:                                                      ║
${result.metadata ? Object.entries(result.metadata).map(([key, value]) => 
  `║   ${key}: ${String(value)}`.slice(0, 64).padEnd(65) + '║'
).join('\n') : '║   None                                                         ║'}
║                                                                ║
║ Timestamp: ${result.metadata?.timestamp || new Date().toISOString()}         ║
╚════════════════════════════════════════════════════════════════╝
    `.trim()
  }

  return (
    <div className="h-screen flex flex-col bg-black">
      <div className="flex-1 p-4 md:p-6 overflow-hidden flex flex-col">
        {/* Header */}
        <div className="mb-4 md:mb-6 flex-shrink-0">
        <h1 className="text-2xl font-bold mb-2 glitch" data-text="MCP TOOLS INTERFACE">
          MCP TOOLS INTERFACE
        </h1>
        <div className="flex items-center justify-between">
          <p className="text-green-600 text-sm">
            {totalTools}+ {toolsLoaded ? 'Real ' : ''}Claude Flow MCP Tools • {Object.keys(filteredCategories).length} Categories
          </p>
          {loading && (
            <div className="flex items-center gap-2 text-yellow-400 text-sm">
              <Loader className="w-3 h-3 animate-spin" />
              Loading real MCP tools...
            </div>
          )}
          {toolsLoaded && (
            <div className="flex items-center gap-4">
              <div className="text-green-400 text-sm">
                ✅ {realTools.length} real tools loaded
              </div>
              <div className={`text-sm flex items-center gap-2 ${wsConnected ? 'text-green-400' : 'text-yellow-400'}`}>
                <div className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-green-400' : 'bg-yellow-400'} ${wsConnected ? '' : 'animate-pulse'}`} />
                {wsConnected ? 'WebSocket Connected' : 'HTTP Fallback Mode'}
              </div>
            </div>
          )}
        </div>
        {error && (
          <div className="mt-2 p-2 bg-red-900/30 border border-red-400 text-red-400 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4" />
            {error}
          </div>
        )}
      </div>

      {/* Search Bar */}
      <div className="mb-4 flex-shrink-0">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-green-600 w-4 h-4" />
          <input
            type="text"
            placeholder="Search tools..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-black border border-green-900 text-green-400 focus:border-green-400"
          />
          {searchQuery && (
            <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-green-600 text-xs">
              {filteredToolsCount} tools found
            </div>
          )}
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col lg:flex-row gap-4 overflow-hidden min-h-0">
        {/* Categories and Tools List */}
        <div className="w-full lg:w-1/2 overflow-y-auto retro-panel h-full">
          <div className="space-y-4 p-4">
            {Object.entries(searchQuery ? filteredCategories : (toolsLoaded ? realToolCategories : toolCategories)).map(([key, category]) => {
              const Icon = category.icon
              return (
                <div key={key} className="border border-green-900">
                  <div className={`p-3 bg-green-950/30 flex items-center gap-2 ${category.color}`}>
                    <Icon className="w-4 h-4" />
                    <span className="font-bold text-sm">{category.name}</span>
                    <span className="text-xs text-green-600 ml-auto">{category.tools.length} tools</span>
                  </div>
                  <div className="p-2 space-y-1">
                    {category.tools.map((tool) => (
                      <button
                        key={tool.name}
                        onClick={() => handleToolSelect(tool, key)}
                        className={`w-full text-left px-3 py-2 text-sm transition-all ${
                          selectedTool?.name === tool.name
                            ? 'bg-green-900/30 text-green-400 border-l-2 border-green-400'
                            : 'text-green-600 hover:bg-green-950/30 hover:text-green-400'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono">{tool.name}</span>
                          <ChevronRight className="w-3 h-3" />
                        </div>
                        <div className="text-xs text-green-700 mt-1">{tool.description}</div>
                      </button>
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Tool Details and Execution */}
        <div className="w-full lg:w-1/2 overflow-y-auto retro-panel h-full">
          {selectedTool ? (
            <div className="space-y-4 p-4">
              {/* Tool Header */}
              <div className="border-b border-green-900 pb-4">
                <h2 className="text-lg font-bold text-green-400 mb-2">
                  mcp__claude-flow__{selectedTool.name}
                </h2>
                <p className="text-sm text-green-600">{selectedTool.description}</p>
              </div>

              {/* Parameters */}
              {selectedTool.params && selectedTool.params.length > 0 ? (
                <div className="space-y-3">
                  <h3 className="text-sm font-bold text-green-400">Parameters:</h3>
                  {selectedTool.params.map((param) => (
                    <div key={param.name} className="space-y-1">
                      <label className="text-xs text-green-600">
                        {param.name} {param.required && <span className="text-red-400">*</span>}
                      </label>
                      {param.type === 'select' && param.options ? (
                        <select
                          value={paramValues[param.name] || ''}
                          onChange={(e) => handleParamChange(param.name, e.target.value)}
                          className="w-full px-2 py-1 bg-black border border-green-900 text-green-400"
                        >
                          <option value="">Select {param.name}</option>
                          {param.options.map(opt => (
                            <option key={opt} value={opt}>{opt}</option>
                          ))}
                        </select>
                      ) : param.type === 'boolean' ? (
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={paramValues[param.name] || false}
                            onChange={(e) => handleParamChange(param.name, e.target.checked)}
                            className="w-4 h-4"
                          />
                          <span className="text-sm text-green-400">Enable</span>
                        </label>
                      ) : param.type === 'number' ? (
                        <input
                          type="number"
                          value={paramValues[param.name] || ''}
                          onChange={(e) => handleParamChange(param.name, parseInt(e.target.value))}
                          className="w-full px-2 py-1 bg-black border border-green-900 text-green-400"
                          placeholder={`Enter ${param.name}`}
                        />
                      ) : param.type === 'json' ? (
                        <textarea
                          value={paramValues[param.name] || ''}
                          onChange={(e) => handleParamChange(param.name, e.target.value)}
                          className="w-full px-2 py-1 bg-black border border-green-900 text-green-400 font-mono text-xs"
                          rows={3}
                          placeholder={`Enter JSON for ${param.name}`}
                        />
                      ) : (
                        <input
                          type="text"
                          value={paramValues[param.name] || ''}
                          onChange={(e) => handleParamChange(param.name, e.target.value)}
                          className="w-full px-2 py-1 bg-black border border-green-900 text-green-400"
                          placeholder={`Enter ${param.name}`}
                        />
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-green-600">This tool has no parameters</p>
              )}

              {/* Execute Button */}
              <button
                onClick={handleExecute}
                disabled={executing || !selectedTool}
                className={`w-full px-4 py-2 border border-green-400 flex items-center justify-center gap-2 transition-all ${
                  executing 
                    ? 'bg-yellow-900/30 text-yellow-400 border-yellow-400' 
                    : 'bg-green-900/30 text-green-400 hover:bg-green-900/50'
                } ${(!selectedTool || executing) ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                {executing ? (
                  <>
                    <Loader className="w-4 h-4 animate-spin" />
                    Executing...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    Execute Tool
                  </>
                )}
              </button>

              {/* Execution Result */}
              {executionResult && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h3 className={`text-sm font-bold ${executionResult.success ? 'text-green-400' : 'text-red-400'}`}>
                      Execution Result: {executionResult.success ? '✅ SUCCESS' : '❌ FAILED'}
                    </h3>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-green-600">{executionResult.executionTime}ms</span>
                      <button
                        onClick={handleCopyResult}
                        className="px-2 py-1 text-xs border border-green-900 text-green-600 hover:text-green-400 hover:border-green-400 flex items-center gap-1"
                      >
                        {copiedResult ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                        {copiedResult ? 'Copied!' : 'Copy'}
                      </button>
                    </div>
                  </div>
                  
                  {/* Success Result */}
                  {executionResult.success && (
                    <div className="p-3 bg-green-950/30 border border-green-400 rounded">
                      <div className="text-green-400 text-xs font-mono">
                        <div className="mb-2 font-bold">Output:</div>
                        <pre className="whitespace-pre-wrap overflow-x-auto">
                          {typeof executionResult.data === 'string' 
                            ? executionResult.data 
                            : JSON.stringify(executionResult.data, null, 2)}
                        </pre>
                      </div>
                      {executionResult.metadata && (
                        <div className="mt-3 pt-2 border-t border-green-800 text-green-600 text-xs">
                          <div className="font-bold mb-1">Metadata:</div>
                          {Object.entries(executionResult.metadata).map(([key, value]) => (
                            <div key={key} className="flex justify-between">
                              <span>{key}:</span>
                              <span>{String(value)}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                  
                  {/* Error Result */}
                  {!executionResult.success && (
                    <div className="p-3 bg-red-950/30 border border-red-400 rounded">
                      <div className="text-red-400 text-xs">
                        <div className="font-bold mb-2">Error:</div>
                        <div className="bg-red-900/30 p-2 rounded font-mono">
                          {executionResult.error || 'Unknown error occurred'}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="h-full flex items-center justify-center text-center p-4">
              <div className="space-y-2">
                <Terminal className="w-12 h-12 text-green-600 mx-auto animate-pulse" />
                <p className="text-green-600">Select a tool to view details and execute</p>
                <p className="text-xs text-green-700">
                  {filteredToolsCount} tools available across {Object.keys(filteredCategories).length} categories
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
      </div>
    </div>
  )
}

export default MCPTools