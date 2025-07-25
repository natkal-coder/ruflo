import React, { useState, useMemo, useEffect, useCallback, useRef } from 'react'
import { Search, Terminal, Brain, Database, Activity, Workflow, Github, Settings, ChevronRight, Play, Copy, Check, AlertCircle, Loader, Wifi, WifiOff, Zap } from 'lucide-react'
import { getMCPBridge, MCPBridge, MCPTool, ToolExecutionResult } from '../../api/mcp-bridge'

// Tool categories - empty initially, will be populated from WebSocket
const toolCategories = {
  neural: {
    name: 'Neural Network Tools',
    icon: Brain,
    color: 'text-purple-400',
    tools: [] // Will be populated from WebSocket
  },
  memory: {
    name: 'Memory & Persistence',
    icon: Database,
    color: 'text-blue-400',
    tools: []
  },
  monitoring: {
    name: 'Monitoring & Analysis',
    icon: Activity,
    color: 'text-green-400',
    tools: []
  },
  workflow: {
    name: 'Workflow & Automation',
    icon: Workflow,
    color: 'text-yellow-400',
    tools: []
  },
  github: {
    name: 'GitHub Integration',
    icon: Github,
    color: 'text-orange-400',
    tools: []
  },
  system: {
    name: 'System & Utilities',
    icon: Settings,
    color: 'text-cyan-400',
    tools: []
  }
}

export default function MCPToolsWebSocket() {
  const [selectedCategory, setSelectedCategory] = useState<string>('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedTool, setSelectedTool] = useState<MCPTool | null>(null)
  const [toolParameters, setToolParameters] = useState<Record<string, any>>({})
  const [executionResult, setExecutionResult] = useState<ToolExecutionResult | null>(null)
  const [isExecuting, setIsExecuting] = useState(false)
  const [copied, setCopied] = useState(false)
  const [loading, setLoading] = useState(true)
  const [realTools, setRealTools] = useState<MCPTool[]>([])
  const [toolsLoaded, setToolsLoaded] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [executing, setExecuting] = useState(false)
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'connecting'>('disconnected')
  const [streamingProgress, setStreamingProgress] = useState<string[]>([])
  
  // Refs for scrollable panels
  const detailsRef = useRef<HTMLDivElement>(null)
  const toolListRef = useRef<HTMLDivElement>(null)
  
  // MCP Bridge (WebSocket + HTTP fallback)
  const [mcpBridge] = useState(() => getMCPBridge())
  
  // Set up WebSocket connection and load tools
  useEffect(() => {
    const connectAndLoadTools = async () => {
      setLoading(true)
      setError(null)
      setConnectionStatus('connecting')
      
      try {
        // Try to connect to WebSocket (with HTTP fallback)
        if (!mcpBridge.isWebSocketConnected()) {
          try {
            await mcpBridge.reconnectWebSocket()
            console.log('WebSocket connection established')
          } catch (wsError) {
            // WebSocket failed, HTTP fallback will be used automatically
          }
        }
        
        // Load tools (works with both WebSocket and HTTP)
        const tools = await mcpBridge.getAvailableTools()
        setRealTools(tools)
        setToolsLoaded(true)
        setConnectionStatus(mcpBridge.isWebSocketConnected() ? 'connected' : 'disconnected')
        console.log(`Loaded ${tools.length} MCP tools`, { websocket: mcpBridge.isWebSocketConnected() })
      } catch (error) {
        console.error('Failed to load MCP tools:', error)
        setError(`Failed to load tools: ${error.message}`)
        setConnectionStatus('disconnected')
      } finally {
        setLoading(false)
      }
    }
    
    connectAndLoadTools()
  }, [mcpBridge])
  
  // Scroll to top when a tool is selected
  useEffect(() => {
    if (selectedTool && detailsRef.current) {
      detailsRef.current.scrollTop = 0
    }
  }, [selectedTool])

  // Scroll tool list to top when category changes
  useEffect(() => {
    if (toolListRef.current) {
      toolListRef.current.scrollTop = 0
    }
  }, [selectedCategory])
  
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
      daa: { name: 'Dynamic Agent Architecture', icon: Zap, color: 'text-pink-400' },
      sparc: { name: 'SPARC Development', icon: Terminal, color: 'text-indigo-400' }
    }
    return categoryMap[category] || { name: category, icon: Settings, color: 'text-gray-400' }
  }

  // Get unique categories from loaded tools
  const categories = useMemo(() => {
    const cats = ['all', ...new Set(realTools.map(tool => tool.category))]
    return cats
  }, [realTools])

  // Filter tools based on search and category
  const filteredTools = useMemo(() => {
    return realTools.filter(tool => {
      const matchesSearch = tool.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          tool.description.toLowerCase().includes(searchTerm.toLowerCase())
      const matchesCategory = selectedCategory === 'all' || tool.category === selectedCategory
      return matchesSearch && matchesCategory
    })
  }, [realTools, searchTerm, selectedCategory])

  // Execute a tool
  const executeTool = useCallback(async (tool: MCPTool, parameters: Record<string, any>) => {
    setIsExecuting(true)
    setExecutionResult(null)
    setStreamingProgress([])
    
    try {
      const result = await mcpBridge.executeTool(tool.name, parameters)
      setExecutionResult(result)
      
      if (result.success) {
        setStreamingProgress(prev => [...prev, `✅ Tool executed successfully in ${result.executionTime}ms`])
      } else {
        setStreamingProgress(prev => [...prev, `❌ Tool execution failed: ${result.error}`])
      }
    } catch (error) {
      setExecutionResult({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        executionTime: 0
      })
      setStreamingProgress(prev => [...prev, `❌ Execution error: ${error.message}`])
    } finally {
      setIsExecuting(false)
    }
  }, [mcpBridge])

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (loading) {
    return (
      <div className="bg-black border border-green-500 rounded-lg p-6">
        <div className="flex items-center justify-center py-8">
          <Loader className="w-6 h-6 text-green-400 animate-spin mr-3" />
          <span className="text-green-400">Loading MCP tools...</span>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-black border border-red-500 rounded-lg p-6">
        <div className="flex items-center justify-center py-8">
          <AlertCircle className="w-6 h-6 text-red-400 mr-3" />
          <span className="text-red-400">{error}</span>
        </div>
      </div>
    )
  }

  return (
    <div className="h-full flex flex-col bg-black">
      <div className="flex-1 p-4 overflow-hidden flex flex-col">
        <div className="bg-black border border-green-500 rounded-lg overflow-hidden flex-1 flex flex-col">
          {/* Header */}
          <div className="bg-green-500/10 border-b border-green-500 p-4 flex-shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <Terminal className="w-6 h-6 text-green-400 mr-3" />
            <h2 className="text-xl font-bold text-green-400">MCP Tools WebSocket</h2>
            <div className="ml-4 flex items-center">
              {connectionStatus === 'connected' ? (
                <div className="flex items-center text-green-400">
                  <Wifi className="w-4 h-4 mr-1" />
                  <span className="text-sm">Connected</span>
                </div>
              ) : connectionStatus === 'connecting' ? (
                <div className="flex items-center text-yellow-400">
                  <Loader className="w-4 h-4 mr-1 animate-spin" />
                  <span className="text-sm">Connecting...</span>
                </div>
              ) : (
                <div className="flex items-center text-red-400">
                  <WifiOff className="w-4 h-4 mr-1" />
                  <span className="text-sm">HTTP Fallback</span>
                </div>
              )}
            </div>
          </div>
          <div className="text-sm text-green-400">
            {toolsLoaded ? `${realTools.length} tools loaded` : 'Loading...'}
          </div>
        </div>
      </div>

      <div className="flex flex-col lg:flex-row flex-1 min-h-0">
        {/* Left Panel - Tool List */}
        <div className="w-full lg:w-1/2 lg:border-r border-green-500 flex flex-col h-1/2 lg:h-full">
          {/* Search and Category Filter */}
          <div className="p-4 border-b border-green-500/30 flex-shrink-0">
            <div className="mb-3">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-green-600" />
                <input
                  type="text"
                  placeholder="Search tools..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full bg-black border border-green-600 rounded pl-10 pr-4 py-2 text-green-400 placeholder-green-600 focus:outline-none focus:border-green-400"
                />
              </div>
            </div>
            
            <div className="flex flex-wrap gap-2">
              {categories.map(category => {
                const categoryInfo = category === 'all' 
                  ? { name: 'All Tools', icon: Terminal, color: 'text-green-400' }
                  : getCategoryInfo(category)
                
                return (
                  <button
                    key={category}
                    onClick={() => setSelectedCategory(category)}
                    className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                      selectedCategory === category
                        ? 'bg-green-500/20 text-green-400 border border-green-500'
                        : 'bg-black border border-green-600 text-green-600 hover:text-green-400 hover:border-green-400'
                    }`}
                  >
                    {categoryInfo.name}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Tool List */}
          <div className="flex-1 overflow-y-auto" ref={toolListRef}>
            {filteredTools.map((tool, index) => {
              const categoryInfo = getCategoryInfo(tool.category)
              const IconComponent = categoryInfo.icon
              
              return (
                <div
                  key={`${tool.category}-${tool.name}-${index}`}
                  onClick={() => setSelectedTool(tool)}
                  className={`p-3 border-b border-green-500/20 cursor-pointer transition-colors hover:bg-green-500/10 ${
                    selectedTool?.name === tool.name ? 'bg-green-500/20' : ''
                  }`}
                >
                  <div className="flex items-start">
                    <IconComponent className={`w-4 h-4 ${categoryInfo.color} mt-1 mr-3 flex-shrink-0`} />
                    <div className="flex-1 min-w-0">
                      <div className="font-mono text-sm text-green-400 truncate">
                        {tool.name.replace('mcp__claude-flow__', '')}
                      </div>
                      <div className="text-xs text-green-600 mt-1 line-clamp-2">
                        {tool.description}
                      </div>
                      <div className="flex items-center mt-2">
                        <span className={`px-2 py-1 rounded text-xs ${categoryInfo.color} bg-black border`}>
                          {categoryInfo.name}
                        </span>
                      </div>
                    </div>
                    <ChevronRight className="w-4 h-4 text-green-600 flex-shrink-0" />
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Right Panel - Tool Details */}
        <div className="w-full lg:w-1/2 flex flex-col h-1/2 lg:h-full border-t lg:border-t-0 border-green-500" ref={detailsRef}>
          {selectedTool ? (
            <>
              {/* Tool Header */}
              <div className="p-4 border-b border-green-500/30 flex-shrink-0">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-mono text-lg text-green-400">
                    {selectedTool.name.replace('mcp__claude-flow__', '')}
                  </h3>
                  <button
                    onClick={() => copyToClipboard(selectedTool.name)}
                    className="p-1 text-green-600 hover:text-green-400 transition-colors"
                  >
                    {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
                <p className="text-sm text-green-600 mb-3">{selectedTool.description}</p>
                
                {/* Tool Parameters */}
                {selectedTool.parameters && Object.keys(selectedTool.parameters).length > 0 && (
                  <div className="space-y-3">
                    <h4 className="text-sm font-medium text-green-400">Parameters:</h4>
                    {Object.entries(selectedTool.parameters).map(([param, config]: [string, any]) => (
                      <div key={param} className="space-y-1">
                        <label className="block text-xs text-green-400">{param}</label>
                        <input
                          type="text"
                          placeholder={config.default || `Enter ${param}...`}
                          value={toolParameters[param] || ''}
                          onChange={(e) => setToolParameters(prev => ({
                            ...prev,
                            [param]: e.target.value
                          }))}
                          className="w-full bg-black border border-green-600 rounded px-3 py-1 text-green-400 text-sm placeholder-green-600 focus:outline-none focus:border-green-400"
                        />
                        {config.description && (
                          <p className="text-xs text-green-600">{config.description}</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
                
                {/* Execute Button */}
                <button
                  onClick={() => executeTool(selectedTool, toolParameters)}
                  disabled={isExecuting}
                  className="w-full mt-4 bg-green-500/20 border border-green-500 text-green-400 py-2 px-4 rounded font-medium hover:bg-green-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center"
                >
                  {isExecuting ? (
                    <>
                      <Loader className="w-4 h-4 mr-2 animate-spin" />
                      Executing...
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4 mr-2" />
                      Execute Tool
                    </>
                  )}
                </button>
              </div>

              {/* Execution Results */}
              <div className="flex-1 overflow-y-auto p-4">
                {streamingProgress.length > 0 && (
                  <div className="mb-4">
                    <h4 className="text-sm font-medium text-green-400 mb-2">Progress:</h4>
                    <div className="bg-black border border-green-600 rounded p-3 space-y-1">
                      {streamingProgress.map((message, index) => (
                        <div key={index} className="text-xs text-green-600 font-mono">
                          {message}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {executionResult && (
                  <div>
                    <h4 className="text-sm font-medium text-green-400 mb-2">Result:</h4>
                    <div className={`border rounded p-3 ${
                      executionResult.success 
                        ? 'border-green-500 bg-green-500/10' 
                        : 'border-red-500 bg-red-500/10'
                    }`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className={`text-xs font-medium ${
                          executionResult.success ? 'text-green-400' : 'text-red-400'
                        }`}>
                          {executionResult.success ? '✅ Success' : '❌ Error'}
                        </span>
                        <span className="text-xs text-green-600">
                          {executionResult.executionTime}ms
                        </span>
                      </div>
                      
                      {executionResult.success ? (
                        <pre className="text-xs text-green-400 whitespace-pre-wrap overflow-x-auto">
                          {typeof executionResult.data === 'string' 
                            ? executionResult.data 
                            : JSON.stringify(executionResult.data, null, 2)}
                        </pre>
                      ) : (
                        <div className="text-xs text-red-400">
                          {executionResult.error}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center">
                <Terminal className="w-12 h-12 text-green-600 mx-auto mb-4" />
                <p className="text-green-600">Select a tool to view details and execute</p>
              </div>
            </div>
          )}
        </div>
      </div>
        </div>
      </div>
    </div>
  )
}