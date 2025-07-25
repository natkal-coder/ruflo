import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react'
import { io, Socket } from 'socket.io-client'
import { Play, Pause, RefreshCw, Zap, Copy, Check, ChevronDown, BookOpen, Code, FileText, Layers, Search, Filter, X } from 'lucide-react'
import SwarmVisualizer from './SwarmVisualizer'
import SwarmVisualizerInline from './SwarmVisualizerInline'
import useRealTimeStore from '../../stores/realTimeStore'

interface StreamEvent {
  type: string
  subtype?: string
  message?: any
  session_id?: string
  parent_tool_use_id?: string | null
  [key: string]: any
}

interface AgentStatus {
  id: string
  name: string
  type: string
  status: string
  taskCount: number
}

interface SwarmStatus {
  id: string
  topology: string
  maxAgents: number
  activeAgents: number
  status: string
}

interface CommandTemplate {
  name: string
  filename: string
  path: string
  content: string
  size: number
}

interface CommandTemplates {
  [category: string]: CommandTemplate[]
}

interface ClaudeFlowProps {
  tabId?: string
  tabName?: string
  onTabNameChange?: (name: string) => void
  onStateChange?: (updates: any) => void
  initialState?: {
    command: string
    streamEvents: any[]
    currentSwarm: any
    agents: any[]
    todos: any[]
    isStreaming: boolean
  }
}

const ClaudeFlow: React.FC<ClaudeFlowProps> = ({ 
  tabId, 
  tabName, 
  onTabNameChange, 
  onStateChange,
  initialState 
}) => {
  const [socket, setSocket] = useState<Socket | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const [isStreaming, setIsStreaming] = useState(initialState?.isStreaming || false)
  const [streamEvents, setStreamEvents] = useState<StreamEvent[]>(initialState?.streamEvents || [])
  const [command, setCommand] = useState(initialState?.command || 'test a concurrent agent swarm to research and build a simple hello world in ./hello/')
  const [selectedTemplate, setSelectedTemplate] = useState<CommandTemplate | null>(null)
  const [currentSwarm, setCurrentSwarm] = useState<SwarmStatus | null>(initialState?.currentSwarm || null)
  const [agents, setAgents] = useState<AgentStatus[]>(initialState?.agents || [])
  const [todos, setTodos] = useState<any[]>(initialState?.todos || [])
  const [copied, setCopied] = useState(false)
  const [commandTemplates, setCommandTemplates] = useState<CommandTemplates>({})
  const [loadingTemplates, setLoadingTemplates] = useState(false)
  const [showCommandDropdown, setShowCommandDropdown] = useState(false)
  const [isAtBottom, setIsAtBottom] = useState(true)
  const [userHasScrolled, setUserHasScrolled] = useState(false)
  const [showTemplateDetails, setShowTemplateDetails] = useState(true)
  const [showCommandPreview, setShowCommandPreview] = useState(true)
  const [copiedEventId, setCopiedEventId] = useState<string | null>(null)
  const [showRawJson, setShowRawJson] = useState(false)
  const [showSwarmVisualizer, setShowSwarmVisualizer] = useState(false)
  const [streamSearch, setStreamSearch] = useState('')
  const [selectedEventTypes, setSelectedEventTypes] = useState<Set<string>>(new Set())
  const [showFilters, setShowFilters] = useState(false)
  const streamRef = useRef<HTMLDivElement>(null)
  const abortControllerRef = useRef<AbortController | null>(null)
  const dropdownRef = useRef<HTMLDivElement>(null)
  
  // Access real-time store
  const { handleUpdate, updateState, connect } = useRealTimeStore()

  // Load command templates from server
  const loadCommandTemplates = async () => {
    if (Object.keys(commandTemplates).length > 0) return // Already loaded
    
    setLoadingTemplates(true)
    try {
      const response = await fetch('/api/commands/templates')
      const data = await response.json()
      
      if (data.templates) {
        setCommandTemplates(data.templates)
      }
    } catch (error) {
      console.error('Failed to load command templates:', error)
    } finally {
      setLoadingTemplates(false)
    }
  }

  // Handle click outside dropdown
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setShowCommandDropdown(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Load templates when dropdown is opened
  useEffect(() => {
    if (showCommandDropdown) {
      loadCommandTemplates()
    }
  }, [showCommandDropdown])

  // Get unique event types from stream
  const eventTypes = useMemo(() => {
    const types = new Map<string, number>()
    streamEvents.forEach(event => {
      const key = event.type
      types.set(key, (types.get(key) || 0) + 1)
    })
    return types
  }, [streamEvents])

  // Filter events based on search and selected types
  const filteredEvents = useMemo(() => {
    return streamEvents.filter(event => {
      // Filter by type if any types are selected
      if (selectedEventTypes.size > 0 && !selectedEventTypes.has(event.type)) {
        return false
      }
      
      // Filter by search
      if (streamSearch) {
        const searchLower = streamSearch.toLowerCase()
        const eventString = JSON.stringify(event).toLowerCase()
        return eventString.includes(searchLower)
      }
      
      return true
    })
  }, [streamEvents, streamSearch, selectedEventTypes])

  // Initialize WebSocket connection
  useEffect(() => {
    console.log('🚀 [ClaudeFlow] Initializing WebSocket connection...')
    console.log('   Current location:', window.location.href)
    
    // Use the same host but different port for WebSocket
    const wsUrl = `ws://${window.location.hostname}:3001`
    
    console.log('   WebSocket URL:', wsUrl)
    
    const newSocket = io(wsUrl, {
      transports: ['websocket'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000
    })

    setSocket(newSocket)

    newSocket.on('connect', () => {
      console.log('✅ [ClaudeFlow] WebSocket connected successfully')
      console.log('   Socket ID:', newSocket.id)
      console.log('   Connected:', newSocket.connected)
      setIsConnected(true)
      // Mark real-time store as connected
      connect()
    })

    newSocket.on('disconnect', (reason) => {
      console.log('❌ [ClaudeFlow] WebSocket disconnected')
      console.log('   Reason:', reason)
      setIsConnected(false)
    })

    newSocket.on('connect_error', (error) => {
      console.error('🔴 [ClaudeFlow] Connection error:', error.message)
      console.error('   Error type:', error.type)
      console.error('   Full error:', error)
    })

    newSocket.on('error', (error) => {
      console.error('🔴 [ClaudeFlow] Socket error:', error)
    })

    // Debug all events
    newSocket.onAny((eventName, ...args) => {
      console.log('📨 [ClaudeFlow] Received event:', eventName)
      console.log('   Args:', args)
    })

    return () => {
      // Silently disconnect WebSocket on cleanup
      newSocket.disconnect()
    }
  }, [])

  // Update performance metrics periodically when streaming
  useEffect(() => {
    if (!isStreaming) return
    
    const interval = setInterval(() => {
      // Update with dummy performance data for now
      // In a real app, this would come from actual metrics
      handleUpdate('performance-update', {
        cpu: Math.random() * 20 + 10, // 10-30%
        memory: Math.random() * 100 + 50, // 50-150MB
        tokenUsage: {
          total: streamEvents.length * 10,
          inputTokens: streamEvents.filter(e => e.type === 'user').length * 5,
          outputTokens: streamEvents.filter(e => e.type === 'assistant').length * 5,
          cost: streamEvents.length * 0.001
        },
        responseTime: Math.random() * 200 + 100, // 100-300ms
        throughput: Math.random() * 50 + 20, // 20-70 req/s
        activeConnections: isConnected ? 1 : 0,
        uptime: Date.now()
      })
    }, 1000)
    
    return () => clearInterval(interval)
  }, [isStreaming, streamEvents.length, isConnected, handleUpdate])

  // Handle Escape key for modal
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && showSwarmVisualizer) {
        setShowSwarmVisualizer(false)
      }
    }
    
    if (showSwarmVisualizer) {
      document.addEventListener('keydown', handleKeyDown)
      return () => document.removeEventListener('keydown', handleKeyDown)
    }
  }, [showSwarmVisualizer])

  // Notify parent of state changes
  useEffect(() => {
    if (onStateChange) {
      onStateChange({
        command,
        streamEvents,
        currentSwarm,
        agents,
        todos,
        isStreaming
      })
    }
  }, [command, streamEvents, currentSwarm, agents, todos, isStreaming, onStateChange])

  // Auto-scroll to bottom unless user has actively scrolled up
  useEffect(() => {
    if (streamRef.current) {
      const element = streamRef.current
      
      // Always auto-scroll unless user has actively scrolled up and is not at bottom
      if (!userHasScrolled || isAtBottom) {
        setTimeout(() => {
          if (element) {
            element.scrollTop = element.scrollHeight
            setIsAtBottom(true)
          }
        }, 10)
      }
    }
  }, [streamEvents, userHasScrolled, isAtBottom])

  const parseStreamEvent = (event: StreamEvent) => {
    console.log('🔍 [ClaudeFlow] Parsing event:', event.type)
    console.log('   Full event:', event)

    // Look for MCP tools in assistant messages
    if (event.type === 'assistant' && event.message?.content) {
      console.log('🤖 [ClaudeFlow] Checking assistant message for tools...')
      event.message.content.forEach((content: any, index: number) => {
        console.log(`   Content [${index}]:`, content.type, content.name || '')
        
        // Handle TodoWrite
        if (content.type === 'tool_use' && content.name === 'TodoWrite') {
          console.log('✅ [ClaudeFlow] Found TodoWrite in assistant message')
          console.log('   Todos:', content.input.todos)
          setTodos(content.input.todos)
        }
        
        // Handle swarm_init
        if (content.type === 'tool_use' && content.name === 'mcp__claude-flow__swarm_init') {
          console.log('📊 [ClaudeFlow] Found swarm_init in assistant message')
          console.log('   Input:', content.input)
          const swarmId = `swarm-${Date.now()}`
          const swarm = {
            id: swarmId,
            topology: content.input.topology || 'hierarchical',
            maxAgents: content.input.maxAgents || 8,
            activeAgents: 0,
            status: 'initialized'
          }
          setCurrentSwarm(swarm)
          
          // Update real-time store
          handleUpdate('swarm-update', {
            action: 'created',
            data: {
              id: swarmId,
              topology: swarm.topology,
              status: 'active',
              agentIds: [],
              maxAgents: swarm.maxAgents,
              createdAt: new Date(),
              lastActivity: new Date(),
              metrics: {
                tasksCompleted: 0,
                totalMessages: 0,
                avgResponseTime: 0
              }
            }
          })
        }
        
        // Handle agent_spawn
        if (content.type === 'tool_use' && content.name === 'mcp__claude-flow__agent_spawn') {
          console.log('🤖 [ClaudeFlow] Found agent_spawn in assistant message')
          console.log('   Input:', content.input)
          const agentId = `agent-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
          const agent = {
            id: agentId,
            name: content.input.name || content.input.type,
            type: content.input.type,
            status: 'active',
            taskCount: 0
          }
          setAgents(prev => [...prev, agent])
          setCurrentSwarm(prev => prev ? { ...prev, activeAgents: prev.activeAgents + 1 } : null)
          
          // Update real-time store
          handleUpdate('agent-update', {
            action: 'created',
            data: {
              id: agentId,
              name: agent.name,
              type: agent.type as 'architect' | 'coder' | 'analyst' | 'tester' | 'researcher' | 'coordinator',
              status: 'idle',
              swarmId: currentSwarm?.id,
              currentTask: undefined,
              position: { x: 0, y: 0, z: 0 },
              metrics: {
                tasksCompleted: 0,
                messagesProcessed: 0,
                avgResponseTime: 0,
                successRate: 100
              },
              lastActivity: new Date()
            }
          })
          
          // Update swarm with new agent
          if (currentSwarm) {
            handleUpdate('swarm-update', {
              action: 'updated',
              data: {
                id: currentSwarm.id,
                agentIds: agents.map(a => a.id).concat(agentId),
                lastActivity: new Date()
              }
            })
          }
        }
      })
    }

    // Also check tool results for any status updates
    if (event.type === 'user' && event.message?.content) {
      event.message.content.forEach((content: any) => {
        // Check if this is a tool result for swarm_init
        if (content.type === 'tool_result' && content.tool_use_id) {
          console.log('📥 [ClaudeFlow] Found tool result, checking content...')
          try {
            // Try to parse the content if it's JSON
            if (content.content && Array.isArray(content.content)) {
              const textContent = content.content.find((c: any) => c.type === 'text')
              if (textContent?.text) {
                // Try parsing as JSON to get swarm IDs or agent IDs
                const result = JSON.parse(textContent.text)
                console.log('   Parsed tool result:', result)
                
                // Update swarm ID if available
                if (result.swarmId && currentSwarm) {
                  setCurrentSwarm(prev => prev ? { ...prev, id: result.swarmId } : null)
                }
                
                // Update agent ID if available
                if (result.agentId && result.type) {
                  setAgents(prev => prev.map(agent => 
                    agent.type === result.type && !agent.id.startsWith('agent-') 
                      ? { ...agent, id: result.agentId }
                      : agent
                  ))
                }
              }
            }
          } catch (error) {
            // Not JSON or parsing failed, that's okay
            console.log('   Tool result is not JSON or parsing failed')
          }
        }
      })
    }
  }

  const startStream = async () => {
    console.log('🎬 [ClaudeFlow] Starting stream...')
    console.log('   Socket connected:', socket?.connected)
    console.log('   Is streaming:', isStreaming)
    
    if (!socket || isStreaming) {
      console.warn('⚠️ [ClaudeFlow] Cannot start stream - socket:', !!socket, 'streaming:', isStreaming)
      return
    }

    setIsStreaming(true)
    setStreamEvents([])
    setAgents([])
    setCurrentSwarm(null)
    setTodos([])
    setUserHasScrolled(false) // Reset scroll state for new stream
    setIsAtBottom(true)
    setShowTemplateDetails(false) // Auto-collapse when starting
    setShowCommandPreview(false)

    // Create abort controller for cancellation
    abortControllerRef.current = new AbortController()

    try {
      // First, set up all event listeners
      console.log('📡 [ClaudeFlow] Setting up event listeners...')
      
      // Listen for output data (exact same pattern as terminal)
      let jsonBuffer = '' // Buffer for incomplete JSON
      
      socket.on('claude-flow:output', (response: { sessionId: string; data: string; type: string }) => {
        console.log('📥 [ClaudeFlow] Received output data')
        console.log('   Data preview:', response.data.substring(0, 100) + (response.data.length > 100 ? '...' : ''))
        
        // Add to buffer
        jsonBuffer += response.data
        
        // Split by lines and process complete lines
        const lines = jsonBuffer.split('\n')
        // Keep the last line in buffer (might be incomplete)
        jsonBuffer = lines.pop() || ''
        
        console.log('📥 Processing', lines.length, 'complete lines')
        
        lines.forEach((line, idx) => {
          if (!line.trim()) return
          console.log(`🔍 Line ${idx}:`, line.substring(0, 100) + (line.length > 100 ? '...' : ''))
          
          try {
            // Try to parse as JSON event
            const event = JSON.parse(line.trim()) as StreamEvent
            console.log('✅ Parsed JSON event:', event.type, event.subtype || '')
            console.log('   Event data:', { type: event.type, subtype: event.subtype, hasTools: !!event.tools })
            setStreamEvents(prev => [...prev, event])
            parseStreamEvent(event)
          } catch (error) {
            // If not JSON, add as raw text (but try to combine consecutive raw lines)
            console.log('❌ JSON parse error:', error.message)
            console.log('   Adding as raw text line')
            setStreamEvents(prev => {
              const lastEvent = prev[prev.length - 1]
              
              // If the last event was also raw and recent, combine them
              if (lastEvent && lastEvent.type === 'raw' && 
                  Date.now() - new Date(lastEvent.timestamp).getTime() < 1000) {
                const updatedEvent = {
                  ...lastEvent,
                  data: lastEvent.data + '\n' + line,
                  timestamp: new Date().toISOString()
                }
                return [...prev.slice(0, -1), updatedEvent]
              }
              
              // Otherwise create new raw event
              return [...prev, { 
                type: 'raw', 
                data: line,
                timestamp: new Date().toISOString()
              } as StreamEvent]
            })
          }
        })
      })
      
      // Listen for session creation
      socket.on('claude-flow:created', (data: { sessionId: string; cwd: string; command: string; timestamp: string }) => {
        console.log('✅ [ClaudeFlow] Session created:', data.sessionId)
      })

      // Listen for stream end
      socket.on('claude-flow:complete', (data) => {
        console.log('✅ [ClaudeFlow] Stream completed')
        console.log('   Completion data:', data)
        console.log('   Was stopped by user:', data.stopped || false)
        
        setIsStreaming(false)
        
        // Add completion event to stream for visibility
        if (data.stopped) {
          setStreamEvents(prev => [...prev, {
            type: 'system',
            subtype: 'stopped',
            message: 'Stream stopped by user',
            exitCode: data.exitCode,
            signal: data.signal,
            timestamp: new Date().toISOString()
          } as StreamEvent])
        }
        
        socket.off('claude-flow:output')
        socket.off('claude-flow:created')
        socket.off('claude-flow:complete')
        socket.off('claude-flow:error')
      })

      // Listen for errors
      socket.on('claude-flow:error', (error: { message: string }) => {
        console.error('❌ [ClaudeFlow] Stream error:', error)
        setIsStreaming(false)
        
        // Add error to stream events for visibility
        setStreamEvents(prev => [...prev, {
          type: 'error',
          message: error.message,
          timestamp: new Date().toISOString()
        } as StreamEvent])
        
        // Clean up listeners
        socket.off('claude-flow:output')
        socket.off('claude-flow:created')
        socket.off('claude-flow:complete')
        socket.off('claude-flow:error')
      })

      // Send structured data instead of command string
      console.log('📤 [ClaudeFlow] Emitting claude-flow:execute with structured data')
      console.log('   User prompt:', command.substring(0, 100) + (command.length > 100 ? '...' : ''))
      console.log('   Template:', selectedTemplate?.name || 'none')
      
      // Small delay to ensure listeners are properly attached
      setTimeout(() => {
        socket.emit('claude-flow:execute', {
          userPrompt: command.trim(),
          template: selectedTemplate ? {
            name: selectedTemplate.name,
            filename: selectedTemplate.filename,
            content: selectedTemplate.content
          } : null,
          options: {
            cwd: '/workspaces/claude-code-flow'
          }
        })
      }, 100)

    } catch (error) {
      console.error('❌ [ClaudeFlow] Failed to start stream:', error)
      setIsStreaming(false)
    }
  }

  const stopStream = () => {
    console.log('🛑 [ClaudeFlow] Stopping stream...')
    
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
    }
    
    if (socket && socket.connected) {
      console.log('📤 [ClaudeFlow] Emitting claude-flow:stop')
      
      // Set up a one-time listener for the stop completion
      const handleStopComplete = (data: any) => {
        console.log('✅ [ClaudeFlow] Stop completed:', data)
        setIsStreaming(false)
        
        // Clean up all listeners
        socket.off('claude-flow:output')
        socket.off('claude-flow:created')
        socket.off('claude-flow:complete')
        socket.off('claude-flow:error')
      }
      
      socket.once('claude-flow:complete', handleStopComplete)
      
      // Send stop signal
      socket.emit('claude-flow:stop')
      
      // Fallback: force stop after 3 seconds if no response
      setTimeout(() => {
        if (isStreaming) {
          console.log('⚠️ [ClaudeFlow] Force stopping after timeout')
          setIsStreaming(false)
          socket.off('claude-flow:output')
          socket.off('claude-flow:created')
          socket.off('claude-flow:complete')
          socket.off('claude-flow:error')
        }
      }, 3000)
      
    } else {
      console.log('⚠️ [ClaudeFlow] Socket not connected, stopping locally')
      setIsStreaming(false)
    }
  }

  const clearStream = () => {
    setStreamEvents([])
    setAgents([])
    setCurrentSwarm(null)
    setTodos([])
  }

  const copyCommand = () => {
    const finalCommand = getFinalCommand()
    const commandToCopy = `claude "${finalCommand}" -p --output-format stream-json --verbose --dangerously-skip-permissions`
    navigator.clipboard.writeText(commandToCopy)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // Handle template selection - show both user input and template
  const handleTemplateSelect = (template: CommandTemplate) => {
    setSelectedTemplate(template)
    setShowCommandDropdown(false)
  }

  // Clear the selected template
  const clearTemplate = () => {
    setSelectedTemplate(null)
  }

  // Get the final command that will be executed
  const getFinalCommand = () => {
    if (!selectedTemplate) {
      return command
    }
    
    // Combine user input with template content
    const userPrompt = command.trim()
    const templateContent = selectedTemplate.content
    
    if (userPrompt) {
      return `${userPrompt}\n\n--- Using Template: ${selectedTemplate.name} ---\n${templateContent}`
    } else {
      return templateContent
    }
  }

  const copyEventJson = (event: StreamEvent, eventId: string) => {
    const eventJson = JSON.stringify(event, null, 2)
    navigator.clipboard.writeText(eventJson)
    setCopiedEventId(eventId)
    setTimeout(() => setCopiedEventId(null), 2000)
  }

  const renderEvent = (event: StreamEvent, index: number) => {
    const eventId = `event-${index}`
    // Handle raw events differently
    if (event.type === 'raw') {
      console.log('📜 Rendering raw event')
      return (
        <div key={index} className="mb-3 p-3 border border-gray-700 rounded-lg bg-gray-900/30">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase text-gray-400 bg-gray-800 px-2 py-1 rounded">📜 RAW OUTPUT</span>
              <span className="text-xs text-gray-500">{event.timestamp}</span>
            </div>
            <button
              onClick={() => copyEventJson(event, eventId)}
              className="flex items-center gap-1 px-2 py-1 text-xs bg-gray-700 text-gray-300 border border-gray-600 rounded hover:bg-gray-600 transition-colors"
              title="Copy event JSON"
            >
              {copiedEventId === eventId ? <Check size={10} /> : <Copy size={10} />}
              JSON
            </button>
          </div>
          <pre className="text-xs whitespace-pre-wrap break-words font-mono text-gray-300 bg-black/30 p-2 rounded max-w-full overflow-hidden">
            {event.data}
          </pre>
          {showRawJson && (
            <div className="mt-2 border-t border-gray-700 pt-2">
              <div className="text-xs text-gray-500 mb-1">Raw Event JSON:</div>
              <pre className="text-xs bg-gray-950/50 p-2 rounded max-h-32 overflow-y-auto whitespace-pre-wrap break-words text-gray-400">
                {JSON.stringify(event, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )
    }

    // Handle error events
    if (event.type === 'error') {
      return (
        <div key={index} className="mb-3 p-3 border border-red-700 rounded-lg bg-red-900/20">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase text-red-300 bg-red-800 px-2 py-1 rounded">❌ ERROR</span>
              <span className="text-xs text-red-400">{event.timestamp}</span>
            </div>
            <button
              onClick={() => copyEventJson(event, eventId)}
              className="flex items-center gap-1 px-2 py-1 text-xs bg-red-800 text-red-300 border border-red-700 rounded hover:bg-red-700 transition-colors"
              title="Copy event JSON"
            >
              {copiedEventId === eventId ? <Check size={10} /> : <Copy size={10} />}
              JSON
            </button>
          </div>
          <pre className="text-xs whitespace-pre-wrap break-words text-red-300 bg-red-950/30 p-2 rounded max-w-full overflow-hidden">
            {event.message || JSON.stringify(event, null, 2)}
          </pre>
          {showRawJson && (
            <div className="mt-2 border-t border-red-700 pt-2">
              <div className="text-xs text-red-400 mb-1">Raw Event JSON:</div>
              <pre className="text-xs bg-red-950/50 p-2 rounded max-h-32 overflow-y-auto whitespace-pre-wrap break-words text-red-300">
                {JSON.stringify(event, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )
    }

    // Handle system events with enhanced formatting
    if (event.type === 'system') {
      console.log('🔧 Rendering system event:', event.subtype)
      return (
        <div key={index} className="mb-3 p-3 border border-cyan-700 rounded-lg bg-cyan-900/20">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase text-cyan-300 bg-cyan-800 px-2 py-1 rounded">⚙️ SYSTEM</span>
              {event.subtype && <span className="text-xs text-cyan-400 bg-cyan-900 px-2 py-1 rounded">({event.subtype})</span>}
            </div>
            <button
              onClick={() => copyEventJson(event, eventId)}
              className="flex items-center gap-1 px-2 py-1 text-xs bg-cyan-800 text-cyan-300 border border-cyan-700 rounded hover:bg-cyan-700 transition-colors"
              title="Copy event JSON"
            >
              {copiedEventId === eventId ? <Check size={10} /> : <Copy size={10} />}
              JSON
            </button>
          </div>
          {event.subtype === 'init' ? (
            <div className="space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="text-sm text-cyan-300">
                  <strong>📋 Session:</strong> <code className="bg-cyan-950/50 px-1 rounded">{event.session_id?.substring(0, 8)}...</code>
                </div>
                <div className="text-sm text-cyan-300">
                  <strong>🤖 Model:</strong> <code className="bg-cyan-950/50 px-1 rounded">{event.model}</code>
                </div>
                <div className="text-sm text-cyan-300 md:col-span-2">
                  <strong>📁 Working Directory:</strong> <code className="bg-cyan-950/50 px-1 rounded">{event.cwd}</code>
                </div>
              </div>
              
              <div className="border-t border-cyan-800 pt-2">
                <div className="text-sm text-cyan-300 mb-2">
                  <strong>🔗 MCP Servers ({event.mcp_servers?.length || 0}):</strong>
                </div>
                <div className="flex flex-wrap gap-1">
                  {event.mcp_servers?.map((server: any, idx: number) => (
                    <span key={idx} className={`text-xs px-2 py-1 rounded ${
                      server.status === 'connected' 
                        ? 'bg-green-900/30 text-green-400 border border-green-800' 
                        : 'bg-red-900/30 text-red-400 border border-red-800'
                    }`}>
                      {server.name} ({server.status})
                    </span>
                  ))}
                </div>
              </div>

              <div className="border-t border-cyan-800 pt-2">
                <div className="text-sm text-cyan-300 mb-2">
                  <strong>🔧 Available Tools ({event.tools?.length || 0}):</strong>
                </div>
                <details className="mt-2">
                  <summary className="text-xs text-cyan-400 cursor-pointer hover:text-cyan-300 p-1 bg-cyan-950/30 rounded">
                    View all tools
                  </summary>
                  <div className="mt-2 max-h-32 overflow-y-auto">
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-1 text-xs">
                      {event.tools?.map((tool: string, idx: number) => (
                        <code key={idx} className="bg-cyan-950/50 p-1 rounded text-cyan-200 block truncate" title={tool}>
                          {tool}
                        </code>
                      ))}
                    </div>
                  </div>
                </details>
              </div>

              {showRawJson && (
                <div className="border-t border-cyan-800 pt-2 mt-2">
                  <div className="text-xs text-cyan-400 mb-1">Raw Event JSON:</div>
                  <pre className="text-xs whitespace-pre-wrap break-words text-cyan-200 bg-cyan-950/30 p-2 rounded max-h-40 overflow-y-auto max-w-full overflow-x-hidden">
                    {JSON.stringify(event, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div>
              <pre className="text-xs whitespace-pre-wrap break-words text-cyan-200 bg-cyan-950/30 p-2 rounded max-w-full overflow-hidden">
                {JSON.stringify(event, null, 2)}
              </pre>
              {showRawJson && (
                <div className="mt-2 border-t border-cyan-700 pt-2">
                  <div className="text-xs text-cyan-400 mb-1">Raw Event JSON:</div>
                  <pre className="text-xs whitespace-pre-wrap break-words text-cyan-200 bg-cyan-950/30 p-2 rounded max-h-40 overflow-y-auto max-w-full overflow-x-hidden">
                    {JSON.stringify(event, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      )
    }

    // Handle assistant messages with enhanced formatting
    if (event.type === 'assistant' && event.message?.content) {
      const hasTools = event.message.content.some((c: any) => c.type === 'tool_use')
      const hasText = event.message.content.some((c: any) => c.type === 'text')
      const toolCount = event.message.content.filter((c: any) => c.type === 'tool_use').length
      
      return (
        <div key={index} className="mb-3 p-3 border border-green-700 rounded-lg bg-green-900/20">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase text-green-300 bg-green-800 px-2 py-1 rounded">🤖 ASSISTANT</span>
              {hasTools && (
                <span className="text-xs text-yellow-400 bg-yellow-900/30 px-2 py-1 rounded border border-yellow-800">
                  🔧 {toolCount} tool{toolCount !== 1 ? 's' : ''}
                </span>
              )}
            </div>
            <span className="text-xs text-green-500 bg-green-950/30 px-2 py-1 rounded font-mono">
              {event.message.id?.substring(0, 8)}...
            </span>
          </div>
          
          <div className="space-y-3">
            {/* Show text content */}
            {hasText && (
              <div className="bg-green-950/30 p-3 rounded border-l-4 border-green-600">
                <div className="text-xs text-green-400 mb-2 uppercase font-bold">💬 Message</div>
                {event.message.content.map((content: any, idx: number) => {
                  if (content.type === 'text') {
                    return (
                      <div key={idx} className="text-sm text-green-200 whitespace-pre-wrap">
                        {content.text}
                      </div>
                    )
                  }
                  return null
                })}
              </div>
            )}
            
            {/* Show tools being used */}
            {hasTools && (
              <div className="space-y-2">
                <div className="text-xs text-yellow-400 mb-2 uppercase font-bold">🔧 Tools Executed</div>
                <div className="grid gap-2">
                  {event.message.content.map((content: any, idx: number) => {
                    if (content.type === 'tool_use') {
                      const isSpecialTool = ['TodoWrite', 'mcp__claude-flow__swarm_init', 'mcp__claude-flow__agent_spawn'].includes(content.name)
                      
                      return (
                        <div key={idx} className="bg-yellow-900/20 p-2 rounded border border-yellow-800/50">
                          <div className="flex items-center justify-between mb-1">
                            <div className="flex items-center gap-2">
                              <span className="text-yellow-400 font-mono text-sm">▶ {content.name}</span>
                              {isSpecialTool && (
                                <span className="text-xs bg-purple-900/50 text-purple-300 px-1 rounded">
                                  swarm
                                </span>
                              )}
                            </div>
                            {content.name === 'TodoWrite' && content.input.todos && (
                              <span className="text-xs text-yellow-500 bg-yellow-950/50 px-2 py-1 rounded">
                                {content.input.todos.length} todos
                              </span>
                            )}
                          </div>
                          
                          {content.input && Object.keys(content.input).length > 0 && (
                            <details className="mt-2">
                              <summary className="text-xs text-yellow-500 cursor-pointer hover:text-yellow-400 bg-yellow-950/30 p-1 rounded">
                                View parameters ({Object.keys(content.input).length} keys)
                              </summary>
                              <div className="mt-2 bg-yellow-950/20 p-2 rounded">
                                <pre className="text-xs text-yellow-200 max-h-32 overflow-y-auto whitespace-pre-wrap break-words max-w-full overflow-x-hidden">
                                  {JSON.stringify(content.input, null, 2)}
                                </pre>
                              </div>
                            </details>
                          )}
                        </div>
                      )
                    }
                    return null
                  })}
                </div>
              </div>
            )}
            
            {/* Show usage info if available */}
            {event.message.usage && (
              <div className="bg-green-950/30 p-2 rounded border border-green-800/50">
                <div className="text-xs text-green-400 mb-1 uppercase font-bold">📊 Token Usage</div>
                <div className="flex flex-wrap gap-3 text-xs text-green-300">
                  <span>
                    <strong>Input:</strong> {event.message.usage.input_tokens.toLocaleString()}
                  </span>
                  <span>
                    <strong>Output:</strong> {event.message.usage.output_tokens.toLocaleString()}
                  </span>
                  {event.message.usage.cache_read_input_tokens > 0 && (
                    <span className="text-blue-400">
                      <strong>Cached:</strong> {event.message.usage.cache_read_input_tokens.toLocaleString()}
                    </span>
                  )}
                  {event.message.usage.cache_creation_input_tokens > 0 && (
                    <span className="text-purple-400">
                      <strong>Cache Created:</strong> {event.message.usage.cache_creation_input_tokens.toLocaleString()}
                    </span>
                  )}
                </div>
              </div>
            )}
            
            {/* Show raw JSON if enabled */}
            {showRawJson && (
              <div className="mt-3 border-t border-green-700 pt-2">
                <div className="flex items-center justify-between mb-2">
                  <div className="text-xs text-green-400 font-bold">Raw Event JSON:</div>
                  <button
                    onClick={() => copyEventJson(event, `assistant-${index}`)}
                    className="flex items-center gap-1 px-2 py-1 text-xs bg-green-800 text-green-300 border border-green-700 rounded hover:bg-green-700 transition-colors"
                    title="Copy event JSON"
                  >
                    {copiedEventId === `assistant-${index}` ? <Check size={10} /> : <Copy size={10} />}
                    Copy
                  </button>
                </div>
                <pre className="text-xs bg-green-950/30 p-2 rounded max-h-40 overflow-y-auto whitespace-pre-wrap break-words text-green-300">
                  {JSON.stringify(event, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )
    }

    // Handle user messages (tool results) with enhanced formatting
    if (event.type === 'user' && event.message?.content) {
      return (
        <div key={index} className="mb-3 p-3 border border-blue-700 rounded-lg bg-blue-900/20">
          <div className="flex items-center gap-2 mb-3">
            <span className="text-xs font-bold uppercase text-blue-300 bg-blue-800 px-2 py-1 rounded">📤 TOOL RESULT</span>
            <button
              onClick={() => copyEventJson(event, `user-${index}`)}
              className="ml-auto flex items-center gap-1 px-2 py-1 text-xs bg-blue-800 text-blue-300 border border-blue-700 rounded hover:bg-blue-700 transition-colors"
              title="Copy event JSON"
            >
              {copiedEventId === `user-${index}` ? <Check size={10} /> : <Copy size={10} />}
              JSON
            </button>
            <span className="text-xs text-blue-400 bg-blue-950/30 px-2 py-1 rounded">
              {event.message.content.length} result{event.message.content.length !== 1 ? 's' : ''}
            </span>
          </div>
          
          <div className="space-y-3">
            {event.message.content.map((content: any, idx: number) => {
              if (content.type === 'tool_result') {
                const toolId = content.tool_use_id?.substring(content.tool_use_id.length - 8) || 'unknown'
                let resultData
                let isJsonResult = false
                let parsedData = null
                
                try {
                  resultData = typeof content.content === 'string' ? content.content : 
                              Array.isArray(content.content) ? content.content[0]?.text || JSON.stringify(content.content) :
                              JSON.stringify(content.content)
                  
                  // Try to parse as JSON for better formatting
                  parsedData = JSON.parse(resultData)
                  isJsonResult = true
                } catch (e) {
                  // Not JSON, display as text
                  isJsonResult = false
                }
                
                return (
                  <div key={idx} className="bg-blue-950/30 p-3 rounded border-l-4 border-blue-600">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono text-blue-400 bg-blue-900/30 px-2 py-1 rounded">
                        Tool ID: {toolId}
                      </span>
                      {isJsonResult && parsedData?.success !== undefined && (
                        <span className={`text-xs px-2 py-1 rounded font-bold ${
                          parsedData.success 
                            ? 'bg-green-900/50 text-green-300 border border-green-700' 
                            : 'bg-red-900/50 text-red-300 border border-red-700'
                        }`}>
                          {parsedData.success ? '✅ Success' : '❌ Failed'}
                        </span>
                      )}
                    </div>
                    
                    {isJsonResult ? (
                      <div className="space-y-2">
                        {/* Show key information if it's a structured response */}
                        {parsedData && typeof parsedData === 'object' && (
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                            {Object.entries(parsedData).slice(0, 6).map(([key, value]: [string, any]) => {
                              if (key === 'success' || key === 'timestamp') return null
                              return (
                                <div key={key} className="bg-blue-900/30 p-2 rounded">
                                  <div className="text-blue-300 font-bold mb-1">{key}:</div>
                                  <div className="text-blue-200 truncate" title={String(value)}>
                                    {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                                  </div>
                                </div>
                              )
                            })}
                          </div>
                        )}
                        
                        <details className="mt-2">
                          <summary className="text-xs text-blue-400 cursor-pointer hover:text-blue-300 bg-blue-950/30 p-2 rounded">
                            View full JSON result
                          </summary>
                          <pre className="text-xs text-blue-200 mt-2 bg-blue-950/20 p-2 rounded max-h-40 overflow-y-auto whitespace-pre-wrap break-words max-w-full overflow-x-hidden">
                            {JSON.stringify(parsedData, null, 2)}
                          </pre>
                        </details>
                      </div>
                    ) : (
                      <div className="bg-blue-950/20 p-2 rounded">
                        <div className="text-xs text-blue-300 mb-1 uppercase font-bold">📄 Raw Output</div>
                        <pre className="text-xs text-blue-200 whitespace-pre-wrap break-words max-h-32 overflow-y-auto max-w-full overflow-x-hidden">
                          {resultData}
                        </pre>
                      </div>
                    )}
                  </div>
                )
              }
              return null
            })}
          </div>
          
          {/* Show raw JSON if enabled */}
          {showRawJson && (
            <div className="mt-3 border-t border-blue-700 pt-2">
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs text-blue-400 font-bold">Raw Event JSON:</div>
                <button
                  onClick={() => copyEventJson(event, `user-result-${index}`)}
                  className="flex items-center gap-1 px-2 py-1 text-xs bg-blue-800 text-blue-300 border border-blue-700 rounded hover:bg-blue-700 transition-colors"
                  title="Copy event JSON"
                >
                  {copiedEventId === `user-result-${index}` ? <Check size={10} /> : <Copy size={10} />}
                  Copy
                </button>
              </div>
              <pre className="text-xs bg-blue-950/30 p-2 rounded max-h-40 overflow-y-auto whitespace-pre-wrap break-words text-blue-300">
                {JSON.stringify(event, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )
    }

    // Default rendering for unknown types
    console.log('❓ Using default rendering for event type:', event.type)
    return (
      <div key={index} className="mb-3 p-3 border border-gray-700 rounded-lg bg-gray-900/20">
        <div className="flex items-center gap-2 mb-2">
          <span className="text-xs font-bold uppercase text-gray-300 bg-gray-700 px-2 py-1 rounded">{event.type?.toUpperCase() || 'UNKNOWN'}</span>
          {event.subtype && <span className="text-xs text-gray-400">({event.subtype})</span>}
        </div>
        <pre className="text-xs whitespace-pre-wrap break-words text-gray-300 bg-gray-950/30 p-2 rounded max-h-40 overflow-y-auto max-w-full overflow-x-hidden">
          {JSON.stringify(event, null, 2)}
        </pre>
      </div>
    )
  }

  // Debug function
  const debugConnection = () => {
    console.log('🔍 [ClaudeFlow] Debug Info:')
    console.log('   Socket exists:', !!socket)
    console.log('   Socket connected:', socket?.connected)
    console.log('   Socket ID:', socket?.id)
    console.log('   Is streaming:', isStreaming)
    console.log('   Stream events count:', streamEvents.length)
    
    if (socket && socket.connected) {
      console.log('📤 [ClaudeFlow] Sending test ping...')
      socket.emit('ping', { timestamp: Date.now() })
    }
  }

  return (
    <div className="p-6 min-h-full flex flex-col bg-gray-950">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-4">
          <h1 className="text-2xl font-bold glitch" data-text="CLAUDE FLOW DASHBOARD">
            CLAUDE FLOW DASHBOARD
          </h1>
          <div className="flex items-center gap-2">
            <span className={`px-2 py-1 text-xs rounded ${isConnected ? 'bg-green-900 text-green-400' : 'bg-red-900 text-red-400'}`}>
              {isConnected ? '🔗 Connected' : '❌ Disconnected'}
            </span>
            <span className={`px-2 py-1 text-xs rounded ${isStreaming ? 'bg-yellow-900 text-yellow-400 animate-pulse' : 'bg-gray-900 text-gray-400'}`}>
              {isStreaming ? '📡 Streaming' : '⏸️ Idle'}
            </span>
          </div>
        </div>
        <button
          onClick={debugConnection}
          className="px-3 py-1 text-xs bg-gray-900 text-gray-400 rounded hover:bg-gray-800 transition-colors"
          title="Debug connection"
        >
          🐛 Debug
        </button>
      </div>

      {/* Command Control - Full Width */}
      <div className="retro-panel p-4 mb-4">
        <h3 className="text-sm font-bold text-green-400 mb-3 flex items-center gap-2">
          ⚡ COMMAND CONTROL
        </h3>
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <label className="text-xs text-green-600 mb-1 block">COMMAND</label>
            <div className="space-y-2">
              <div className="flex gap-2">
                {/* Command Templates Dropdown */}
                <div className="relative" ref={dropdownRef}>
                  <button
                    onClick={() => setShowCommandDropdown(!showCommandDropdown)}
                    className="px-3 py-2 bg-blue-900/30 text-blue-400 rounded hover:bg-blue-900/50 transition-colors flex items-center gap-2"
                    title="Command templates"
                    disabled={isStreaming || loadingTemplates}
                  >
                    <BookOpen size={16} />
                    {loadingTemplates ? 'Loading...' : <ChevronDown size={14} />}
                  </button>
                
                {showCommandDropdown && (
                  <div className="absolute top-full left-0 mt-1 w-96 bg-gray-900 border border-gray-700 rounded-lg shadow-lg z-50 max-h-96 overflow-y-auto">
                    <div className="p-2">
                      <div className="text-xs font-bold text-gray-400 mb-2 px-2">📋 Command Templates</div>
                      
                      {loadingTemplates ? (
                        <div className="text-center py-4 text-gray-400">
                          <div className="animate-spin text-blue-400">⚙️</div>
                          <div className="text-sm mt-2">Loading templates...</div>
                        </div>
                      ) : Object.keys(commandTemplates).length === 0 ? (
                        <div className="text-center py-4 text-gray-400">
                          <div className="text-sm">No command templates found</div>
                          <div className="text-xs mt-1">Check .claude/commands/ directory</div>
                        </div>
                      ) : (
                        Object.entries(commandTemplates).map(([category, templates]) => (
                          <div key={category} className="mb-3">
                            <div className="text-xs font-bold text-green-400 mb-1 px-2">
                              {category === 'root' ? 'commands' : category}
                            </div>
                            {templates.map((template) => (
                              <button
                                key={`${category}-${template.name}`}
                                onClick={() => handleTemplateSelect(template)}
                                className="w-full text-left p-2 hover:bg-gray-800 rounded text-xs transition-colors"
                              >
                                <div className="font-medium text-gray-200 mb-1">{template.name}</div>
                                <div className="text-gray-400 mb-1">
                                  {template.filename} • {Math.round(template.size / 1024)}KB
                                </div>
                                <div className="text-green-300 font-mono bg-gray-950/50 p-1 rounded text-xs truncate">
                                  Click to use this template
                                </div>
                              </button>
                            ))}
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}
              </div>
                
                <input
                  type="text"
                  value={command}
                  onChange={(e) => setCommand(e.target.value)}
                  className="flex-1 bg-black border border-green-900 text-green-400 px-3 py-2 rounded font-mono text-sm"
                  placeholder="Enter your prompt or task description..."
                  disabled={isStreaming}
                />
                
                {selectedTemplate && (
                  <button
                    onClick={clearTemplate}
                    className="px-3 py-2 bg-red-900/30 text-red-400 rounded hover:bg-red-900/50 transition-colors"
                    title="Clear template"
                  >
                    ✕
                  </button>
                )}
                
                <button
                  onClick={copyCommand}
                  className="px-3 py-2 bg-green-900/30 text-green-400 rounded hover:bg-green-900/50 transition-colors"
                  title="Copy full command"
                >
                  {copied ? <Check size={16} /> : <Copy size={16} />}
                </button>
              </div>
              
              {/* Show selected template */}
              {selectedTemplate && (
                <div className="bg-blue-950/30 border border-blue-700 rounded">
                  <button
                    onClick={() => setShowTemplateDetails(!showTemplateDetails)}
                    className="w-full p-3 text-left hover:bg-blue-950/50 transition-colors flex items-center justify-between"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-blue-300">📋 Selected Template: {selectedTemplate.name}</span>
                      <span className="text-xs text-blue-400">{selectedTemplate.filename}</span>
                    </div>
                    <span className="text-blue-400">{showTemplateDetails ? '▼' : '▶'}</span>
                  </button>
                  {showTemplateDetails && (
                    <div className="px-3 pb-3 border-t border-blue-800/50">
                      <div className="text-xs text-blue-200 mb-2 mt-2">
                        This template content will be combined with your prompt above.
                      </div>
                      <details className="text-xs">
                        <summary className="text-blue-400 cursor-pointer hover:text-blue-300">View template content ({Math.round(selectedTemplate.size / 1024)}KB)</summary>
                        <pre className="mt-2 bg-blue-950/50 p-2 rounded text-blue-200 max-h-32 overflow-y-auto whitespace-pre-wrap break-words">
                          {selectedTemplate.content.substring(0, 500)}{selectedTemplate.content.length > 500 ? '...' : ''}
                        </pre>
                      </details>
                    </div>
                  )}
                </div>
              )}
              
              {/* Show final command preview */}
              {(selectedTemplate || command) && (
                <div className="bg-gray-900/50 border border-gray-600 rounded">
                  <button
                    onClick={() => setShowCommandPreview(!showCommandPreview)}
                    className="w-full p-3 text-left hover:bg-gray-800/50 transition-colors flex items-center justify-between"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-gray-300">🚀 Command Preview</span>
                      <span className="text-xs text-gray-500">({getFinalCommand().length} chars)</span>
                    </div>
                    <span className="text-gray-400">{showCommandPreview ? '▼' : '▶'}</span>
                  </button>
                  {showCommandPreview && (
                    <div className="px-3 pb-3 border-t border-gray-700/50">
                      <div className="text-xs font-mono text-gray-400 bg-black/50 p-2 rounded break-words mt-2">
                        claude "[combined prompt]" -p --output-format stream-json --verbose
                      </div>
                      <details className="mt-2">
                        <summary className="text-xs text-gray-500 cursor-pointer hover:text-gray-400">View combined prompt</summary>
                        <pre className="mt-1 text-xs bg-gray-950/50 p-2 rounded max-h-32 overflow-y-auto whitespace-pre-wrap break-words">
                          {getFinalCommand()}
                        </pre>
                      </details>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
          <div className="flex gap-2">
            {!isStreaming ? (
              <button
                onClick={startStream}
                disabled={!isConnected || !command}
                className="px-4 py-2 bg-green-900 text-green-400 rounded hover:bg-green-800 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                <Play size={16} />
                Start
              </button>
            ) : (
              <button
                onClick={stopStream}
                className="px-4 py-2 bg-red-900 text-red-400 rounded hover:bg-red-800 transition-colors flex items-center gap-2"
              >
                <Pause size={16} />
                Stop
              </button>
            )}
            <button
              onClick={clearStream}
              disabled={isStreaming}
              className="px-4 py-2 bg-gray-900 text-gray-400 rounded hover:bg-gray-800 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              title="Clear stream"
            >
              <RefreshCw size={16} />
            </button>
          </div>
        </div>
      </div>

      <div className="flex gap-6 h-full">
        {/* Left Sidebar - Status Panel */}
        <div className="w-80 space-y-4">

          {/* Task Progress */}
          <div className="retro-panel p-4">
            <h3 className="text-sm font-bold text-green-400 mb-3 flex items-center gap-2">
              📋 TASK PROGRESS
              {todos.length > 0 && (
                <span className="text-xs bg-blue-900/30 text-blue-400 px-2 py-1 rounded">
                  {todos.length}
                </span>
              )}
            </h3>
            {todos.length > 0 ? (
              <div className="space-y-2">
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="bg-green-950/30 p-2 rounded">
                    <div className="text-green-300 font-bold">Completed</div>
                    <div className="text-green-400 text-lg">{todos.filter(t => t.status === 'completed').length}</div>
                  </div>
                  <div className="bg-yellow-950/30 p-2 rounded">
                    <div className="text-yellow-300 font-bold">In Progress</div>
                    <div className="text-yellow-400 text-lg">{todos.filter(t => t.status === 'in_progress').length}</div>
                  </div>
                  <div className="bg-gray-800 p-2 rounded">
                    <div className="text-gray-300 font-bold">Pending</div>
                    <div className="text-gray-400 text-lg">{todos.filter(t => t.status === 'pending').length}</div>
                  </div>
                  <div className="bg-blue-950/30 p-2 rounded">
                    <div className="text-blue-300 font-bold">Total</div>
                    <div className="text-blue-400 text-lg">{todos.length}</div>
                  </div>
                </div>
                
                {/* Progress Bar */}
                <div className="bg-gray-800 rounded-full h-2">
                  <div 
                    className="bg-green-500 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${todos.length > 0 ? (todos.filter(t => t.status === 'completed').length / todos.length) * 100 : 0}%` }}
                  />
                </div>
                <div className="text-xs text-gray-400 text-center">
                  {todos.length > 0 ? Math.round((todos.filter(t => t.status === 'completed').length / todos.length) * 100) : 0}% Complete
                </div>
              </div>
            ) : (
              <div className="text-center py-6">
                <div className="text-gray-500 text-xs mb-2">📋 No tasks tracked</div>
                <div className="text-gray-600 text-xs">Tasks will appear during execution</div>
              </div>
            )}
          </div>

          {/* Swarm Overview */}
          <div className="retro-panel p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-bold text-green-400 flex items-center gap-2">
                <Zap size={14} />
                SWARM OVERVIEW
              </h3>
              {currentSwarm && (
                <button
                  onClick={() => setShowSwarmVisualizer(!showSwarmVisualizer)}
                  className={`flex items-center gap-1 px-2 py-1 text-xs rounded transition-colors ${
                    showSwarmVisualizer
                      ? 'bg-green-900/50 text-green-400 border border-green-700'
                      : 'bg-gray-800 text-gray-400 border border-gray-600 hover:bg-gray-700'
                  }`}
                  title="Toggle swarm visualizer"
                >
                  <Layers size={12} />
                  Visual
                </button>
              )}
            </div>
            {currentSwarm ? (
              <div className="space-y-3">
                <div className="bg-green-950/30 p-2 rounded border border-green-800/50">
                  <div className="text-xs text-green-300 mb-1">SWARM ID</div>
                  <div className="text-xs text-green-400 font-mono">{currentSwarm.id.split('_')[1]}</div>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="bg-cyan-950/30 p-2 rounded">
                    <div className="text-cyan-300 font-bold">Topology</div>
                    <div className="text-cyan-400">{currentSwarm.topology}</div>
                  </div>
                  <div className="bg-blue-950/30 p-2 rounded">
                    <div className="text-blue-300 font-bold">Status</div>
                    <div className="text-blue-400">{currentSwarm.status}</div>
                  </div>
                </div>
                <div className="bg-purple-950/30 p-2 rounded">
                  <div className="text-xs text-purple-300 mb-1">AGENT CAPACITY</div>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 bg-gray-800 rounded-full h-2">
                      <div 
                        className="bg-purple-500 h-2 rounded-full transition-all duration-300"
                        style={{ width: `${currentSwarm.maxAgents > 0 ? (currentSwarm.activeAgents / currentSwarm.maxAgents) * 100 : 0}%` }}
                      />
                    </div>
                    <span className="text-xs text-purple-400">{currentSwarm.activeAgents}/{currentSwarm.maxAgents}</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-6">
                <div className="text-gray-500 text-xs mb-2">⚪ No swarm initialized</div>
                <div className="text-gray-600 text-xs">Execute a command to start</div>
              </div>
            )}
          </div>

          {/* Active Agents */}
          <div className="retro-panel p-4">
            <h3 className="text-sm font-bold text-green-400 mb-3 flex items-center gap-2">
              🤖 ACTIVE AGENTS
              {agents.length > 0 && (
                <span className="text-xs bg-green-900/30 text-green-400 px-2 py-1 rounded">
                  {agents.length}
                </span>
              )}
            </h3>
            {agents.length > 0 ? (
              <SwarmVisualizerInline 
                agents={agents} 
                currentSwarm={currentSwarm}
                onOpenFullView={() => setShowSwarmVisualizer(true)}
              />
            ) : (
              <div className="text-center py-6">
                <div className="text-gray-500 text-xs mb-2">🤖 No agents spawned</div>
                <div className="text-gray-600 text-xs">Agents will appear when swarm starts</div>
              </div>
            )}
          </div>
        </div>

        {/* Main Content - Stream Output */}
        <div className="flex-1 retro-panel bg-black p-4 font-mono text-sm flex flex-col min-w-0">
          <div className="mb-4 space-y-3">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-green-900/50 pb-2">
              <h3 className="text-sm font-bold text-green-400 flex items-center gap-2">
                📡 LIVE STREAM OUTPUT
              </h3>
              <div className="flex items-center gap-3">
                <span className="text-xs text-gray-500">
                  {filteredEvents.length}{streamSearch || selectedEventTypes.size > 0 ? `/${streamEvents.length}` : ''} events
                </span>
                <button
                  onClick={() => setShowFilters(!showFilters)}
                  className={`flex items-center gap-1 px-3 py-1 text-xs rounded transition-all ${
                    showFilters || selectedEventTypes.size > 0
                      ? 'bg-purple-900/50 text-purple-400 border border-purple-700'
                      : 'bg-gray-800 text-gray-400 border border-gray-600 hover:bg-gray-700'
                  }`}
                  title="Toggle filters"
                >
                  <Filter size={12} />
                  Filters {selectedEventTypes.size > 0 && `(${selectedEventTypes.size})`}
                </button>
                <button
                  onClick={() => setShowRawJson(!showRawJson)}
                  className={`flex items-center gap-1 px-3 py-1 text-xs rounded transition-all ${
                    showRawJson 
                      ? 'bg-yellow-500 text-black border border-yellow-400 font-bold shadow-lg animate-pulse' 
                      : 'bg-gray-800 text-gray-400 border border-gray-600 hover:bg-gray-700'
                  }`}
                  title={showRawJson ? "Hide raw JSON view" : "Show raw JSON view"}
                >
                  <Code size={12} />
                  {showRawJson ? 'JSON ON' : 'JSON'}
                </button>
                <button
                  onClick={() => {
                    const eventsToExport = filteredEvents.length > 0 ? filteredEvents : streamEvents
                    const allEventsJson = JSON.stringify(eventsToExport, null, 2)
                    navigator.clipboard.writeText(allEventsJson)
                    setCopiedEventId('all')
                    setTimeout(() => setCopiedEventId(null), 2000)
                  }}
                  className="flex items-center gap-1 px-3 py-1 text-xs bg-blue-900/50 text-blue-400 border border-blue-700 rounded hover:bg-blue-900/70 transition-colors"
                  title="Copy events as JSON"
                >
                  {copiedEventId === 'all' ? <Check size={12} /> : <FileText size={12} />}
                  Copy
                </button>
                <div className={`w-2 h-2 rounded-full ${isStreaming ? 'bg-green-400 animate-pulse' : 'bg-gray-600'}`} />
              </div>
            </div>

            {/* Search Bar */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-green-600 w-4 h-4" />
              <input
                type="text"
                placeholder="Search events..."
                value={streamSearch}
                onChange={(e) => setStreamSearch(e.target.value)}
                className="w-full pl-10 pr-10 py-2 bg-black border border-green-900 text-green-400 placeholder-green-600 focus:border-green-400 focus:outline-none text-sm"
              />
              {streamSearch && (
                <button
                  onClick={() => setStreamSearch('')}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-green-600 hover:text-green-400"
                >
                  <X size={14} />
                </button>
              )}
            </div>

            {/* Filters */}
            {showFilters && (
              <div className="flex flex-wrap gap-2 p-3 bg-gray-900/30 border border-green-900/50 rounded">
                <div className="text-xs text-green-600 w-full mb-2">Filter by event type:</div>
                {Array.from(eventTypes.entries()).map(([type, count]) => (
                  <button
                    key={type}
                    onClick={() => {
                      const newTypes = new Set(selectedEventTypes)
                      if (newTypes.has(type)) {
                        newTypes.delete(type)
                      } else {
                        newTypes.add(type)
                      }
                      setSelectedEventTypes(newTypes)
                    }}
                    className={`px-2 py-1 text-xs rounded transition-all ${
                      selectedEventTypes.has(type)
                        ? 'bg-green-900/50 text-green-400 border border-green-600'
                        : 'bg-gray-800 text-gray-400 border border-gray-700 hover:bg-gray-700'
                    }`}
                  >
                    {type} ({count})
                  </button>
                ))}
                {selectedEventTypes.size > 0 && (
                  <button
                    onClick={() => setSelectedEventTypes(new Set())}
                    className="px-2 py-1 text-xs bg-red-900/30 text-red-400 border border-red-800 rounded hover:bg-red-900/50 ml-auto"
                  >
                    Clear All
                  </button>
                )}
              </div>
            )}
          </div>
          
          <div 
            ref={streamRef} 
            className="flex-1 overflow-y-auto overflow-x-hidden pr-2"
            onScroll={(e) => {
              const element = e.currentTarget
              const atBottom = element.scrollTop + element.clientHeight >= element.scrollHeight - 10
              
              // Mark that user has scrolled (only if they scrolled up from bottom)
              if (!atBottom && isAtBottom) {
                setUserHasScrolled(true)
              }
              
              // If user scrolls back to bottom, resume auto-scrolling
              if (atBottom && userHasScrolled) {
                setUserHasScrolled(false)
              }
              
              setIsAtBottom(atBottom)
            }}
          >
            {filteredEvents.length > 0 ? (
              <div className="space-y-3 max-w-full">
                {filteredEvents.map((event, idx) => renderEvent(event, idx))}
              </div>
            ) : (
              <div className="flex items-center justify-center h-full">
                <div className="text-center text-gray-500">
                  <div className="text-6xl mb-4">📡</div>
                  {streamEvents.length > 0 ? (
                    <>
                      <p className="text-lg mb-2">No matching events</p>
                      <p className="text-sm">Try adjusting your search or filters</p>
                      <div className="mt-4 text-xs text-gray-600">
                        {streamEvents.length} events available
                      </div>
                    </>
                  ) : (
                    <>
                      <p className="text-lg mb-2">Ready to stream</p>
                      <p className="text-sm">Enter a command and click "Start" to begin execution</p>
                      <div className="mt-4 text-xs text-gray-600">
                        Real-time Claude Flow events will appear here
                      </div>
                    </>
                  )}
                </div>
              </div>
            )}
            
            {/* Scroll to bottom button */}
            {!isAtBottom && streamEvents.length > 0 && (
              <button
                onClick={() => {
                  if (streamRef.current) {
                    streamRef.current.scrollTop = streamRef.current.scrollHeight
                    setIsAtBottom(true)
                    setUserHasScrolled(false) // Resume auto-scrolling
                  }
                }}
                className="absolute bottom-4 right-6 bg-green-900/90 hover:bg-green-800 text-green-300 px-3 py-2 rounded-full shadow-lg transition-all duration-200 flex items-center gap-2 text-sm font-medium z-10"
                title="Scroll to bottom"
              >
                ↓ New Events
                {isStreaming && (
                  <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
                )}
              </button>
            )}
          </div>
        </div>
      </div>
      
      {/* Swarm Visualizer Modal */}
      {showSwarmVisualizer && currentSwarm && (
        <div 
          className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={(e) => {
            // Close modal if clicking on backdrop
            if (e.target === e.currentTarget) {
              setShowSwarmVisualizer(false)
            }
          }}
          onKeyDown={(e) => {
            // Close modal on Escape key
            if (e.key === 'Escape') {
              setShowSwarmVisualizer(false)
            }
          }}
        >
          <div 
            className="bg-gray-950 border-2 border-green-500 rounded-lg shadow-2xl w-full max-w-7xl h-[90vh] flex flex-col"
            onClick={(e) => e.stopPropagation()} // Prevent closing when clicking inside modal
          >
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-green-900">
              <h2 className="text-xl font-bold text-green-400 flex items-center gap-2">
                <Layers size={20} />
                SWARM TOPOLOGY VISUALIZER
              </h2>
              <button
                onClick={() => setShowSwarmVisualizer(false)}
                className="flex items-center gap-2 px-3 py-1 bg-red-900/30 hover:bg-red-900/50 text-red-400 hover:text-red-300 transition-all rounded border border-red-800 hover:border-red-600"
                title="Close visualizer (Esc)"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
                <span className="text-sm font-medium">Close</span>
              </button>
            </div>
            
            {/* Visualizer */}
            <div className="flex-1 p-4">
              <SwarmVisualizer
                agents={agents}
                currentSwarm={currentSwarm}
                onAgentUpdate={(agentId, updates) => {
                  console.log('Agent update:', agentId, updates)
                  // Update agent in state
                  setAgents(prev => prev.map(agent => 
                    agent.id === agentId ? { ...agent, ...updates } : agent
                  ))
                }}
                onTaskAssign={(taskId, agentId) => {
                  console.log('Task assign:', taskId, 'to', agentId)
                  // Handle task assignment
                }}
                onTopologyChange={(topology) => {
                  console.log('Topology change:', topology)
                  // Update swarm topology
                  setCurrentSwarm(prev => prev ? { ...prev, topology } : null)
                }}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default ClaudeFlow