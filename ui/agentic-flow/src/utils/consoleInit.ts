export const initializeConsole = () => {
  // Clear console first
  console.clear()

  // ASCII Art Header
  const asciiArt = `
%c╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗          ║
║  ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝          ║
║  ██║     ██║     ███████║██║   ██║██║  ██║█████╗            ║
║  ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝            ║
║  ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗          ║
║   ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝          ║
║                                                               ║
║                    FLOW v2.0.0 - HIVEMIND                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝`

  // Style for ASCII art
  const asciiStyle = 'color: #2d5016; font-family: monospace;'

  // Print ASCII art
  console.log(asciiArt, asciiStyle)

  // System Information
  console.group('%c[SYSTEM INFORMATION]', 'color: #2d5016; font-weight: bold;')
  console.log('%c├─ Version:', 'color: #3a6b1e;', '2.0.0-alpha')
  console.log('%c├─ Build:', 'color: #3a6b1e;', process.env.NODE_ENV || 'development')
  console.log('%c├─ Platform:', 'color: #3a6b1e;', navigator.platform)
  console.log('%c├─ User Agent:', 'color: #3a6b1e;', navigator.userAgent)
  console.log('%c└─ Language:', 'color: #3a6b1e;', navigator.language)
  console.groupEnd()

  // API Endpoints
  console.group('%c[API ENDPOINTS]', 'color: #1e4d5b; font-weight: bold;')
  console.log('%c├─ REST API:', 'color: #2a6478;', 'http://localhost:3001/api')
  console.log('%c├─ WebSocket:', 'color: #2a6478;', 'ws://localhost:3001')
  console.log('%c├─ Health Check:', 'color: #2a6478;', 'http://localhost:3001/api/health')
  console.log('%c└─ MCP Tools:', 'color: #2a6478;', 'http://localhost:3001/api/mcp/tools')
  console.groupEnd()

  // Available Commands
  console.group('%c[DEVELOPER COMMANDS]', 'color: #5c5c3d; font-weight: bold;')
  console.log('%c├─ claudeFlow.status()', 'color: #7a7a52;', '- Check system status')
  console.log('%c├─ claudeFlow.swarm.init()', 'color: #7a7a52;', '- Initialize swarm')
  console.log('%c├─ claudeFlow.memory.usage()', 'color: #7a7a52;', '- View memory usage')
  console.log('%c├─ claudeFlow.tools.list()', 'color: #7a7a52;', '- List MCP tools')
  console.log('%c├─ claudeFlow.debug.enable()', 'color: #7a7a52;', '- Enable debug mode')
  console.log('%c└─ claudeFlow.help()', 'color: #7a7a52;', '- Show all commands')
  console.groupEnd()

  // Performance Metrics
  if (performance && performance.timing) {
    const loadTime = performance.timing.loadEventEnd - performance.timing.navigationStart
    console.group('%c[PERFORMANCE METRICS]', 'color: #4d2d4d; font-weight: bold;')
    console.log('%c├─ Page Load Time:', 'color: #663d66;', `${loadTime}ms`)
    console.log('%c├─ DOM Ready:', 'color: #663d66;', `${performance.timing.domContentLoadedEventEnd - performance.timing.navigationStart}ms`)
    console.log('%c└─ Resources:', 'color: #663d66;', `${performance.getEntriesByType('resource').length} loaded`)
    console.groupEnd()
  }

  // Security Notice
  console.log('\n%c⚠️  SECURITY NOTICE ⚠️', 'color: #8b0000; font-size: 16px; font-weight: bold;')
  console.log('%cThis is a browser feature intended for developers. Do not paste code here unless you understand what it does!', 'color: #8b0000;')

  // Welcome Message
  console.log('\n%c✨ Welcome to Claude Flow HiveMind Console ✨', 'color: #2d5016; font-size: 14px; font-weight: bold;')
  console.log('%cType claudeFlow.help() for available commands', 'color: #3a6b1e; font-style: italic;')

  // Create global claudeFlow object with helper functions
  ;(window as any).claudeFlow = {
    version: '2.0.0',
    status: () => {
      console.group('%c[SYSTEM STATUS]', 'color: #2d5016; font-weight: bold;')
      console.log('%c├─ API:', 'color: #3a6b1e;', 'Connected')
      console.log('%c├─ WebSocket:', 'color: #3a6b1e;', 'Active')
      console.log('%c├─ Memory:', 'color: #3a6b1e;', `${(performance as any).memory?.usedJSHeapSize ? Math.round((performance as any).memory.usedJSHeapSize / 1048576) : 'N/A'} MB`)
      console.log('%c└─ Uptime:', 'color: #3a6b1e;', `${Math.round(performance.now() / 1000)}s`)
      console.groupEnd()
    },
    swarm: {
      init: () => {
        console.log('%c🐝 Initializing swarm...', 'color: #3a6b1e;')
        return fetch('http://localhost:3001/api/hive/init', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ topology: 'mesh', maxAgents: 5 })
        }).then(r => r.json())
      },
      status: () => {
        return fetch('http://localhost:3001/api/hive/status').then(r => r.json())
      }
    },
    memory: {
      usage: () => {
        if ((performance as any).memory) {
          const mem = (performance as any).memory
          console.table({
            'Total JS Heap Size': `${Math.round(mem.totalJSHeapSize / 1048576)} MB`,
            'Used JS Heap Size': `${Math.round(mem.usedJSHeapSize / 1048576)} MB`,
            'JS Heap Size Limit': `${Math.round(mem.jsHeapSizeLimit / 1048576)} MB`
          })
        } else {
          console.log('%cMemory API not available in this browser', 'color: #8b0000;')
        }
      }
    },
    tools: {
      list: async () => {
        try {
          const response = await fetch('http://localhost:3001/api/mcp/tools')
          const tools = await response.json()
          console.table(tools.map((t: any) => ({ name: t.name, category: t.category, description: t.description })))
          return tools
        } catch (error) {
          console.error('%cFailed to fetch tools:', 'color: #8b0000;', error)
        }
      }
    },
    debug: {
      enabled: false,
      enable: () => {
        (window as any).claudeFlow.debug.enabled = true
        localStorage.setItem('claudeFlow.debug', 'true')
        console.log('%c🔧 Debug mode enabled', 'color: #3a6b1e;')
      },
      disable: () => {
        (window as any).claudeFlow.debug.enabled = false
        localStorage.removeItem('claudeFlow.debug')
        console.log('%c🔧 Debug mode disabled', 'color: #8b0000;')
      }
    },
    help: () => {
      console.log('%c📚 Claude Flow Console Commands:', 'color: #00ff00; font-size: 14px; font-weight: bold;')
      console.log('\n%cSystem Commands:', 'color: #00ffff; font-weight: bold;')
      console.log('  claudeFlow.status()         - Check system status')
      console.log('  claudeFlow.version          - Show version')
      console.log('\n%cSwarm Commands:', 'color: #00ffff; font-weight: bold;')
      console.log('  claudeFlow.swarm.init()     - Initialize a new swarm')
      console.log('  claudeFlow.swarm.status()   - Get swarm status')
      console.log('\n%cMemory Commands:', 'color: #00ffff; font-weight: bold;')
      console.log('  claudeFlow.memory.usage()   - Show memory usage')
      console.log('\n%cTool Commands:', 'color: #00ffff; font-weight: bold;')
      console.log('  claudeFlow.tools.list()     - List all MCP tools')
      console.log('\n%cDebug Commands:', 'color: #00ffff; font-weight: bold;')
      console.log('  claudeFlow.debug.enable()   - Enable debug mode')
      console.log('  claudeFlow.debug.disable()  - Disable debug mode')
    }
  }

  // Check if debug mode was previously enabled
  if (localStorage.getItem('claudeFlow.debug') === 'true') {
    (window as any).claudeFlow.debug.enabled = true
    console.log('%c🔧 Debug mode is enabled', 'color: #00ff00;')
  }
}