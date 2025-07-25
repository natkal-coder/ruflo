import React, { useState, useCallback, useEffect } from 'react'
import { Plus, X, Terminal, Activity } from 'lucide-react'
import ClaudeFlow from './ClaudeFlow'

interface Tab {
  id: string
  name: string
  isActive: boolean
  startTime: Date
}

interface TabState {
  // Each tab has its own isolated state
  command: string
  streamEvents: any[]
  currentSwarm: any
  agents: any[]
  todos: any[]
  isStreaming: boolean
}

const ClaudeFlowTabs: React.FC = () => {
  const [tabs, setTabs] = useState<Tab[]>([
    {
      id: '1',
      name: 'Swarm 1',
      isActive: true,
      startTime: new Date()
    }
  ])
  const [activeTabId, setActiveTabId] = useState('1')
  const [editingTabId, setEditingTabId] = useState<string | null>(null)
  const [editingTabName, setEditingTabName] = useState('')
  const [tabStates, setTabStates] = useState<Record<string, TabState>>({
    '1': {
      command: 'test a concurrent agent swarm to research and build a simple hello world in ./hello/',
      streamEvents: [],
      currentSwarm: null,
      agents: [],
      todos: [],
      isStreaming: false
    }
  })
  const [tabCounter, setTabCounter] = useState(2)

  // Add new tab
  const addTab = useCallback(() => {
    const newId = String(tabCounter)
    const newTab: Tab = {
      id: newId,
      name: `Swarm ${tabCounter}`,
      isActive: false,
      startTime: new Date()
    }
    
    setTabs(prev => [...prev, newTab])
    setTabStates(prev => ({
      ...prev,
      [newId]: {
        command: '',
        streamEvents: [],
        currentSwarm: null,
        agents: [],
        todos: [],
        isStreaming: false
      }
    }))
    setActiveTabId(newId)
    setTabCounter(prev => prev + 1)
  }, [tabCounter])

  // Close tab
  const closeTab = useCallback((tabId: string) => {
    if (tabs.length === 1) return // Keep at least one tab
    
    setTabs(prev => prev.filter(tab => tab.id !== tabId))
    setTabStates(prev => {
      const newStates = { ...prev }
      delete newStates[tabId]
      return newStates
    })
    
    // If closing active tab, switch to another
    if (activeTabId === tabId) {
      const remainingTabs = tabs.filter(tab => tab.id !== tabId)
      if (remainingTabs.length > 0) {
        setActiveTabId(remainingTabs[0].id)
      }
    }
  }, [tabs, activeTabId])

  // Switch tab
  const switchTab = useCallback((tabId: string) => {
    setActiveTabId(tabId)
  }, [])

  // Update tab name
  const updateTabName = useCallback((tabId: string, name: string) => {
    setTabs(prev => prev.map(tab => 
      tab.id === tabId ? { ...tab, name } : tab
    ))
  }, [])

  // Update tab state from child component
  const updateTabState = useCallback((updates: Partial<TabState>) => {
    setTabStates(prev => ({
      ...prev,
      [activeTabId]: {
        ...prev[activeTabId],
        ...updates
      }
    }))
  }, [activeTabId])

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ctrl/Cmd + T: New tab
      if ((e.ctrlKey || e.metaKey) && e.key === 't') {
        e.preventDefault()
        addTab()
      }
      // Ctrl/Cmd + W: Close current tab
      else if ((e.ctrlKey || e.metaKey) && e.key === 'w') {
        e.preventDefault()
        if (tabs.length > 1) {
          closeTab(activeTabId)
        }
      }
      // Ctrl/Cmd + Tab: Next tab
      else if ((e.ctrlKey || e.metaKey) && e.key === 'Tab' && !e.shiftKey) {
        e.preventDefault()
        const currentIndex = tabs.findIndex(tab => tab.id === activeTabId)
        const nextIndex = (currentIndex + 1) % tabs.length
        setActiveTabId(tabs[nextIndex].id)
      }
      // Ctrl/Cmd + Shift + Tab: Previous tab
      else if ((e.ctrlKey || e.metaKey) && e.key === 'Tab' && e.shiftKey) {
        e.preventDefault()
        const currentIndex = tabs.findIndex(tab => tab.id === activeTabId)
        const prevIndex = currentIndex === 0 ? tabs.length - 1 : currentIndex - 1
        setActiveTabId(tabs[prevIndex].id)
      }
      // Ctrl/Cmd + 1-9: Switch to specific tab
      else if ((e.ctrlKey || e.metaKey) && e.key >= '1' && e.key <= '9') {
        e.preventDefault()
        const tabIndex = parseInt(e.key) - 1
        if (tabIndex < tabs.length) {
          setActiveTabId(tabs[tabIndex].id)
        }
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [tabs, activeTabId, addTab, closeTab])

  const activeTab = tabs.find(tab => tab.id === activeTabId)
  const activeTabState = tabStates[activeTabId]

  return (
    <div className="h-full flex flex-col bg-black">
      {/* Tab Bar */}
      <div className="flex items-center bg-gray-950 border-b-2 border-green-900">
        <div className="flex-1 flex items-center overflow-x-auto scrollbar-thin scrollbar-thumb-green-600 scrollbar-track-gray-900 min-h-[40px]">
          {tabs.map((tab, index) => (
            <div
              key={tab.id}
              className={`relative group flex items-center min-w-[150px] max-w-[250px] h-full cursor-pointer transition-all ${
                tab.id === activeTabId
                  ? 'bg-black text-green-400'
                  : 'bg-gray-900 text-green-600 hover:bg-gray-800 hover:text-green-400'
              }`}
              style={{
                clipPath: tab.id === activeTabId 
                  ? 'polygon(0 0, calc(100% - 15px) 0, 100% 100%, 0 100%)' 
                  : 'polygon(0 0, calc(100% - 15px) 0, calc(100% - 5px) 100%, 10px 100%)',
                marginLeft: index > 0 ? '-10px' : '0',
                zIndex: tab.id === activeTabId ? 10 : tabs.length - index
              }}
              onClick={() => switchTab(tab.id)}
            >
              <div className="px-4 py-2 flex items-center">
                <Terminal className="w-3 h-3 mr-2 flex-shrink-0" />
                {editingTabId === tab.id ? (
                  <input
                    type="text"
                    value={editingTabName}
                    onChange={(e) => setEditingTabName(e.target.value)}
                    onBlur={() => {
                      updateTabName(tab.id, editingTabName || tab.name)
                      setEditingTabId(null)
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        updateTabName(tab.id, editingTabName || tab.name)
                        setEditingTabId(null)
                      } else if (e.key === 'Escape') {
                        setEditingTabId(null)
                      }
                    }}
                    className="flex-1 bg-transparent border-b border-green-400 text-xs font-mono outline-none"
                    autoFocus
                    onClick={(e) => e.stopPropagation()}
                  />
                ) : (
                  <span 
                    className="flex-1 text-xs font-mono truncate"
                    onDoubleClick={(e) => {
                      e.stopPropagation()
                      setEditingTabId(tab.id)
                      setEditingTabName(tab.name)
                    }}
                  >
                    {tab.name}
                  </span>
                )}
                {tabStates[tab.id]?.isStreaming && (
                  <Activity className="w-3 h-3 ml-1 text-green-400 animate-pulse" />
                )}
                {tabs.length > 1 && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      closeTab(tab.id)
                    }}
                    className="ml-2 opacity-0 group-hover:opacity-100 transition-opacity"
                  >
                    <X className="w-3 h-3 hover:text-red-400" />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
        
        {/* Add Tab Button */}
        <button
          onClick={addTab}
          className="px-3 py-2 bg-gray-900 hover:bg-gray-800 text-green-600 hover:text-green-400 border-l border-green-900/50 transition-all"
          title="New swarm tab"
        >
          <Plus className="w-4 h-4" />
        </button>
      </div>

      {/* Tab Content */}
      <div className="flex-1 overflow-y-auto">
        {activeTab && activeTabState && (
          <ClaudeFlow
            key={activeTabId}
            tabId={activeTabId}
            tabName={activeTab.name}
            onTabNameChange={(name) => updateTabName(activeTabId, name)}
            onStateChange={updateTabState}
            initialState={activeTabState}
          />
        )}
      </div>
    </div>
  )
}

export default ClaudeFlowTabs