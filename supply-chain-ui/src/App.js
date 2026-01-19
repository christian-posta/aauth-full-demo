import React, { useEffect, useState } from 'react';
import { Shield, Clock, CheckCircle, DollarSign, Package, TrendingUp, AlertCircle } from 'lucide-react';
import { useKeycloak } from './hooks/useKeycloak';
import { useOptimization } from './hooks/useOptimization';
import Login from './components/Login';
import UserDropdown from './components/UserDropdown';
import MarkdownRenderer from './components/MarkdownRenderer';
import apiService from './api';

// Loading component
const LoadingScreen = () => (
  <div className="min-h-screen bg-slate-50 flex items-center justify-center">
    <div className="text-center">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
      <p className="text-gray-600">Loading...</p>
    </div>
  </div>
);

// Header Component
const Header = ({ user, onLogout, keycloak }) => {
  // Safety check for user object
  if (!user) {
    return (
      <div className="bg-white shadow-sm border-b border-gray-200 px-6 py-4">
        <div className="flex items-center justify-center">
          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600 mr-2"></div>
          <span className="text-gray-600">Loading user data...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white shadow-sm border-b border-gray-200 px-6 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <Shield className="h-8 w-8 text-blue-600" />
            <h1 className="text-xl font-bold text-gray-900">AcmeCorp Supply Chain</h1>
          </div>
        </div>
        <div className="flex items-center space-x-4">
          <UserDropdown 
            user={user} 
            onLogout={onLogout} 
            keycloak={keycloak}
          />
        </div>
      </div>
    </div>
  );
};

// Delegation Chain Visualization
const DelegationChain = ({ delegation }) => {
  const renderChain = (del, depth = 0) => {
    if (!del.act) {
      return (
        <div className="text-xs bg-blue-50 text-blue-800 px-2 py-1 rounded">
          {del.sub}
        </div>
      );
    }

    return (
      <div className="flex items-center space-x-2">
        <div className="text-xs bg-blue-50 text-blue-800 px-2 py-1 rounded">
          {del.sub}
        </div>
        <span className="text-gray-400">→</span>
        {renderChain(del.act, depth + 1)}
      </div>
    );
  };

  return (
    <div className="mt-2">
      <div className="text-xs text-gray-500 mb-1">Delegation Chain:</div>
      {renderChain(delegation)}
      <div className="text-xs text-gray-500 mt-1">
        Scope: <span className="font-mono bg-gray-100 px-1 py-0.5 rounded">{delegation.scope}</span>
      </div>
    </div>
  );
};

// Activity Feed Component
const ActivityFeed = ({ activities, isRunning, error, selectedActivityId, onActivitySelect, onClear }) => {
  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'running':
        return <div className="h-4 w-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />;
      default:
        return <Clock className="h-4 w-4 text-gray-400" />;
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 h-full">
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold text-gray-900 flex items-center space-x-2">
            <TrendingUp className="h-5 w-5 text-blue-600" />
            <span>Agent Activity Feed</span>
          </h2>
          {activities.length > 0 && (
            <button
              onClick={onClear}
              className="text-sm text-gray-500 hover:text-gray-700"
            >
              Clear
            </button>
          )}
        </div>
      </div>
      
      <div className="p-4 space-y-3 max-h-96 overflow-y-auto">
        {error && (
          <div className="flex items-center space-x-2 p-3 bg-red-50 border border-red-200 rounded-lg">
            <AlertCircle className="h-4 w-4 text-red-500" />
            <span className="text-sm text-red-700">{error}</span>
          </div>
        )}
        
        {activities.length === 0 && !isRunning && !error && (
          <div className="text-center text-gray-500 py-8">
            <Clock className="h-12 w-12 text-gray-300 mx-auto mb-2" />
            <p>No activities yet</p>
            <p className="text-sm">Start optimization to see agent activities</p>
          </div>
        )}
        
        {activities.map((activity, index) => (
          <div 
            key={index} 
            className={`flex items-start space-x-3 p-3 rounded-lg cursor-pointer transition-all duration-200 ${
              selectedActivityId === activity.id 
                ? 'bg-blue-100 border-2 border-blue-300 shadow-md' 
                : 'bg-gray-50 hover:bg-gray-100 border-2 border-transparent'
            }`}
            onClick={() => onActivitySelect(activity.id)}
          >
            {getStatusIcon(activity.status)}
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900">
                {activity.action === 'supply_chain_optimization' ? 'Supply Chain Optimization Completed' : activity.description || activity.action}
              </p>
              <p className="text-xs text-gray-500">{activity.timestamp}</p>
            </div>
            {selectedActivityId === activity.id && (
              <div className="flex-shrink-0">
                <div className="w-2 h-2 bg-blue-600 rounded-full"></div>
              </div>
            )}
          </div>
        ))}
        
        {isRunning && (
          <div className="flex items-center space-x-3 p-3 bg-blue-50 border border-blue-200 rounded-lg">
            <div className="h-4 w-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            <div className="flex-1">
              <p className="text-sm font-medium text-blue-900">Optimization in progress...</p>
              <p className="text-xs text-blue-700">Agents are working on your request</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// Results Panel Component
const ResultsPanel = ({ results, isVisible }) => {
  if (!isVisible || !results) return null;

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
      <h2 className="text-xl font-semibold text-gray-900 mb-4 flex items-center space-x-2">
        <CheckCircle className="h-6 w-6 text-green-600" />
        <span>Optimization Results</span>
      </h2>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Cost Savings */}
        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
          <div className="flex items-center space-x-2">
            <DollarSign className="h-5 w-5 text-green-600" />
            <h3 className="font-medium text-green-900">Cost Savings</h3>
          </div>
          <p className="text-2xl font-bold text-green-600 mt-2">
            ${results.costSavings?.toLocaleString() || '0'}
          </p>
          <p className="text-sm text-green-700 mt-1">
            {results.costSavingsPercentage || 0}% reduction
          </p>
        </div>
        
        {/* Delivery Time */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-center space-x-2">
            <Clock className="h-5 w-5 text-blue-600" />
            <h3 className="font-medium text-blue-900">Delivery Time</h3>
          </div>
          <p className="text-2xl font-bold text-blue-600 mt-2">
            {results.deliveryTime || 'N/A'}
          </p>
          <p className="text-sm text-blue-700 mt-1">
            Optimized from {results.originalDeliveryTime || 'N/A'}
          </p>
        </div>
        
        {/* Quality Score */}
        <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
          <div className="flex items-center space-x-2">
            <Shield className="h-5 w-5 text-purple-600" />
            <h3 className="font-medium text-purple-900">Quality Score</h3>
          </div>
          <p className="text-2xl font-bold text-purple-600 mt-2">
            {results.qualityScore || 'N/A'}
          </p>
          <p className="text-sm text-purple-700 mt-1">
            {results.qualityRating || 'N/A'} rating
          </p>
        </div>
      </div>
      
              {/* Detailed Results */}
        {results.recommendations && (
          <div className="mt-6">
            <h3 className="text-lg font-medium text-gray-900 mb-3">Recommendations</h3>
            <div className="space-y-2">
              {results.recommendations.map((rec, index) => (
                <div key={index} className="flex items-start space-x-2 p-3 bg-gray-50 rounded-lg">
                  <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                  <div>
                    <div className="text-sm font-medium text-gray-900">
                      <MarkdownRenderer content={rec.title} showToggle={false} />
                    </div>
                    <div className="text-sm text-gray-600">
                      <MarkdownRenderer content={rec.description} showToggle={false} />
                    </div>
                    {rec.impact && (
                      <div className="text-xs text-gray-500 mt-1">
                        <span className="font-medium">Impact: </span>
                        <MarkdownRenderer content={rec.impact} showToggle={false} />
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
    </div>
  );
};

// Main Dashboard Component
const Dashboard = () => {
  const { user, logout, keycloak } = useKeycloak();
  const {
    activities,
    isRunning,
    showResults,
    progress,
    results,
    selectedActivityId,
    error,
    startOptimization,
    clearOptimization,
    clearAllActivities,
    selectActivity,
    createResultsFromActivity
  } = useOptimization();
  
  const [optimizationPrompt, setOptimizationPrompt] = useState('');

  // Set Keycloak instance in API service
  useEffect(() => {
    if (keycloak) {
      apiService.setKeycloak(keycloak);
    }
  }, [keycloak]);

  return (
    <div className="min-h-screen bg-slate-50">
      <Header user={user} onLogout={logout} keycloak={keycloak} />
      
      <div className="max-w-7xl mx-auto p-6">
        <div className="grid grid-cols-12 gap-6 h-[calc(100vh-120px)]">
          {/* Left Panel - Activity Feed */}
          <div className="col-span-4">
            <ActivityFeed 
              activities={activities} 
              isRunning={isRunning} 
              error={error}
              selectedActivityId={selectedActivityId}
              onActivitySelect={selectActivity}
              onClear={clearAllActivities}
            />
          </div>

          {/* Right Panel - Main Content */}
          <div className="col-span-8 space-y-6">
            {/* Action Panel */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <div className="text-center">
                <h2 className="text-2xl font-bold text-gray-900 mb-4">Supply Chain Optimization</h2>
                <p className="text-gray-600 mb-6">
                  Customize your optimization request and initiate autonomous agent workflow
                </p>
                
                {/* Custom Prompt Input */}
                <div className="max-w-2xl mx-auto mb-6">
                  <label htmlFor="optimization-prompt" className="block text-sm font-medium text-gray-700 mb-2 text-left">
                    Custom Optimization Prompt
                  </label>
                  <textarea
                    id="optimization-prompt"
                    placeholder="e.g., Analyze our laptop procurement strategy for Q4, focusing on cost optimization and supplier diversity. Consider our budget of $100k and need for 50 units."
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 resize-none"
                    rows={4}
                    value={optimizationPrompt}
                    onChange={(e) => setOptimizationPrompt(e.target.value)}
                    disabled={isRunning}
                  />
                  <p className="text-xs text-gray-500 mt-1 text-left">
                    Describe your specific optimization needs, constraints, or questions for the AI agent
                  </p>
                </div>
                
                <button
                  onClick={() => startOptimization(optimizationPrompt)}
                  disabled={isRunning}
                  className={`inline-flex items-center px-8 py-4 border border-transparent text-lg font-medium rounded-lg ${
                    isRunning 
                      ? 'bg-gray-300 text-gray-500 cursor-not-allowed' 
                      : 'bg-blue-600 text-white hover:bg-blue-700 transform hover:scale-105 transition-all duration-200 shadow-lg hover:shadow-xl'
                  }`}
                >
                  {isRunning ? (
                    <>
                      <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-3"></div>
                      Optimizing...
                    </>
                  ) : (
                    <>
                      <Package className="h-6 w-6 mr-3" />
                      {optimizationPrompt.trim() ? 'Run Custom Optimization' : 'Optimize Laptop Supply Chain'}
                    </>
                  )}
                </button>

                {isRunning && (
                  <div className="mt-6">
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div 
                        className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                        style={{ width: `${progress}%` }}
                      ></div>
                    </div>
                    <p className="text-sm text-gray-500 mt-2">{Math.round(progress)}% complete</p>
                  </div>
                )}
              </div>
            </div>

            {/* Agent Responses Panel */}
            {(() => {
              console.log('🔍 Agent Responses Panel render check:');
              console.log('  - selectedActivityId:', selectedActivityId);
              console.log('  - activities.length:', activities.length);
              console.log('  - activities:', activities);
              return selectedActivityId && activities.length > 0;
            })() && (
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                <h2 className="text-xl font-semibold text-gray-900 mb-4 flex items-center space-x-2">
                  <TrendingUp className="h-6 w-6 text-blue-600" />
                  <span>Selected Agent Response</span>
                </h2>
                
                {(() => {
                  const selectedActivity = activities.find(activity => activity.id === selectedActivityId);
                  if (selectedActivity && selectedActivity.details) {
                    return (
                      <div className="border border-gray-200 rounded-lg p-4">
                        <div className="flex items-center justify-between mb-3">
                          <h3 className="text-lg font-medium text-gray-900">
                            Supply Chain Optimization Analysis
                          </h3>
                          <span className="text-sm text-gray-500">
                            {new Date(selectedActivity.timestamp).toLocaleString()}
                          </span>
                        </div>
                        
                        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                          <MarkdownRenderer 
                            content={selectedActivity.details}
                            className="max-w-none"
                          />
                        </div>
                      </div>
                    );
                  }
                  return (
                    <div className="text-center text-gray-500 py-8">
                      <TrendingUp className="h-12 w-12 text-gray-300 mx-auto mb-2" />
                      <p>No response details available</p>
                    </div>
                  );
                })()}
              </div>
            )}

            {/* Results Panel */}
            <ResultsPanel results={results} isVisible={showResults} />
          </div>
        </div>
      </div>
    </div>
  );
};

// Main App Component
const App = () => {
  const { user, isAuthenticated, isLoading, error, login } = useKeycloak();

  if (isLoading) {
    return <LoadingScreen />;
  }

  if (!isAuthenticated || !user) {
    return <Login onLogin={login} error={error} isLoading={isLoading} />;
  }

  return <Dashboard />;
};

export default App;


