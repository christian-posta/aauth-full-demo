import { useState, useCallback, useEffect, useRef } from 'react';
import apiService from '../api';

// Module-level state to survive component unmounts during Keycloak state transitions
// This is necessary because Dashboard unmounts/remounts during Keycloak auth flow
let modulePollingState = {
  isPolling: false,
  intervalId: null,
  timeoutId: null,
  requestId: null,
  onComplete: null,  // Callback to update React state when polling completes
  restoredState: null,  // Cache restored state for remounts
  hasRestoredOnce: false,  // Track if we've restored at least once
};

export const useOptimization = () => {
  const [activities, setActivities] = useState([]);
  const [isRunning, setIsRunning] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState(null);
  const [selectedActivityId, setSelectedActivityId] = useState(null);
  const [error, setError] = useState(null);
  const [requestId, setRequestId] = useState(null);
  const [promptText, setPromptText] = useState('');
  const [interactionData, setInteractionData] = useState(null); // { url, code } when PS requires consent
  const popupRef = useRef(null);
  
  // Use a ref to track current activities value for closures
  const activitiesRef = useRef(activities);
  
  // Keep ref in sync with state
  useEffect(() => {
    activitiesRef.current = activities;
  }, [activities]);

  const startOptimization = useCallback(async (customPrompt = '') => {
    try {
      setError(null);
      setIsRunning(true);
      setProgress(0);
      setShowResults(false);
      setResults(null);
      // Don't clear selectedActivityId here - let the auto-selection handle it

      // Start optimization with custom prompt
      const response = await apiService.startOptimization({
        scenario: 'laptop_procurement',
        custom_prompt: customPrompt.trim() || 'optimize laptop supply chain',
        constraints: {
          budget_limit: 500000,
          delivery_time: '2 weeks',
          quality_requirement: 'enterprise_grade'
        }
      });

      setRequestId(response.request_id);
      console.log('Optimization started:', response);

      // Poll for progress
      const progressInterval = setInterval(async () => {
        try {
          const progressData = await apiService.getOptimizationProgress(response.request_id);
          console.log('Progress data received:', progressData);
          setProgress(progressData.progress_percentage || 0);
          
          // Update activities from progress data - append new activities to existing ones
          if (progressData.activities && progressData.activities.length > 0) {
            console.log('📋 Progress data activities:', JSON.stringify(progressData.activities, null, 2));
            setActivities(prevActivities => {
              console.log('📋 Previous activities:', JSON.stringify(prevActivities, null, 2));
              
              // Check if we already have these activities to avoid duplicates
              const newActivities = progressData.activities.filter(newActivity => 
                !prevActivities.some(existingActivity => 
                  existingActivity.id === newActivity.id && 
                  existingActivity.timestamp === newActivity.timestamp
                )
              );
              
              console.log('📋 New activities to add:', JSON.stringify(newActivities, null, 2));
              
              if (newActivities.length > 0) {
                // Add new activities and sort by timestamp (most recent first)
                const allActivities = [...prevActivities, ...newActivities];
                const sortedActivities = allActivities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
                console.log('📋 Final sorted activities:', JSON.stringify(sortedActivities, null, 2));
                return sortedActivities;
              }
              return prevActivities;
            });
          }

          if (progressData.status === 'interaction_required') {
            // PS/AS requires human consent before the agent can proceed.
            // Open a popup so the user stays in context; backend is still polling.
            if (progressData.interaction_url && progressData.interaction_code) {
              setInteractionData({
                url: progressData.interaction_url,
                code: progressData.interaction_code,
              });
              // Open the consent page in a small popup if not already open
              if (!popupRef.current || popupRef.current.closed) {
                popupRef.current = window.open(
                  progressData.interaction_url,
                  'aauth-consent',
                  'width=520,height=620,left=200,top=100'
                );
              }
            }
            // Don't stop polling — backend is waiting for the PS to approve
            return;
          }

          // Once we advance past interaction_required, clear the banner and close popup
          if (interactionData) {
            setInteractionData(null);
            if (popupRef.current && !popupRef.current.closed) {
              popupRef.current.close();
            }
          }

          if (progressData.status === 'completed') {
            clearInterval(progressInterval);
            setIsRunning(false);
            setProgress(100);

            // Always use the request_id from the progress data
            const completedRequestId = progressData.request_id;
            console.log('Optimization completed, fetching results for:', completedRequestId);
            console.log('Original request ID was:', response.request_id);

            if (!completedRequestId) {
              console.error('No request_id in progress data:', progressData);
              return;
            }

            // Wait a moment for results to be generated, then get results
            setTimeout(async () => {
              try {
                const resultsData = await apiService.getOptimizationResults(completedRequestId);
                setResults(resultsData);
                setShowResults(true);
              } catch (resultsErr) {
                console.error('Error fetching results:', resultsErr);
                // Don't show error to user, just log it
              }
            }, 1000);

          } else if (progressData.status === 'failed') {
            clearInterval(progressInterval);
            setIsRunning(false);
            setError('Optimization failed: ' + (progressData.error || 'Unknown error'));
          }
        } catch (err) {
          console.error('Error polling progress:', err);
        }
      }, 2000);

    } catch (err) {
      console.error('Failed to start optimization:', err);
      setError(err.message);
      setIsRunning(false);
    }
  }, []);

  const clearOptimization = useCallback(() => {
    // Clear current optimization state but keep activity history
    setShowResults(false);
    setResults(null);
    setError(null);
    setProgress(0);
    setRequestId(null);
    setSelectedActivityId(null);
  }, []);

  const clearAllActivities = useCallback(() => {
    // Clear all activities (for when user explicitly wants to clear history)
    setActivities([]);
    setSelectedActivityId(null);
    setResults(null);
    setShowResults(false);
    setPromptText('');
  }, []);

  const createResultsFromActivity = useCallback((activity) => {
    console.log('🔧 createResultsFromActivity called with:', JSON.stringify(activity, null, 2));
    
    if (activity && activity.details) {
      // Create a simple result object from the activity
      const mockResults = {
        request_id: `activity-${activity.id}`,
        summary: {
          total_cost: 0,
          expected_delivery: 'N/A',
          cost_savings: 0,
          efficiency: 0
        },
        recommendations: [
          {
            item: 'Supply Chain Analysis',
            quantity: 1,
            unit_price: 0,
            supplier: 'A2A Agent',
            lead_time: 'Immediate',
            total: 0
          }
        ],
        reasoning: [
          {
            decision: 'Analysis Completed',
            agent: activity.agent,
            rationale: activity.details
          }
        ],
        completed_at: activity.timestamp
      };
      
      console.log('🧹 Clearing existing results...');
      // Clear any existing results and set only this one
      setResults(null);
      setShowResults(false);
      
      console.log('⏰ Setting timeout to create new results...');
      // Use setTimeout to ensure the clear happens before setting new results
      setTimeout(() => {
        console.log('✅ Setting new results:', mockResults);
        setResults(mockResults);
        setShowResults(true);
      }, 0);
    } else {
      console.log('❌ No activity or details found:', activity);
    }
  }, []);

  const selectActivity = useCallback(async (activityId) => {
    console.log('🎯 selectActivity called with ID:', activityId);
    console.log('📋 Available activities:', JSON.stringify(activities, null, 2));
    
    setSelectedActivityId(activityId);
    
    // Find the selected activity
    const selectedActivity = activities.find(activity => activity.id === activityId);
    console.log('🔍 Found selected activity:', JSON.stringify(selectedActivity, null, 2));
    
    if (selectedActivity) {
      createResultsFromActivity(selectedActivity);
    } else {
      console.log('❌ No activity found with ID:', activityId);
    }
  }, [activities, createResultsFromActivity]);

  // Auto-select the most recent activity when activities change
  useEffect(() => {
    console.log('🔄 Auto-selection effect triggered');
    console.log('📊 Activities length:', activities.length);
    console.log('🎯 Current selectedActivityId:', selectedActivityId);
    
    if (activities.length > 0) {
      // Since activities are now sorted by timestamp (most recent first), just take the first one
      const mostRecentActivity = activities[0];
      console.log('⭐ Most recent activity:', mostRecentActivity);
      
      // Always select the most recent activity when activities change
      // This ensures we show the latest response
      if (mostRecentActivity) {
        // Check if this is a different activity (by timestamp, not just ID)
        const currentSelectedActivity = activities.find(a => a.id === selectedActivityId);
        console.log('🔍 Current selected activity:', JSON.stringify(currentSelectedActivity, null, 2));
        console.log('🔍 Most recent activity:', JSON.stringify(mostRecentActivity, null, 2));
        
        const isDifferentActivity = !currentSelectedActivity || 
          currentSelectedActivity.timestamp !== mostRecentActivity.timestamp;
        
        console.log('🔍 Is different activity?', isDifferentActivity);
        
        if (isDifferentActivity) {
          console.log('🎯 Auto-selecting most recent activity:', mostRecentActivity.id);
          console.log('🔧 About to call setSelectedActivityId with:', mostRecentActivity.id);
          
          // Set the selected activity ID first
          setSelectedActivityId(mostRecentActivity.id);
          
          // Then create results for this activity
          console.log('🔧 setSelectedActivityId called, now calling createResultsFromActivity');
          createResultsFromActivity(mostRecentActivity);
        } else {
          console.log('⏭️ Same activity already selected (same ID and timestamp)');
        }
      }
    } else {
      console.log('⏭️ No activities available');
    }
  }, [activities, selectedActivityId, createResultsFromActivity]);

  // Monitor selectedActivityId changes
  useEffect(() => {
    console.log('🎯 selectedActivityId changed to:', selectedActivityId);
  }, [selectedActivityId]);

  // Listen for postMessage from the auth-callback popup page
  useEffect(() => {
    const handler = (event) => {
      if (event.data?.type === 'aauth-consent-complete') {
        setInteractionData(null);
        if (popupRef.current && !popupRef.current.closed) {
          popupRef.current.close();
        }
      }
    };
    window.addEventListener('message', handler);
    return () => window.removeEventListener('message', handler);
  }, []);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  useEffect(() => {
    if (!modulePollingState.isPolling) {
      return;
    }
    modulePollingState.onComplete = (data) => {
      if (data.activities) {
        setActivities((prevActivities) => {
          const existingMap = new Map();
          prevActivities.forEach((act) => {
            existingMap.set(`${act.id}_${act.timestamp}`, act);
          });
          data.activities.forEach((act) => {
            const key = `${act.id}_${act.timestamp}`;
            if (!existingMap.has(key)) {
              existingMap.set(key, act);
            }
          });
          return Array.from(existingMap.values()).sort(
            (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
          );
        });
      }
      if (data.progress !== undefined) setProgress(data.progress);
      if (data.results) {
        setResults(data.results);
        setShowResults(true);
      }
      if (data.error) setError(data.error);
      if (data.isRunning !== undefined) setIsRunning(data.isRunning);
    };
    setRequestId(modulePollingState.requestId);
    setIsRunning(true);
  }, []);

  return {
    activities,
    isRunning,
    showResults,
    progress,
    results,
    selectedActivityId,
    error,
    requestId,
    promptText,
    interactionData,
    setPromptText,
    startOptimization,
    clearOptimization,
    clearAllActivities,
    selectActivity,
    createResultsFromActivity,
    clearError
  };
};
