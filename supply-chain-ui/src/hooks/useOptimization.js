import { useState, useCallback, useEffect } from 'react';
import apiService from '../api';

// Module-level state to survive component unmounts during Keycloak state transitions
// This is necessary because Dashboard unmounts/remounts during Keycloak auth flow
let modulePollingState = {
  isPolling: false,
  intervalId: null,
  timeoutId: null,
  requestId: null,
  onComplete: null,  // Callback to update React state when polling completes
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

      // If backend requires user consent (Keycloak returned request_token), redirect to consent URL
      if (response.consent_required && response.consent_url) {
        setIsRunning(false);
        console.log('User consent required for agent, redirecting to consent page', response.consent_url);
        window.location.href = response.consent_url;
        return;
      }

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

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  // When returning from AAuth consent, URL has ?aauth_authorized=1&request_id=...
  // (or request_id was persisted in sessionStorage by index.js if Keycloak stripped the URL)
  // Backend has already started the optimization; start polling for that request_id.
  //
  // IMPORTANT: Dashboard unmounts/remounts during Keycloak state transitions.
  // We use module-level state to survive these unmounts and keep polling running.
  useEffect(() => {
    console.log('[useOptimization] 🔄 Post-consent useEffect running');
    console.log('[useOptimization] Module polling state:', JSON.stringify({
      isPolling: modulePollingState.isPolling,
      requestId: modulePollingState.requestId,
      hasInterval: !!modulePollingState.intervalId,
      hasTimeout: !!modulePollingState.timeoutId,
    }));

    // Check for AAuth error (backend redirected here after consent failed)
    const params = new URLSearchParams(window.location.search);
    const urlError = params.get('aauth_error');
    const storedError = sessionStorage.getItem('aauth_error');
    const storedErrorDesc = sessionStorage.getItem('aauth_error_description');
    if (urlError === '1' || storedError) {
      const errCode = params.get('error') || storedError || 'unknown';
      const errDesc = params.get('error_description') || storedErrorDesc || 'AAuth consent flow failed';
      console.log('[useOptimization] ⚠️ AAuth error detected:', errCode, errDesc);
      setError(`AAuth consent failed: ${errDesc} (${errCode})`);
      setIsRunning(false);
      // Clear URL params and sessionStorage
      const url = new URL(window.location.href);
      url.searchParams.delete('aauth_error');
      url.searchParams.delete('error');
      url.searchParams.delete('error_description');
      url.searchParams.delete('request_id');
      window.history.replaceState({}, '', url.pathname + (url.search || ''));
      sessionStorage.removeItem('aauth_error');
      sessionStorage.removeItem('aauth_error_description');
      sessionStorage.removeItem('aauth_error_request_id');
      return;
    }
    
    // If module-level polling is already in progress, just reconnect state updates
    if (modulePollingState.isPolling) {
      console.log('[useOptimization] 🔗 Reconnecting to existing polling session');
      // Update the callback to use current component's setState functions
      modulePollingState.onComplete = (data) => {
        console.log('[useOptimization] 🔗 Reconnected callback received data');
        if (data.activities) setActivities(data.activities);
        if (data.progress !== undefined) setProgress(data.progress);
        if (data.results) {
          setResults(data.results);
          setShowResults(true);
        }
        if (data.error) setError(data.error);
        if (data.isRunning !== undefined) setIsRunning(data.isRunning);
      };
      // Sync current state
      setRequestId(modulePollingState.requestId);
      setIsRunning(true);
      return;
    }
    
    // Get the request_id - first from URL, then from sessionStorage
    const urlAuthorized = params.get('aauth_authorized');
    const urlRequestId = params.get('request_id');
    
    console.log('[useOptimization] Current URL:', window.location.href);
    console.log('[useOptimization] URL aauth_authorized:', urlAuthorized);
    console.log('[useOptimization] URL request_id:', urlRequestId);
    
    let rid = urlAuthorized === '1' ? urlRequestId : null;
    console.log('[useOptimization] rid from URL:', rid);
    
    if (!rid) {
      // Check sessionStorage (index.js may have saved it before Keycloak redirected)
      rid = sessionStorage.getItem('aauth_return_request_id');
      console.log('[useOptimization] rid from sessionStorage:', rid);
    }
    
    // Also check the pending flag
    const pendingFlag = sessionStorage.getItem('aauth_return_pending');
    console.log('[useOptimization] aauth_return_pending flag:', pendingFlag);
    
    if (!rid) {
      console.log('[useOptimization] ❌ No request_id found, skipping consent return handling');
      return;
    }

    console.log('[useOptimization] ✅ Found request_id for consent return:', rid);
    
    // Clear the request_id from sessionStorage
    sessionStorage.removeItem('aauth_return_request_id');
    sessionStorage.removeItem('aauth_return_pending');
    
    // Clear params from URL
    const url = new URL(window.location.href);
    url.searchParams.delete('aauth_authorized');
    url.searchParams.delete('request_id');
    window.history.replaceState({}, '', url.pathname + (url.search || ''));
    console.log('[useOptimization] Cleared URL params and sessionStorage request_id');

    // Set up module-level polling state
    modulePollingState.isPolling = true;
    modulePollingState.requestId = rid;
    
    // Set up callback for state updates
    modulePollingState.onComplete = (data) => {
      console.log('[useOptimization] Callback received data:', data);
      if (data.activities) setActivities(data.activities);
      if (data.progress !== undefined) setProgress(data.progress);
      if (data.results) {
        setResults(data.results);
        setShowResults(true);
      }
      if (data.error) setError(data.error);
      if (data.isRunning !== undefined) setIsRunning(data.isRunning);
    };

    console.log('[useOptimization] Setting state: requestId, isRunning=true');
    setRequestId(rid);
    setIsRunning(true);
    setProgress(0);
    setError(null);

    console.log('[useOptimization] Starting 1.5s delay before polling...');
    
    modulePollingState.timeoutId = setTimeout(() => {
      console.log('[useOptimization] 🚀 Starting progress polling for:', rid);
      
      modulePollingState.intervalId = setInterval(async () => {
        console.log('[useOptimization] 📊 Polling progress for:', rid);
        try {
          const progressData = await apiService.getOptimizationProgress(rid);
          console.log('[useOptimization] Progress response:', progressData);
          
          // Update progress via callback
          if (modulePollingState.onComplete) {
            modulePollingState.onComplete({ progress: progressData.progress_percentage ?? 0 });
          }
          
          if (progressData.activities?.length) {
            console.log('[useOptimization] Activities received:', progressData.activities.length);
            if (modulePollingState.onComplete) {
              // Sort activities by timestamp (most recent first)
              const sortedActivities = [...progressData.activities].sort(
                (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
              );
              modulePollingState.onComplete({ activities: sortedActivities });
            }
          }
          
          const status = (progressData.status || '').toLowerCase();
          console.log('[useOptimization] Status:', status);
          
          if (status === 'completed') {
            console.log('[useOptimization] ✅ Optimization completed!');
            if (modulePollingState.intervalId) {
              clearInterval(modulePollingState.intervalId);
              modulePollingState.intervalId = null;
            }
            
            if (modulePollingState.onComplete) {
              modulePollingState.onComplete({ isRunning: false, progress: 100 });
            }
            
            const reqId = progressData.request_id || rid;
            console.log('[useOptimization] Fetching results for:', reqId);
            
            setTimeout(async () => {
              try {
                const resultsData = await apiService.getOptimizationResults(reqId);
                console.log('[useOptimization] Results received:', resultsData);
                if (modulePollingState.onComplete) {
                  modulePollingState.onComplete({ results: resultsData });
                }
              } catch (resErr) {
                console.error('[useOptimization] Error fetching results after consent:', resErr);
              }
              // Clean up module state
              modulePollingState.isPolling = false;
              modulePollingState.requestId = null;
            }, 1000);
            
          } else if (status === 'failed') {
            console.log('[useOptimization] ❌ Optimization failed');
            if (modulePollingState.intervalId) {
              clearInterval(modulePollingState.intervalId);
              modulePollingState.intervalId = null;
            }
            if (modulePollingState.onComplete) {
              modulePollingState.onComplete({
                isRunning: false,
                error: 'Optimization failed: ' + (progressData.error || 'Unknown error')
              });
            }
            // Clean up module state
            modulePollingState.isPolling = false;
            modulePollingState.requestId = null;
          }
        } catch (err) {
          console.error('[useOptimization] Error polling progress after consent:', err);
        }
      }, 2000);
    }, 1500);

    // Cleanup: DON'T clear the module-level polling on unmount!
    // The polling needs to survive Dashboard unmount/remount cycles.
    return () => {
      console.log('[useOptimization] Cleanup called, but NOT clearing module polling');
      // Don't clear timeouts/intervals - they need to survive remounts
    };
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
    startOptimization,
    clearOptimization,
    clearAllActivities,
    selectActivity,
    createResultsFromActivity,
    clearError
  };
};
