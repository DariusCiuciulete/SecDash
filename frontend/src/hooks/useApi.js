import { useState, useEffect, useCallback } from "react";
import { useAuth } from "../contexts/AuthContext";

const API_BASE_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

export const useApi = () => {
  const { token } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const apiCall = useCallback(async (endpoint, options = {}) => {
    setLoading(true);
    setError(null);

    try {
      const headers = {
        "Content-Type": "application/json",
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
      };

      console.log(`Making API call to: ${API_BASE_URL}${endpoint}`);
      console.log('Headers:', headers);

      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers,
        ...options,
      });

      console.log(`Response status: ${response.status}`);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      console.log('Response data:', data);
      setLoading(false);
      return data;
    } catch (err) {
      console.error('API call error:', err);
      setError(err.message);
      setLoading(false);
      throw err;
    }
  }, [token]);

  return { apiCall, loading, error };
};

export const useScans = () => {
  const [scans, setScans] = useState([]);
  const [assets, setAssets] = useState({});
  const { apiCall, loading, error } = useApi();

  const fetchAssets = useCallback(async () => {
    try {
      console.log('Fetching assets...');
      const data = await apiCall("/api/v1/assets");
      console.log('Assets data received:', data);
      const assetsMap = {};
      (data.items || []).forEach(asset => {
        assetsMap[asset.id] = asset;
      });
      console.log('Assets map created:', assetsMap);
      setAssets(assetsMap);
    } catch (err) {
      console.error("Failed to fetch assets:", err);
    }
  }, [apiCall]);

  const fetchScans = useCallback(async () => {
    try {
      console.log('Fetching scans...');
      console.log('Available assets:', assets);
      const data = await apiCall("/api/v1/scans");
      console.log('Scans data received:', data);
      // Transform backend data to match frontend expectations
      const transformedScans = await Promise.all((data.items || []).map(async (scan) => {
        const asset = assets[scan.asset_id];
        console.log(`Processing scan ${scan.id}, asset:`, asset);
        
        // Fetch current scan status for running scans
        let scanStatus = scan;
        if (scan.status === 'running' || scan.status === 'queued') {
          try {
            const statusData = await apiCall(`/api/v1/scans/${scan.id}/status`);
            scanStatus = { ...scan, ...statusData };
            console.log(`Status for running scan ${scan.id}:`, statusData);
          } catch (err) {
            console.warn("Failed to fetch status for scan:", scan.id);
          }
        }
        
        // Fetch vulnerabilities for completed scans
        let vulnerabilities = [];
        if (scanStatus.status === 'completed') {
          try {
            const vulnData = await apiCall(`/api/v1/vulnerabilities?scan_id=${scan.id}`);
            vulnerabilities = vulnData.items || [];
            console.log(`Vulnerabilities for scan ${scan.id}:`, vulnerabilities);
          } catch (err) {
            console.warn("Failed to fetch vulnerabilities for scan:", scan.id);
          }
        }
        
        // Calculate duration - start from 0 and count upwards
        let durationText = "N/A";
        if (scanStatus.duration_seconds) {
          // Completed scan - use final duration
          const minutes = Math.floor(scanStatus.duration_seconds / 60);
          const seconds = scanStatus.duration_seconds % 60;
          if (minutes > 0) {
            durationText = `${minutes}m ${seconds}s`;
          } else {
            durationText = `${seconds}s`;
          }
        } else if (scanStatus.status === 'running' && scanStatus.started_at) {
          // Running scan - calculate elapsed time from start
          // Ensure proper timezone handling - backend returns UTC timestamps
          // Only add 'Z' if timestamp doesn't already have timezone info
          const startTimeStr = scanStatus.started_at.includes('+') || scanStatus.started_at.includes('Z') 
            ? scanStatus.started_at 
            : scanStatus.started_at + 'Z';
          const startTime = new Date(startTimeStr);
          const currentTime = new Date();
          const elapsedSeconds = Math.max(0, Math.floor((currentTime - startTime) / 1000));
          const minutes = Math.floor(elapsedSeconds / 60);
          const seconds = elapsedSeconds % 60;
          durationText = `${minutes}m ${seconds}s (running)`;
        } else if (scanStatus.status === 'queued') {
          durationText = "Queued";
        }
        
        const transformedScan = {
          scanId: scan.id,
          target: asset ? asset.target : 'Unknown',
          tool: scan.tool,
          profile: scan.profile || 'default',
          status: scanStatus.status,
          progress: scanStatus.progress || (
            scanStatus.status === 'completed' ? 100 : 
            scanStatus.status === 'running' ? 50 : 
            scanStatus.status === 'failed' ? 0 : 
            scanStatus.status === 'queued' ? 5 : 25
          ),
          progress_message: scanStatus.progress_message || scanStatus.status,
          startTime: scanStatus.started_at || scan.created_at,
          endTime: scanStatus.completed_at,
          duration_seconds: scanStatus.duration_seconds,
          duration_text: durationText,
          findings_count: scanStatus.findings_count || 0,
          vulnerability_count: scanStatus.findings_count || 0,
          errorMessage: scanStatus.error_message,
          created_at: scan.created_at,
          result: scanStatus.status === 'completed' ? { 
            findings: vulnerabilities.map(vuln => ({
              host: vuln.host,
              port: vuln.port,
              service: vuln.service,
              severity: vuln.severity,
              description: vuln.description || vuln.name
            })),
            error: scanStatus.error_message
          } : null
        };
        console.log('Transformed scan:', transformedScan);
        return transformedScan;
      }));
      console.log('All transformed scans:', transformedScans);
      setScans(transformedScans);
    } catch (err) {
      console.error("Failed to fetch scans:", err);
    }
  }, [apiCall, assets]);

  const getScanStatus = useCallback(async (scanId) => {
    try {
      const data = await apiCall(`/api/v1/scans/${scanId}/status`);
      return data;
    } catch (err) {
      console.error("Failed to get scan status:", err);
      throw err;
    }
  }, [apiCall]);

  const createScan = useCallback(async (scanData) => {
    try {
      const data = await apiCall("/api/v1/scans", {
        method: "POST",
        body: JSON.stringify(scanData),
      });
      await fetchScans(); // Refresh the list
      return data;
    } catch (err) {
      console.error("Failed to create scan:", err);
      throw err;
    }
  }, [apiCall, fetchScans]);

  const getScanDetails = useCallback(async (scanId) => {
    try {
      const data = await apiCall(`/api/v1/scans/${scanId}`);
      return data;
    } catch (err) {
      console.error("Failed to get scan details:", err);
      throw err;
    }
  }, [apiCall]);

  const stopScan = useCallback(async (scanId) => {
    try {
      const data = await apiCall(`/api/v1/scans/${scanId}/cancel`, {
        method: "POST",
      });
      await fetchScans(); // Refresh the list
      return data;
    } catch (err) {
      console.error("Failed to stop scan:", err);
      throw err;
    }
  }, [apiCall, fetchScans]);

  useEffect(() => {
    fetchAssets();
  }, [fetchAssets]);

  useEffect(() => {
    if (Object.keys(assets).length > 0) {
      fetchScans();
    }
  }, [fetchScans, assets]);

  // Auto-refresh running scans every 5 seconds with smooth updates
  useEffect(() => {
    const runningScans = scans.filter(scan => 
      scan.status === 'running' || scan.status === 'queued'
    );
    
    if (runningScans.length > 0) {
      const interval = setInterval(async () => {
        console.log('Auto-refreshing running scans...');
        
        // Update each running scan individually to avoid full page refresh
        const updatedScans = [...scans];
        let hasUpdates = false;
        
        for (const scan of runningScans) {
          try {
            const response = await fetch(`/api/v1/scans/${scan.scanId}/status`);
            if (response.ok) {
              const scanStatus = await response.json();
              
              // Find and update the scan in the array
              const scanIndex = updatedScans.findIndex(s => s.scanId === scan.scanId);
              if (scanIndex !== -1) {
                // Calculate real-time duration for running scans
                let durationText = "N/A";
                if (scanStatus.duration_seconds) {
                  const minutes = Math.floor(scanStatus.duration_seconds / 60);
                  const seconds = scanStatus.duration_seconds % 60;
                  durationText = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
                } else if (scanStatus.status === 'running' && scanStatus.started_at) {
                  const startTime = new Date(scanStatus.started_at);
                  const currentTime = new Date();
                  const elapsedSeconds = Math.floor((currentTime - startTime) / 1000);
                  const minutes = Math.floor(elapsedSeconds / 60);
                  const seconds = elapsedSeconds % 60;
                  durationText = `${minutes}m ${seconds}s (running)`;
                }
                
                updatedScans[scanIndex] = {
                  ...updatedScans[scanIndex],
                  status: scanStatus.status,
                  progress: scanStatus.progress || updatedScans[scanIndex].progress,
                  progress_message: scanStatus.progress_message || scanStatus.status,
                  duration_seconds: scanStatus.duration_seconds,
                  duration_text: durationText,
                  findings_count: scanStatus.findings_count || 0,
                  vulnerability_count: scanStatus.findings_count || 0,
                  endTime: scanStatus.completed_at,
                  errorMessage: scanStatus.error_message
                };
                hasUpdates = true;
              }
            }
          } catch (error) {
            console.warn(`Failed to update scan ${scan.scanId}:`, error);
          }
        }
        
        // Only update state if there were actual changes
        if (hasUpdates) {
          setScans(updatedScans);
        }
        
        // If all scans completed, do a full refresh to get final data
        const stillRunning = updatedScans.filter(scan => 
          scan.status === 'running' || scan.status === 'queued'
        );
        if (stillRunning.length === 0 && runningScans.length > 0) {
          fetchScans(); // Final refresh when all scans complete
        }
      }, 3000); // Refresh every 3 seconds instead of 5
      
      return () => clearInterval(interval);
    }
  }, [scans, fetchScans, setScans]);

  return {
    scans,
    loading,
    error,
    fetchScans,
    createScan,
    getScanDetails,
    getScanStatus,
    stopScan,
  };
};

export const useAssets = () => {
  const [assets, setAssets] = useState([]);
  const { apiCall, loading, error } = useApi();

  const fetchAssets = useCallback(async () => {
    try {
      const data = await apiCall("/api/v1/assets");
      setAssets(data.items || []);
    } catch (err) {
      console.error("Failed to fetch assets:", err);
    }
  }, [apiCall]);

  const createAsset = useCallback(async (assetData) => {
    try {
      const data = await apiCall("/api/v1/assets", {
        method: "POST",
        body: JSON.stringify(assetData),
      });
      await fetchAssets(); // Refresh the list
      return data;
    } catch (err) {
      console.error("Failed to create asset:", err);
      throw err;
    }
  }, [apiCall, fetchAssets]);

  const updateAsset = useCallback(async (assetId, assetData) => {
    try {
      const data = await apiCall(`/api/v1/assets/${assetId}`, {
        method: "PUT",
        body: JSON.stringify(assetData),
      });
      await fetchAssets(); // Refresh the list
      return data;
    } catch (err) {
      console.error("Failed to update asset:", err);
      throw err;
    }
  }, [apiCall, fetchAssets]);

  const deleteAsset = useCallback(async (assetId) => {
    try {
      await apiCall(`/api/v1/assets/${assetId}`, {
        method: "DELETE",
      });
      await fetchAssets(); // Refresh the list
    } catch (err) {
      console.error("Failed to delete asset:", err);
      throw err;
    }
  }, [apiCall, fetchAssets]);

  const getAssetScans = useCallback(async (assetId) => {
    try {
      const data = await apiCall(`/api/v1/assets/${assetId}/scans`);
      return data.items || [];
    } catch (err) {
      console.error("Failed to get asset scans:", err);
      throw err;
    }
  }, [apiCall]);

  const getAssetVulnerabilities = useCallback(async (assetId) => {
    try {
      const data = await apiCall(`/api/v1/assets/${assetId}/vulnerabilities`);
      return data.items || [];
    } catch (err) {
      console.error("Failed to get asset vulnerabilities:", err);
      throw err;
    }
  }, [apiCall]);

  useEffect(() => {
    fetchAssets();
  }, [fetchAssets]);

  return {
    assets,
    loading,
    error,
    fetchAssets,
    createAsset,
    updateAsset,
    deleteAsset,
    getAssetScans,
    getAssetVulnerabilities,
  };
};

export const useVulnerabilities = () => {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const { apiCall, loading, error } = useApi();

  const fetchVulnerabilities = useCallback(async (filters = {}) => {
    try {
      const queryParams = new URLSearchParams(filters).toString();
      const data = await apiCall(`/api/v1/vulnerabilities${queryParams ? `?${queryParams}` : ""}`);
      setVulnerabilities(data.items || []);
    } catch (err) {
      console.error("Failed to fetch vulnerabilities:", err);
    }
  }, [apiCall]);

  const updateVulnerability = useCallback(async (vulnId, updates) => {
    try {
      const data = await apiCall(`/api/v1/vulnerabilities/${vulnId}`, {
        method: "PATCH",
        body: JSON.stringify(updates),
      });
      await fetchVulnerabilities(); // Refresh the list
      return data;
    } catch (err) {
      console.error("Failed to update vulnerability:", err);
      throw err;
    }
  }, [apiCall, fetchVulnerabilities]);

  useEffect(() => {
    fetchVulnerabilities();
  }, [fetchVulnerabilities]);

  return {
    vulnerabilities,
    loading,
    error,
    fetchVulnerabilities,
    updateVulnerability,
  };
};

export const useProfiles = () => {
  const [profiles, setProfiles] = useState({});
  const [supportedTools, setSupportedTools] = useState([]);
  const { apiCall, loading, error } = useApi();

  const fetchProfiles = useCallback(async () => {
    try {
      console.log('Fetching scan profiles...');
      const data = await apiCall("/api/v1/profiles/");
      console.log('Profiles data received:', data);
      setProfiles(data);
      setSupportedTools(Object.keys(data));
    } catch (err) {
      console.error("Failed to fetch profiles:", err);
    }
  }, [apiCall]);

  const getToolProfiles = useCallback(async (tool) => {
    try {
      const data = await apiCall(`/api/v1/profiles/${tool}`);
      return data;
    } catch (err) {
      console.error(`Failed to fetch profiles for tool ${tool}:`, err);
      throw err;
    }
  }, [apiCall]);

  const getSpecificProfile = useCallback(async (tool, profileName) => {
    try {
      const data = await apiCall(`/api/v1/profiles/${tool}/${profileName}`);
      return data;
    } catch (err) {
      console.error(`Failed to fetch profile ${profileName} for tool ${tool}:`, err);
      throw err;
    }
  }, [apiCall]);

  const validateScanConfig = useCallback(async (config) => {
    try {
      const data = await apiCall("/api/v1/profiles/validate", {
        method: "POST",
        body: JSON.stringify(config),
      });
      return data;
    } catch (err) {
      console.error("Failed to validate scan config:", err);
      throw err;
    }
  }, [apiCall]);

  useEffect(() => {
    fetchProfiles();
  }, [fetchProfiles]);

  return {
    profiles,
    supportedTools,
    loading,
    error,
    fetchProfiles,
    getToolProfiles,
    getSpecificProfile,
    validateScanConfig,
  };
};

export default useApi;
