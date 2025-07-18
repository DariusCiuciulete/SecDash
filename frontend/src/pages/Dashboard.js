import React, { useState, useEffect } from "react";
import { useScans } from "../hooks/useApi";
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Button,
  Chip,
  LinearProgress,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
} from "@mui/material";
import {
  Refresh,
  Visibility,
  Stop,
  Download,
} from "@mui/icons-material";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";

const COLORS = ["#f44336", "#ff9800", "#2196f3", "#4caf50"];

function Dashboard() {
  const { scans, loading, error, fetchScans, stopScan } = useScans();
  const [selectedScan, setSelectedScan] = useState(null);
  const [open, setOpen] = useState(false);
  const [stats, setStats] = useState({
    total: 0,
    running: 0,
    completed: 0,
    failed: 0,
  });

  // Calculate statistics from real scan data
  useEffect(() => {
    const newStats = scans.reduce(
      (acc, scan) => {
        acc[scan.status] = (acc[scan.status] || 0) + 1;
        acc.total++;
        return acc;
      },
      { total: 0, running: 0, completed: 0, failed: 0 }
    );
    setStats(newStats);
  }, [scans]);

  const handleViewResult = (scan) => {
    setSelectedScan(scan);
    setOpen(true);
  };

  const handleRefreshScan = async (scanId) => {
    // Refresh scan data from API
    console.log("Refreshing scan:", scanId);
    await fetchScans();
  };

  const handleStopScan = async (scanId) => {
    // Stop scan via API
    console.log("Stopping scan:", scanId);
    try {
      await stopScan(scanId);
    } catch (err) {
      console.error("Failed to stop scan:", err);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case "running":
        return "info";
      case "completed":
        return "success";
      case "failed":
        return "error";
      case "stopped":
        return "warning";
      default:
        return "default";
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "critical":
        return "#f44336";
      case "high":
        return "#ff9800";
      case "medium":
        return "#2196f3";
      case "low":
        return "#4caf50";
      default:
        return "#aaa";
    }
  };

  const formatDuration = (durationSeconds, status, startTime) => {
    if (durationSeconds) {
      const minutes = Math.floor(durationSeconds / 60);
      const seconds = durationSeconds % 60;
      if (minutes > 0) {
        return `${minutes}m ${seconds}s`;
      }
      return `${seconds}s`;
    }
    
    if (status === "running" && startTime) {
      const start = new Date(startTime);
      const current = new Date();
      const elapsedSeconds = Math.max(0, Math.floor((current - start) / 1000));
      const minutes = Math.floor(elapsedSeconds / 60);
      const seconds = elapsedSeconds % 60;
      return `${minutes}m ${seconds}s (running)`;
    }
    
    if (status === "queued") {
      return "Queued";
    }
    
    return "N/A";
  };

  // Real-time duration updates for running scans
  useEffect(() => {
    const runningScans = scans.filter(scan => scan.status === 'running');
    
    if (runningScans.length > 0) {
      const interval = setInterval(() => {
        // Force a re-render to update duration displays
        setSelectedScan(prev => prev ? {...prev} : null);
      }, 1000); // Update every second for smooth duration display
      
      return () => clearInterval(interval);
    }
  }, [scans]);

  // Data for charts
  const statusData = [
    { name: "Completed", value: stats.completed, color: COLORS[3] },
    { name: "Running", value: stats.running, color: COLORS[2] },
    { name: "Failed", value: stats.failed, color: COLORS[0] },
  ].filter(item => item.value > 0);

  // Calculate tool usage from actual scan data with enhanced information
  const toolUsageData = scans.reduce((acc, scan) => {
    const existingTool = acc.find(t => t.name === scan.tool);
    if (existingTool) {
      existingTool.scans++;
      existingTool.vulnerabilities += scan.vulnerability_count || 0;
    } else {
      // Define tool information
      const toolInfo = {
        nmap: { displayName: "Nmap", description: "Network Scanner", color: "#2196F3" },
        zap: { displayName: "OWASP ZAP", description: "Web App Scanner", color: "#FF9800" },
        nuclei: { displayName: "Nuclei", description: "Vulnerability Scanner", color: "#4CAF50" },
        metasploit: { displayName: "Metasploit", description: "Penetration Testing", color: "#F44336" },
        tshark: { displayName: "Tshark", description: "Network Analysis", color: "#9C27B0" },
        openvas: { displayName: "OpenVAS", description: "Vulnerability Assessment", color: "#607D8B" },
      };
      
      const info = toolInfo[scan.tool] || { 
        displayName: scan.tool?.toUpperCase() || "Unknown", 
        description: "Security Tool",
        color: "#795548"
      };
      
      acc.push({ 
        name: scan.tool,
        displayName: info.displayName,
        description: info.description,
        scans: 1,
        vulnerabilities: scan.vulnerability_count || 0,
        color: info.color
      });
    }
    return acc;
  }, []);

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Scan Dashboard
      </Typography>
      <Typography variant="subtitle1" color="text.secondary" gutterBottom>
        Monitor active scans and view results
      </Typography>

      {/* Loading State */}
      {loading && (
        <Box sx={{ display: 'flex', justifyContent: 'center', my: 4 }}>
          <LinearProgress sx={{ width: '100%' }} />
        </Box>
      )}

      {/* Error State */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          Failed to load scan data: {error}
        </Alert>
      )}

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mt: 2, mb: 3 }}>
        <Grid item xs={12} sm={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Total Scans
              </Typography>
              <Typography variant="h4">{stats.total}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Running
              </Typography>
              <Typography variant="h4" color="info.main">
                {stats.running}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Completed
              </Typography>
              <Typography variant="h4" color="success.main">
                {stats.completed}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Failed
              </Typography>
              <Typography variant="h4" color="error.main">
                {stats.failed}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Scan Status Distribution
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={statusData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {statusData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Security Tools Usage
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={toolUsageData} margin={{ left: 20, right: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="displayName" 
                    angle={-45}
                    textAnchor="end"
                    height={80}
                    fontSize={12}
                  />
                  <YAxis />
                  <Tooltip 
                    formatter={(value, name) => [value, name === 'scans' ? 'Scans' : 'Vulnerabilities']}
                    labelFormatter={(label) => {
                      const tool = toolUsageData.find(t => t.displayName === label);
                      return tool ? `${tool.displayName} - ${tool.description}` : label;
                    }}
                  />
                  <Legend />
                  <Bar dataKey="scans" fill="#00e676" name="Scans" />
                  <Bar dataKey="vulnerabilities" fill="#ff5722" name="Findings" />
                </BarChart>
              </ResponsiveContainer>
              
              {/* Tool Legend */}
              <Box sx={{ mt: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Available Security Tools:
                </Typography>
                <Grid container spacing={1}>
                  {[
                    { name: "Nmap", desc: "Network/Port Scanner", color: "#2196F3" },
                    { name: "OWASP ZAP", desc: "Web Application Scanner", color: "#FF9800" },
                    { name: "Nuclei", desc: "Fast Vulnerability Scanner", color: "#4CAF50" },
                    { name: "Metasploit", desc: "Penetration Testing Framework", color: "#F44336" },
                    { name: "Tshark", desc: "Network Protocol Analyzer", color: "#9C27B0" },
                    { name: "OpenVAS", desc: "Comprehensive Vulnerability Scanner", color: "#607D8B" },
                  ].map((tool) => (
                    <Grid item xs={12} sm={6} key={tool.name}>
                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
                        <Box 
                          sx={{ 
                            width: 12, 
                            height: 12, 
                            bgcolor: tool.color, 
                            mr: 1,
                            borderRadius: '50%'
                          }} 
                        />
                        <Typography variant="caption">
                          <strong>{tool.name}</strong>: {tool.desc}
                        </Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Scans Table */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Scan History
          </Typography>
          {scans.length === 0 ? (
            <Alert severity="info">
              No scans found. Launch your first scan from the Scan Launcher.
            </Alert>
          ) : (
            <TableContainer component={Paper} sx={{ mt: 2 }}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Scan ID</TableCell>
                    <TableCell>Target</TableCell>
                    <TableCell>Tool</TableCell>
                    <TableCell>Profile</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Findings</TableCell>
                    <TableCell>Duration</TableCell>
                    <TableCell>Started</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {scans.map((scan) => (
                    <TableRow key={scan.scanId}>
                      <TableCell>
                        <Typography variant="body2" fontFamily="monospace">
                          {scan.scanId}
                        </Typography>
                      </TableCell>
                      <TableCell>{scan.target}</TableCell>
                      <TableCell>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          {scan.tool && (
                            <Chip
                              label={scan.tool.toUpperCase()}
                              size="small"
                              variant="outlined"
                              sx={{
                                bgcolor: toolUsageData.find(t => t.name === scan.tool)?.color + "20" || "#f5f5f5",
                                borderColor: toolUsageData.find(t => t.name === scan.tool)?.color || "#ccc"
                              }}
                            />
                          )}
                        </Box>
                      </TableCell>
                      <TableCell>{scan.profile || "Default"}</TableCell>
                      <TableCell>
                        <Chip
                          label={scan.status}
                          size="small"
                          color={getStatusColor(scan.status)}
                        />
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          {scan.vulnerability_count !== undefined ? (
                            <Chip
                              label={`${scan.vulnerability_count} findings`}
                              size="small"
                              color={scan.vulnerability_count > 0 ? "warning" : "success"}
                              variant="outlined"
                            />
                          ) : scan.status === "running" || scan.status === "queued" ? (
                            <Box sx={{ display: "flex", flexDirection: "column", width: "100%" }}>
                              <LinearProgress
                                variant="determinate"
                                value={scan.progress || 0}
                                sx={{ flexGrow: 1, minWidth: 80, mb: 0.5 }}
                              />
                              <Typography variant="caption" color="text.secondary">
                                {scan.progress_message || `${scan.progress || 0}%`}
                              </Typography>
                            </Box>
                          ) : (
                            <Typography variant="caption" color="text.secondary">
                              No data
                            </Typography>
                          )}
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {scan.duration_text || formatDuration(scan.duration_seconds, scan.status, scan.startTime)}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption" color="text.secondary">
                          {scan.created_at 
                            ? new Date(scan.created_at).toLocaleString()
                            : "Unknown"
                          }
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={() => handleRefreshScan(scan.scanId)}
                          color="primary"
                        >
                          <Refresh />
                        </IconButton>
                        {scan.status === "running" && (
                          <IconButton
                            size="small"
                            onClick={() => handleStopScan(scan.scanId)}
                            color="error"
                          >
                            <Stop />
                          </IconButton>
                        )}
                        <IconButton
                          size="small"
                          onClick={() => handleViewResult(scan)}
                          color="primary"
                        >
                          <Visibility />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

      {/* Scan Result Dialog */}
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="lg" fullWidth>
        <DialogTitle>
          Scan Results - {selectedScan?.scanId}
        </DialogTitle>
        <DialogContent>
          {selectedScan && (
            <Box>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    Target:
                  </Typography>
                  <Typography variant="body1">{selectedScan.target}</Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    Status:
                  </Typography>
                  <Chip
                    label={selectedScan.status}
                    size="small"
                    color={getStatusColor(selectedScan.status)}
                  />
                </Grid>
              </Grid>

              {/* Error Display */}
              {selectedScan.result?.error && (
                <Alert severity="error" sx={{ mb: 2 }}>
                  <strong>Error:</strong> {selectedScan.result.error}
                </Alert>
              )}

              {/* Findings Table */}
              {selectedScan.result?.findings && selectedScan.result.findings.length > 0 && (
                <TableContainer component={Paper}>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Host</TableCell>
                        <TableCell>Port</TableCell>
                        <TableCell>Service</TableCell>
                        <TableCell>Severity</TableCell>
                        <TableCell>Description</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {selectedScan.result.findings.map((finding, idx) => (
                        <TableRow key={idx}>
                          <TableCell>{finding.host}</TableCell>
                          <TableCell>{finding.port}</TableCell>
                          <TableCell>{finding.service}</TableCell>
                          <TableCell>
                            <Chip
                              label={finding.severity}
                              size="small"
                              sx={{
                                backgroundColor: getSeverityColor(finding.severity),
                                color: "white",
                              }}
                            />
                          </TableCell>
                          <TableCell>{finding.description}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}

              {/* No Findings Message */}
              {selectedScan.result?.findings && selectedScan.result.findings.length === 0 && (
                <Alert severity="success">
                  No vulnerabilities or issues found.
                </Alert>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button startIcon={<Download />}>Export Report</Button>
          <Button onClick={() => setOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

// Helper function to format duration
const formatDuration = (startTime, endTime) => {
  if (!startTime || !endTime) return 'N/A';
  
  const start = new Date(startTime);
  const end = new Date(endTime);
  const durationMs = end - start;
  
  if (durationMs < 0) return 'N/A';
  
  const hours = Math.floor(durationMs / (1000 * 60 * 60));
  const minutes = Math.floor((durationMs % (1000 * 60 * 60)) / (1000 * 60));
  const seconds = Math.floor((durationMs % (1000 * 60)) / 1000);
  
  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`;
  } else if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  } else {
    return `${seconds}s`;
  }
};

export default Dashboard;
