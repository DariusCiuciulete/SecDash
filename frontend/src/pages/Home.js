import React, { useState, useEffect } from "react";
import { useAssets, useScans, useVulnerabilities } from "../hooks/useApi";
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  List,
  ListItem,
  ListItemText,
  Button,
  LinearProgress,
  Alert,
} from "@mui/material";
import {
  Security,
  BugReport,
  Timeline,
  PlayArrow,
} from "@mui/icons-material";

function Home() {
  const { assets } = useAssets();
  const { scans } = useScans();
  const { vulnerabilities } = useVulnerabilities();
  
  const [stats, setStats] = useState({
    totalAssets: 0,
    activeScans: 0,
    vulnerabilities: 0,
    lastScanTime: null,
  });

  const [recentActivity, setRecentActivity] = useState([]);
  const [activeScans, setActiveScans] = useState([]);

  // Calculate real statistics from API data
  useEffect(() => {
    const activeScansCount = scans.filter(scan => 
      scan.status === 'running' || scan.status === 'queued'
    ).length;
    
    const lastScan = scans.length > 0 
      ? scans.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0]
      : null;

    setStats({
      totalAssets: assets.length,
      activeScans: activeScansCount,
      vulnerabilities: vulnerabilities.length,
      lastScanTime: lastScan?.created_at || null,
    });

    // Set recent activity from recent scans and vulnerabilities
    const recentScans = scans
      .slice(0, 3)
      .map(scan => ({
        id: scan.id,
        type: scan.status === 'completed' ? 'scan_completed' : 'scan_started',
        target: scan.asset?.target || 'Unknown',
        timestamp: scan.created_at,
        severity: scan.status === 'failed' ? 'high' : 'info',
      }));

    setRecentActivity(recentScans);
    setActiveScans(scans.filter(scan => scan.status === 'running'));
  }, [assets, scans, vulnerabilities]);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "critical":
        return "error";
      case "high":
        return "warning";
      case "medium":
        return "info";
      case "low":
        return "success";
      default:
        return "default";
    }
  };

  const formatTimeAgo = (timestamp) => {
    const diff = Date.now() - new Date(timestamp).getTime();
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ago`;
    }
    return `${minutes}m ago`;
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Welcome to SecDash
      </Typography>
      <Typography variant="subtitle1" color="text.secondary" gutterBottom>
        Your centralized security scanning dashboard
      </Typography>

      <Grid container spacing={3} sx={{ mt: 2 }}>
        {/* Stats Cards */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Security color="primary" sx={{ mr: 2 }} />
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Total Assets
                  </Typography>
                  <Typography variant="h4">{stats.totalAssets}</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Timeline color="info" sx={{ mr: 2 }} />
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Active Scans
                  </Typography>
                  <Typography variant="h4">{stats.activeScans}</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <BugReport color="error" sx={{ mr: 2 }} />
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Vulnerabilities
                  </Typography>
                  <Typography variant="h4">{stats.vulnerabilities}</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <PlayArrow color="success" sx={{ mr: 2 }} />
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Last Scan
                  </Typography>
                  <Typography variant="body1">
                    {stats.lastScanTime ? formatTimeAgo(stats.lastScanTime) : "Never"}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Active Scans */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Active Scans
              </Typography>
              {activeScans.length === 0 ? (
                <Alert severity="info">No active scans running</Alert>
              ) : (
                <List dense>
                  {activeScans.map((scan) => (
                    <ListItem key={scan.id} divider>
                      <ListItemText
                        primary={
                          <Box display="flex" alignItems="center" gap={1}>
                            <Typography variant="body1">{scan.target}</Typography>
                            <Chip
                              label={scan.tool.toUpperCase()}
                              size="small"
                              variant="outlined"
                            />
                          </Box>
                        }
                        secondary={
                          <Box sx={{ mt: 1 }}>
                            <LinearProgress
                              variant="determinate"
                              value={scan.progress}
                              sx={{ mb: 1 }}
                            />
                            <Typography variant="caption">
                              {scan.progress}% complete • Started {formatTimeAgo(scan.startTime)}
                            </Typography>
                          </Box>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Activity */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Activity
              </Typography>
              <List dense>
                {recentActivity.map((activity) => (
                  <ListItem key={activity.id} divider>
                    <ListItemText
                      primary={
                        <Box display="flex" alignItems="center" gap={1}>
                          <Typography variant="body2">
                            {activity.type.replace("_", " ").toUpperCase()}
                          </Typography>
                          <Chip
                            label={activity.severity}
                            size="small"
                            color={getSeverityColor(activity.severity)}
                          />
                        </Box>
                      }
                      secondary={
                        <Box>
                          <Typography variant="body2" color="text.primary">
                            {activity.target}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {formatTimeAgo(activity.timestamp)}
                          </Typography>
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* Quick Actions */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Quick Actions
              </Typography>
              <Box display="flex" gap={2} flexWrap="wrap">
                <Button variant="contained" color="primary" startIcon={<PlayArrow />}>
                  Start Network Scan
                </Button>
                <Button variant="outlined" startIcon={<Security />}>
                  Add New Asset
                </Button>
                <Button variant="outlined" startIcon={<BugReport />}>
                  View Vulnerabilities
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

export default Home;
