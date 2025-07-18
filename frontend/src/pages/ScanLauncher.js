import React, { useState, useEffect } from "react";
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Button,
  Chip,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  FormControlLabel,
  Checkbox,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  CircularProgress,
} from "@mui/material";
import {
  ExpandMore,
  PlayArrow,
  Security,
  BugReport,
  Lan,
  Speed,
  Settings,
} from "@mui/icons-material";
import { useNavigate } from "react-router-dom";
import { useAssets, useScans, useProfiles } from "../hooks/useApi";

function ScanLauncher() {
  const { assets, loading: assetsLoading, createAsset } = useAssets();
  const { createScan } = useScans();
  const { profiles, supportedTools, loading: profilesLoading } = useProfiles();
  const [selectedTool, setSelectedTool] = useState("nmap");
  const [selectedAsset, setSelectedAsset] = useState("");
  const [selectedProfile, setSelectedProfile] = useState("");
  const [customTarget, setCustomTarget] = useState("");
  const [customOptions, setCustomOptions] = useState("");
  const [useCustomTarget, setUseCustomTarget] = useState(false);
  const [isLaunching, setIsLaunching] = useState(false);
  const navigate = useNavigate();

  // Convert backend profiles format to frontend format
  const scanProfiles = React.useMemo(() => {
    const converted = {};
    Object.keys(profiles).forEach(tool => {
      converted[tool] = Object.keys(profiles[tool]).map(profileKey => {
        const profile = profiles[tool][profileKey];
        return {
          name: profile.name,
          description: profile.description,
          options: profile.default_options || {}
        };
      });
    });
    return converted;
  }, [profiles]);

  // Update supported tools when profiles are loaded
  useEffect(() => {
    if (supportedTools.length > 0 && !supportedTools.includes(selectedTool)) {
      setSelectedTool(supportedTools[0]);
    }
  }, [supportedTools, selectedTool]);

  // Assets are now loaded via useAssets hook

  const handleToolChange = (tool) => {
    setSelectedTool(tool);
    setSelectedProfile("");
    setCustomOptions("");
  };

  const handleProfileChange = (profile) => {
    setSelectedProfile(profile.name);
    setCustomOptions(profile.options);
  };

  const handleLaunchScan = async () => {
    setIsLaunching(true);
    
    try {
      let targetAssetId = selectedAsset;
      
      // If using custom target, check if asset already exists or create one
      if (useCustomTarget) {
        // First, check if an asset with this target already exists
        const existingAsset = assets.find(asset => asset.target === customTarget);
        
        if (existingAsset) {
          // Use existing asset
          targetAssetId = existingAsset.id;
        } else {
          // Create new asset only if it doesn't exist
          const assetData = {
            name: `Custom Target: ${customTarget}`,
            type: "host", // Default type
            target: customTarget,
            description: `Temporary asset for scan`,
            tags: ["temporary", "scan"]
          };
          
          const newAsset = await createAsset(assetData);
          targetAssetId = newAsset.id;
        }
      }

      const scanData = {
        asset_id: targetAssetId,
        tool: selectedTool,
        options: selectedProfile ? scanProfiles[selectedTool].find(p => p.name === selectedProfile)?.options || {} : {},
      };

      await createScan(scanData);
      console.log("Scan launched successfully:", scanData);
      
      // Navigate to dashboard to show the running scan
      navigate("/dashboard");
    } catch (error) {
      console.error("Failed to launch scan:", error);
      alert("Failed to launch scan: " + error.message);
    } finally {
      setIsLaunching(false);
    }
  };

  const isFormValid = () => {
    const hasTarget = useCustomTarget ? customTarget.trim() : selectedAsset;
    return selectedTool && hasTarget && selectedProfile;
  };

  const getToolIcon = (tool) => {
    switch (tool) {
      case "nmap":
        return <Lan />;
      case "zap":
        return <Security />;
      case "metasploit":
        return <BugReport />;
      case "tshark":
        return <Speed />;
      case "nuclei":
        return <Security />;
      case "nikto":
        return <Security />;
      case "openvas":
        return <BugReport />;
      default:
        return <Settings />;
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Scan Launcher
      </Typography>
      <Typography variant="subtitle1" color="text.secondary" gutterBottom>
        Configure and launch security scans with various tools
      </Typography>

      <Grid container spacing={3} sx={{ mt: 2 }}>
        {/* Tool Selection */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Select Tool
              </Typography>
              {profilesLoading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                  <CircularProgress />
                </Box>
              ) : (
                <Grid container spacing={1}>
                  {Object.keys(scanProfiles).map((tool) => (
                    <Grid item xs={6} key={tool}>
                      <Card
                        sx={{
                          cursor: "pointer",
                          border: selectedTool === tool ? 2 : 1,
                          borderColor: selectedTool === tool ? "primary.main" : "divider",
                        }}
                        onClick={() => handleToolChange(tool)}
                      >
                        <CardContent sx={{ textAlign: "center", py: 2 }}>
                          {getToolIcon(tool)}
                          <Typography variant="body2" sx={{ mt: 1 }}>
                            {tool.toUpperCase()}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Target Selection */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Target Configuration
              </Typography>
              
              <FormControlLabel
                control={
                  <Checkbox
                    checked={useCustomTarget}
                    onChange={(e) => setUseCustomTarget(e.target.checked)}
                  />
                }
                label="Use custom target"
                sx={{ mb: 2 }}
              />

              {useCustomTarget ? (
                <TextField
                  fullWidth
                  label="Custom Target"
                  value={customTarget}
                  onChange={(e) => setCustomTarget(e.target.value)}
                  placeholder="e.g., 192.168.1.1, https://example.com, 10.0.0.0/24"
                  helperText="Enter IP address, domain, or network range"
                />
              ) : (
                <FormControl fullWidth>
                  <InputLabel>Select Asset</InputLabel>
                  <Select
                    value={selectedAsset}
                    label="Select Asset"
                    onChange={(e) => setSelectedAsset(e.target.value)}
                  >
                    {assets.map((asset) => (
                      <MenuItem key={asset.id} value={asset.id}>
                        <Box>
                          <Typography variant="body2">{asset.name}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {asset.target}
                          </Typography>
                        </Box>
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Scan Profiles */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Scan Profiles
              </Typography>
              {profilesLoading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                  <CircularProgress />
                </Box>
              ) : selectedTool && scanProfiles[selectedTool] ? (
                <Grid container spacing={2}>
                  {scanProfiles[selectedTool].map((profile) => (
                    <Grid item xs={12} sm={6} md={4} key={profile.name}>
                      <Card
                        sx={{
                          cursor: "pointer",
                          border: selectedProfile === profile.name ? 2 : 1,
                          borderColor: selectedProfile === profile.name ? "primary.main" : "divider",
                        }}
                        onClick={() => handleProfileChange(profile)}
                      >
                        <CardContent>
                          <Typography variant="h6" gutterBottom>
                            {profile.name}
                          </Typography>
                          <Typography variant="body2" color="text.secondary" gutterBottom>
                            {profile.description}
                          </Typography>
                          <Chip
                            label={
                              typeof profile.options === 'object' && profile.options !== null
                                ? Object.entries(profile.options)
                                    .map(([key, value]) => `${key}: ${value}`)
                                    .join(', ')
                                : String(profile.options || 'Default')
                            }
                            size="small"
                            variant="outlined"
                            sx={{ fontFamily: "monospace" }}
                          />
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              ) : (
                <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                  {selectedTool ? 'No profiles available for this tool' : 'Select a tool to view profiles'}
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Advanced Options */}
        <Grid item xs={12}>
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMore />}>
              <Typography variant="h6">Advanced Options</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <TextField
                fullWidth
                label="Custom Options"
                value={customOptions}
                onChange={(e) => setCustomOptions(e.target.value)}
                placeholder="Additional command-line options"
                helperText="Override or extend the profile options"
                sx={{ mb: 2 }}
              />
              
              <Divider sx={{ my: 2 }} />
              
              <Typography variant="subtitle2" gutterBottom>
                Common Options for {selectedTool?.toUpperCase()}:
              </Typography>
              <List dense>
                {selectedTool === "nmap" && (
                  <>
                    <ListItem>
                      <ListItemIcon><Lan fontSize="small" /></ListItemIcon>
                      <ListItemText 
                        primary="-sS" 
                        secondary="TCP SYN scan (default)"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><Lan fontSize="small" /></ListItemIcon>
                      <ListItemText 
                        primary="-sV" 
                        secondary="Version detection"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><Lan fontSize="small" /></ListItemIcon>
                      <ListItemText 
                        primary="-O" 
                        secondary="OS detection"
                      />
                    </ListItem>
                  </>
                )}
                {selectedTool === "zap" && (
                  <>
                    <ListItem>
                      <ListItemIcon><Security fontSize="small" /></ListItemIcon>
                      <ListItemText 
                        primary="baseline" 
                        secondary="Basic security scan"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><Security fontSize="small" /></ListItemIcon>
                      <ListItemText 
                        primary="full-scan" 
                        secondary="Complete vulnerability assessment"
                      />
                    </ListItem>
                  </>
                )}
              </List>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Launch Controls */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center">
                <Box>
                  <Typography variant="h6">Ready to Launch</Typography>
                  {isFormValid() && (
                    <Typography variant="body2" color="text.secondary">
                      {selectedTool.toUpperCase()} scan on {
                        useCustomTarget ? customTarget : 
                        assets.find(asset => asset.id === selectedAsset)?.name
                      } using {selectedProfile} profile
                    </Typography>
                  )}
                </Box>
                <Button
                  variant="contained"
                  size="large"
                  startIcon={<PlayArrow />}
                  onClick={handleLaunchScan}
                  disabled={!isFormValid() || isLaunching}
                >
                  {isLaunching ? "Launching..." : "Launch Scan"}
                </Button>
              </Box>
              
              {!isFormValid() && (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  Please select a tool, target, and scan profile to launch a scan.
                </Alert>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

export default ScanLauncher;
