import React, { useState } from "react";
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  TextField,
  Button,
  Switch,
  FormControlLabel,
  Divider,
  Alert,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Chip,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from "@mui/material";
import {
  Save,
  Science,
  Add,
  Delete,
  Settings as SettingsIcon,
  Security,
  Notifications,
  Storage,
} from "@mui/icons-material";

function Settings() {
  const [settings, setSettings] = useState({
    // General Settings
    scanTimeout: 600,
    maxConcurrentScans: 5,
    defaultScanProfile: "comprehensive",
    enableNotifications: true,
    autoRefreshInterval: 30,
    
    // Security Settings
    requireAuthentication: true,
    sessionTimeout: 1800,
    enableAuditLog: true,
    
    // Integration Settings
    splunkEnabled: false,
    splunkUrl: "",
    splunkToken: "",
    elasticEnabled: false,
    elasticUrl: "",
    elasticApiKey: "",
    
    // Email Notifications
    emailEnabled: false,
    smtpServer: "",
    smtpPort: 587,
    smtpUsername: "",
    smtpPassword: "",
  });

  const [apiKeys, setApiKeys] = useState([
    { id: 1, name: "Main Dashboard", key: "sdk_123...abc", created: "2024-01-15", lastUsed: "2024-01-16" },
    { id: 2, name: "CI/CD Pipeline", key: "sdk_456...def", created: "2024-01-10", lastUsed: "2024-01-16" },
  ]);

  const [showKeyDialog, setShowKeyDialog] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [testResults, setTestResults] = useState({});

  const handleSettingChange = (field, value) => {
    setSettings(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleSaveSettings = () => {
    // Simulate API call to save settings
    console.log("Saving settings:", settings);
    // Show success message
  };

  const handleTestConnection = async (service) => {
    setTestResults(prev => ({ ...prev, [service]: "testing" }));
    
    // Simulate API test
    setTimeout(() => {
      setTestResults(prev => ({ 
        ...prev, 
        [service]: Math.random() > 0.5 ? "success" : "error" 
      }));
    }, 2000);
  };

  const handleCreateApiKey = () => {
    if (newKeyName.trim()) {
      const newKey = {
        id: Date.now(),
        name: newKeyName,
        key: `sdk_${Math.random().toString(36).substring(2, 15)}...${Math.random().toString(36).substring(2, 6)}`,
        created: new Date().toISOString().split('T')[0],
        lastUsed: "Never"
      };
      setApiKeys([...apiKeys, newKey]);
      setNewKeyName("");
      setShowKeyDialog(false);
    }
  };

  const handleDeleteApiKey = (id) => {
    setApiKeys(apiKeys.filter(key => key.id !== id));
  };

  const getTestResultColor = (result) => {
    switch (result) {
      case "testing":
        return "info";
      case "success":
        return "success";
      case "error":
        return "error";
      default:
        return "default";
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Settings & Integrations
      </Typography>
      <Typography variant="subtitle1" color="text.secondary" gutterBottom>
        Configure SecDash settings and external integrations
      </Typography>

      <Grid container spacing={3} sx={{ mt: 2 }}>
        {/* General Settings */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2} mb={3}>
                <SettingsIcon />
                <Typography variant="h6">General Settings</Typography>
              </Box>
              
              <Grid container spacing={3}>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Scan Timeout (seconds)"
                    type="number"
                    value={settings.scanTimeout}
                    onChange={(e) => handleSettingChange("scanTimeout", parseInt(e.target.value))}
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Max Concurrent Scans"
                    type="number"
                    value={settings.maxConcurrentScans}
                    onChange={(e) => handleSettingChange("maxConcurrentScans", parseInt(e.target.value))}
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControl fullWidth>
                    <InputLabel>Default Scan Profile</InputLabel>
                    <Select
                      value={settings.defaultScanProfile}
                      label="Default Scan Profile"
                      onChange={(e) => handleSettingChange("defaultScanProfile", e.target.value)}
                    >
                      <MenuItem value="quick">Quick Scan</MenuItem>
                      <MenuItem value="comprehensive">Comprehensive</MenuItem>
                      <MenuItem value="stealth">Stealth Scan</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Auto Refresh Interval (seconds)"
                    type="number"
                    value={settings.autoRefreshInterval}
                    onChange={(e) => handleSettingChange("autoRefreshInterval", parseInt(e.target.value))}
                  />
                </Grid>
                <Grid item xs={12}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.enableNotifications}
                        onChange={(e) => handleSettingChange("enableNotifications", e.target.checked)}
                      />
                    }
                    label="Enable Notifications"
                  />
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Security Settings */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2} mb={3}>
                <Security />
                <Typography variant="h6">Security Settings</Typography>
              </Box>
              
              <Grid container spacing={3}>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Session Timeout (seconds)"
                    type="number"
                    value={settings.sessionTimeout}
                    onChange={(e) => handleSettingChange("sessionTimeout", parseInt(e.target.value))}
                  />
                </Grid>
                <Grid item xs={12}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.requireAuthentication}
                        onChange={(e) => handleSettingChange("requireAuthentication", e.target.checked)}
                      />
                    }
                    label="Require Authentication"
                  />
                </Grid>
                <Grid item xs={12}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.enableAuditLog}
                        onChange={(e) => handleSettingChange("enableAuditLog", e.target.checked)}
                      />
                    }
                    label="Enable Audit Logging"
                  />
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Splunk Integration */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2} mb={3}>
                <Storage />
                <Typography variant="h6">Splunk Integration</Typography>
                <FormControlLabel
                  control={
                    <Switch
                      checked={settings.splunkEnabled}
                      onChange={(e) => handleSettingChange("splunkEnabled", e.target.checked)}
                    />
                  }
                  label="Enabled"
                  sx={{ ml: "auto" }}
                />
              </Box>
              
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Splunk URL"
                    value={settings.splunkUrl}
                    onChange={(e) => handleSettingChange("splunkUrl", e.target.value)}
                    disabled={!settings.splunkEnabled}
                    placeholder="https://your-splunk-instance.com:8088"
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="HEC Token"
                    type="password"
                    value={settings.splunkToken}
                    onChange={(e) => handleSettingChange("splunkToken", e.target.value)}
                    disabled={!settings.splunkEnabled}
                  />
                </Grid>
                <Grid item xs={12}>
                  <Button
                    variant="outlined"
                    startIcon={<Science />}
                    onClick={() => handleTestConnection("splunk")}
                    disabled={!settings.splunkEnabled || !settings.splunkUrl}
                    color={getTestResultColor(testResults.splunk)}
                  >
                    {testResults.splunk === "testing" ? "Testing..." : "Test Connection"}
                  </Button>
                  {testResults.splunk === "success" && (
                    <Chip label="Connection successful" color="success" size="small" sx={{ ml: 1 }} />
                  )}
                  {testResults.splunk === "error" && (
                    <Chip label="Connection failed" color="error" size="small" sx={{ ml: 1 }} />
                  )}
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Elasticsearch Integration */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2} mb={3}>
                <Storage />
                <Typography variant="h6">Elasticsearch Integration</Typography>
                <FormControlLabel
                  control={
                    <Switch
                      checked={settings.elasticEnabled}
                      onChange={(e) => handleSettingChange("elasticEnabled", e.target.checked)}
                    />
                  }
                  label="Enabled"
                  sx={{ ml: "auto" }}
                />
              </Box>
              
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Elasticsearch URL"
                    value={settings.elasticUrl}
                    onChange={(e) => handleSettingChange("elasticUrl", e.target.value)}
                    disabled={!settings.elasticEnabled}
                    placeholder="https://your-elastic-cluster.com:9200"
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="API Key"
                    type="password"
                    value={settings.elasticApiKey}
                    onChange={(e) => handleSettingChange("elasticApiKey", e.target.value)}
                    disabled={!settings.elasticEnabled}
                  />
                </Grid>
                <Grid item xs={12}>
                  <Button
                    variant="outlined"
                    startIcon={<Science />}
                    onClick={() => handleTestConnection("elastic")}
                    disabled={!settings.elasticEnabled || !settings.elasticUrl}
                    color={getTestResultColor(testResults.elastic)}
                  >
                    {testResults.elastic === "testing" ? "Testing..." : "Test Connection"}
                  </Button>
                  {testResults.elastic === "success" && (
                    <Chip label="Connection successful" color="success" size="small" sx={{ ml: 1 }} />
                  )}
                  {testResults.elastic === "error" && (
                    <Chip label="Connection failed" color="error" size="small" sx={{ ml: 1 }} />
                  )}
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Email Notifications */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" gap={2} mb={3}>
                <Notifications />
                <Typography variant="h6">Email Notifications</Typography>
                <FormControlLabel
                  control={
                    <Switch
                      checked={settings.emailEnabled}
                      onChange={(e) => handleSettingChange("emailEnabled", e.target.checked)}
                    />
                  }
                  label="Enabled"
                  sx={{ ml: "auto" }}
                />
              </Box>
              
              <Grid container spacing={3}>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="SMTP Server"
                    value={settings.smtpServer}
                    onChange={(e) => handleSettingChange("smtpServer", e.target.value)}
                    disabled={!settings.emailEnabled}
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="SMTP Port"
                    type="number"
                    value={settings.smtpPort}
                    onChange={(e) => handleSettingChange("smtpPort", parseInt(e.target.value))}
                    disabled={!settings.emailEnabled}
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Username"
                    value={settings.smtpUsername}
                    onChange={(e) => handleSettingChange("smtpUsername", e.target.value)}
                    disabled={!settings.emailEnabled}
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Password"
                    type="password"
                    value={settings.smtpPassword}
                    onChange={(e) => handleSettingChange("smtpPassword", e.target.value)}
                    disabled={!settings.emailEnabled}
                  />
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* API Keys Management */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justify="space-between" mb={3}>
                <Typography variant="h6">API Keys</Typography>
                <Button
                  variant="outlined"
                  startIcon={<Add />}
                  onClick={() => setShowKeyDialog(true)}
                >
                  Generate New Key
                </Button>
              </Box>
              
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Name</TableCell>
                      <TableCell>Key</TableCell>
                      <TableCell>Created</TableCell>
                      <TableCell>Last Used</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {apiKeys.map((key) => (
                      <TableRow key={key.id}>
                        <TableCell>{key.name}</TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {key.key}
                          </Typography>
                        </TableCell>
                        <TableCell>{key.created}</TableCell>
                        <TableCell>{key.lastUsed}</TableCell>
                        <TableCell>
                          <IconButton
                            size="small"
                            onClick={() => handleDeleteApiKey(key.id)}
                            color="error"
                          >
                            <Delete />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Save Settings */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center">
                <Alert severity="info">
                  Changes will be applied immediately after saving.
                </Alert>
                <Button
                  variant="contained"
                  size="large"
                  startIcon={<Save />}
                  onClick={handleSaveSettings}
                >
                  Save Settings
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* API Key Generation Dialog */}
      <Dialog open={showKeyDialog} onClose={() => setShowKeyDialog(false)}>
        <DialogTitle>Generate New API Key</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="Key Name"
            value={newKeyName}
            onChange={(e) => setNewKeyName(e.target.value)}
            placeholder="e.g., Production Dashboard, CI/CD Pipeline"
            sx={{ mt: 1 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowKeyDialog(false)}>Cancel</Button>
          <Button onClick={handleCreateApiKey} variant="contained">
            Generate Key
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default Settings;
