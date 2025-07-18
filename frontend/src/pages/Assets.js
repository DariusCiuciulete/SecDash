import React, { useState, useEffect } from "react";
import { useAssets } from "../hooks/useApi";
import {
  Box,
  Typography,
  Button,
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
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Chip,
  IconButton,
  Alert,
  List,
  ListItem,
  ListItemText,
  Tabs,
  Tab,
  Divider,
} from "@mui/material";
import {
  Add,
  Edit,
  Delete,
  Security,
  Language,
  Router,
  Computer,
  Visibility,
  PlayArrow,
  BugReport,
} from "@mui/icons-material";

function Assets() {
  const { assets, loading, error, createAsset, updateAsset, deleteAsset, getAssetScans, getAssetVulnerabilities } = useAssets();
  const [open, setOpen] = useState(false);
  const [detailOpen, setDetailOpen] = useState(false);
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [assetScans, setAssetScans] = useState([]);
  const [assetVulns, setAssetVulns] = useState([]);
  const [detailTab, setDetailTab] = useState(0);
  const [editingAsset, setEditingAsset] = useState(null);
  const [formData, setFormData] = useState({
    name: "",
    type: "",
    target: "",
    description: "",
    tags: "",
  });

  const handleOpen = (asset = null) => {
    if (asset) {
      setEditingAsset(asset);
      setFormData({
        name: asset.name,
        type: asset.type,
        target: asset.target,
        description: asset.description,
        tags: asset.tags?.join(", ") || "",
      });
    } else {
      setEditingAsset(null);
      setFormData({
        name: "",
        type: "",
        target: "",
        description: "",
        tags: "",
      });
    }
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
    setEditingAsset(null);
    setFormData({
      name: "",
      type: "",
      target: "",
      description: "",
      tags: "",
    });
  };

  const handleSave = async () => {
    try {
      const assetData = {
        ...formData,
        tags: formData.tags.split(",").map((tag) => tag.trim()).filter(tag => tag),
        is_active: true,
      };

      if (editingAsset) {
        await updateAsset(editingAsset.id, assetData);
      } else {
        await createAsset(assetData);
      }

      handleClose();
    } catch (error) {
      console.error("Failed to save asset:", error);
      alert("Failed to save asset: " + error.message);
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm("Are you sure you want to delete this asset?")) {
      try {
        await deleteAsset(id);
      } catch (error) {
        console.error("Failed to delete asset:", error);
        alert("Failed to delete asset: " + error.message);
      }
    }
  };

  const handleViewDetails = async (asset) => {
    setSelectedAsset(asset);
    setDetailOpen(true);
    setDetailTab(0);
    
    try {
      const [scans, vulns] = await Promise.all([
        getAssetScans(asset.id),
        getAssetVulnerabilities(asset.id)
      ]);
      setAssetScans(scans);
      setAssetVulns(vulns);
    } catch (error) {
      console.error("Failed to load asset details:", error);
    }
  };

  const getAssetIcon = (type) => {
    switch (type) {
      case "web_application":
        return <Language />;
      case "network_range":
        return <Router />;
      case "host":
        return <Computer />;
      default:
        return <Security />;
    }
  };

  const getStatusColor = (status) => {
    return status === "active" ? "success" : "default";
  };

  const formatLastScan = (timestamp) => {
    if (!timestamp) return "Never";
    return new Date(timestamp).toLocaleDateString();
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "critical": return "error";
      case "high": return "warning";
      case "medium": return "info";
      case "low": return "success";
      default: return "default";
    }
  };

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">Assets & Targets</Typography>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => handleOpen()}
        >
          Add Asset
        </Button>
      </Box>

      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={4}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Total Assets
              </Typography>
              <Typography variant="h4">{assets.length}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Active Assets
              </Typography>
              <Typography variant="h4">
                {assets.filter((asset) => asset.is_active).length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom>
                Never Scanned
              </Typography>
              <Typography variant="h4">
                {assets.filter((asset) => !asset.last_scan_at).length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Assets Table */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Asset Inventory
          </Typography>
          {loading ? (
            <Alert severity="info">Loading assets...</Alert>
          ) : error ? (
            <Alert severity="error">Error loading assets: {error}</Alert>
          ) : assets.length === 0 ? (
            <Alert severity="info">
              No assets configured. Add your first asset to get started.
            </Alert>
          ) : (
            <TableContainer component={Paper} sx={{ mt: 2 }}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Target</TableCell>
                    <TableCell>Tags</TableCell>
                    <TableCell>Last Scan</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {assets.map((asset) => (
                    <TableRow key={asset.id}>
                      <TableCell>
                        <Box display="flex" alignItems="center" gap={1}>
                          {getAssetIcon(asset.type)}
                          <Box>
                            <Typography variant="body2" fontWeight="bold">
                              {asset.name}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {asset.description}
                            </Typography>
                          </Box>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={asset.type.replace("_", " ")}
                          size="small"
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontFamily="monospace">
                          {asset.target}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Box display="flex" gap={0.5} flexWrap="wrap">
                          {(asset.tags || []).map((tag) => (
                            <Chip
                              key={tag}
                              label={tag}
                              size="small"
                              color="primary"
                              variant="outlined"
                            />
                          ))}
                        </Box>
                      </TableCell>
                      <TableCell>{formatLastScan(asset.last_scan_at)}</TableCell>
                      <TableCell>
                        <Chip
                          label={asset.is_active ? "active" : "inactive"}
                          size="small"
                          color={asset.is_active ? "success" : "default"}
                        />
                      </TableCell>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={() => handleViewDetails(asset)}
                          color="info"
                          title="View Details"
                        >
                          <Visibility />
                        </IconButton>
                        <IconButton
                          size="small"
                          onClick={() => handleOpen(asset)}
                          color="primary"
                          title="Edit Asset"
                        >
                          <Edit />
                        </IconButton>
                        <IconButton
                          size="small"
                          onClick={() => handleDelete(asset.id)}
                          color="error"
                          title="Delete Asset"
                        >
                          <Delete />
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

      {/* Add/Edit Asset Dialog */}
      <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
        <DialogTitle>
          {editingAsset ? "Edit Asset" : "Add New Asset"}
        </DialogTitle>
        <DialogContent>
          <Box display="flex" flexDirection="column" gap={2} sx={{ mt: 1 }}>
            <TextField
              label="Asset Name"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              fullWidth
              required
            />
            <FormControl fullWidth required>
              <InputLabel>Asset Type</InputLabel>
              <Select
                value={formData.type}
                label="Asset Type"
                onChange={(e) => setFormData({ ...formData, type: e.target.value })}
              >
                <MenuItem value="host">Host</MenuItem>
                <MenuItem value="network_range">Network Range</MenuItem>
                <MenuItem value="web_application">Web Application</MenuItem>
                <MenuItem value="service">Service</MenuItem>
              </Select>
            </FormControl>
            <TextField
              label="Target"
              value={formData.target}
              onChange={(e) => setFormData({ ...formData, target: e.target.value })}
              fullWidth
              required
              placeholder="e.g., 192.168.1.1, https://example.com, 10.0.0.0/24"
            />
            <TextField
              label="Description"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              fullWidth
              multiline
              rows={3}
            />
            <TextField
              label="Tags"
              value={formData.tags}
              onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
              fullWidth
              placeholder="production, web, critical (comma separated)"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>Cancel</Button>
          <Button onClick={handleSave} variant="contained">
            {editingAsset ? "Update" : "Add"} Asset
          </Button>
        </DialogActions>
      </Dialog>

      {/* Asset Details Dialog */}
      <Dialog open={detailOpen} onClose={() => setDetailOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Asset Details: {selectedAsset?.name}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
            <Tabs value={detailTab} onChange={(e, newValue) => setDetailTab(newValue)}>
              <Tab label={`Scans (${assetScans.length})`} icon={<PlayArrow />} />
              <Tab label={`Vulnerabilities (${assetVulns.length})`} icon={<BugReport />} />
            </Tabs>
          </Box>

          {detailTab === 0 && (
            <Box>
              <Typography variant="h6" gutterBottom>Recent Scans</Typography>
              {assetScans.length === 0 ? (
                <Alert severity="info">No scans found for this asset.</Alert>
              ) : (
                <List>
                  {assetScans.map((scan) => (
                    <React.Fragment key={scan.id}>
                      <ListItem>
                        <ListItemText
                          primary={
                            <Box display="flex" justifyContent="space-between" alignItems="center">
                              <Typography variant="body1">
                                {scan.tool.toUpperCase()} Scan
                              </Typography>
                              <Chip 
                                label={scan.status} 
                                size="small" 
                                color={scan.status === 'completed' ? 'success' : scan.status === 'failed' ? 'error' : 'info'}
                              />
                            </Box>
                          }
                          secondary={
                            <Box>
                              <Typography variant="caption" color="text.secondary">
                                Started: {new Date(scan.created_at).toLocaleString()}
                              </Typography>
                              {scan.completed_at && (
                                <Typography variant="caption" color="text.secondary" display="block">
                                  Completed: {new Date(scan.completed_at).toLocaleString()}
                                </Typography>
                              )}
                              <Typography variant="caption" color="text.secondary" display="block">
                                Findings: {scan.findings_count || 0}
                              </Typography>
                            </Box>
                          }
                        />
                      </ListItem>
                      <Divider />
                    </React.Fragment>
                  ))}
                </List>
              )}
            </Box>
          )}

          {detailTab === 1 && (
            <Box>
              <Typography variant="h6" gutterBottom>Vulnerabilities</Typography>
              {assetVulns.length === 0 ? (
                <Alert severity="success">No vulnerabilities found for this asset.</Alert>
              ) : (
                <List>
                  {assetVulns.map((vuln) => (
                    <React.Fragment key={vuln.id}>
                      <ListItem>
                        <ListItemText
                          primary={
                            <Box display="flex" justifyContent="space-between" alignItems="center">
                              <Typography variant="body1">{vuln.name}</Typography>
                              <Chip 
                                label={vuln.severity} 
                                size="small" 
                                color={getSeverityColor(vuln.severity)}
                              />
                            </Box>
                          }
                          secondary={
                            <Box>
                              <Typography variant="body2" color="text.secondary">
                                {vuln.description}
                              </Typography>
                              <Typography variant="caption" color="text.secondary" display="block">
                                Host: {vuln.host} {vuln.port && `| Port: ${vuln.port}`}
                              </Typography>
                              <Typography variant="caption" color="text.secondary" display="block">
                                Discovered: {new Date(vuln.first_seen).toLocaleString()}
                              </Typography>
                            </Box>
                          }
                        />
                      </ListItem>
                      <Divider />
                    </React.Fragment>
                  ))}
                </List>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default Assets;
