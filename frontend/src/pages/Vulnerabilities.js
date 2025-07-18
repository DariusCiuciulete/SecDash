import React, { useState, useEffect } from "react";
import { useVulnerabilities } from "../hooks/useApi";
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
  Chip,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Badge,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Link,
} from "@mui/material";
import {
  BugReport,
  Security,
  Warning,
  Info,
  Edit,
  FilterList,
  ExpandMore,
  OpenInNew,
  Assignment,
} from "@mui/icons-material";

function Vulnerabilities() {
  const { vulnerabilities, loading, error, updateVulnerability } = useVulnerabilities();
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [notes, setNotes] = useState("");
  const [stats, setStats] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    total: 0,
  });

  // Calculate stats from loaded vulnerabilities
  useEffect(() => {
    const newStats = vulnerabilities.reduce(
      (acc, vuln) => {
        acc[vuln.severity]++;
        acc.total++;
        return acc;
      },
      { critical: 0, high: 0, medium: 0, low: 0, total: 0 }
    );
    setStats(newStats);
  }, [vulnerabilities]);

  const handleViewDetails = (vuln) => {
    setSelectedVuln(vuln);
    setNotes(vuln.notes);
    setOpen(true);
  };

  const handleUpdateNotes = async () => {
    try {
      await updateVulnerability(selectedVuln.id, { notes });
      setOpen(false);
    } catch (error) {
      console.error("Failed to update notes:", error);
      alert("Failed to update notes: " + error.message);
    }
  };

  const handleStatusChange = async (id, newStatus) => {
    try {
      await updateVulnerability(id, { status: newStatus });
    } catch (error) {
      console.error("Failed to update status:", error);
      alert("Failed to update status: " + error.message);
    }
  };

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

  const getStatusColor = (status) => {
    switch (status) {
      case "open":
        return "error";
      case "acknowledged":
        return "warning";
      case "fixed":
        return "success";
      case "false_positive":
        return "default";
      default:
        return "default";
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case "critical":
        return <BugReport color="error" />;
      case "high":
        return <Warning color="warning" />;
      case "medium":
        return <Security color="info" />;
      case "low":
        return <Info color="success" />;
      default:
        return <Security />;
    }
  };

  const filteredVulnerabilities = vulnerabilities.filter((vuln) => {
    const severityMatch = filter === "all" || vuln.severity === filter;
    const statusMatch = statusFilter === "all" || vuln.status === statusFilter;
    return severityMatch && statusMatch;
  });

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString();
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Vulnerability Management
      </Typography>
      <Typography variant="subtitle1" color="text.secondary" gutterBottom>
        Review, analyze, and manage discovered vulnerabilities
      </Typography>

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mt: 2, mb: 3 }}>
        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <BugReport color="error" sx={{ mr: 2 }} />
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Critical
                  </Typography>
                  <Typography variant="h4" color="error.main">
                    {stats.critical}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Warning color="warning" sx={{ mr: 2 }} />
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    High
                  </Typography>
                  <Typography variant="h4" color="warning.main">
                    {stats.high}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Security color="info" sx={{ mr: 2 }} />
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Medium
                  </Typography>
                  <Typography variant="h4" color="info.main">
                    {stats.medium}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Info color="success" sx={{ mr: 2 }} />
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Low
                  </Typography>
                  <Typography variant="h4" color="success.main">
                    {stats.low}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Assignment sx={{ mr: 2 }} />
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Total
                  </Typography>
                  <Typography variant="h4">{stats.total}</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box display="flex" alignItems="center" gap={2} flexWrap="wrap">
            <FilterList />
            <FormControl size="small" sx={{ minWidth: 120 }}>
              <InputLabel>Severity</InputLabel>
              <Select
                value={filter}
                label="Severity"
                onChange={(e) => setFilter(e.target.value)}
              >
                <MenuItem value="all">All</MenuItem>
                <MenuItem value="critical">Critical</MenuItem>
                <MenuItem value="high">High</MenuItem>
                <MenuItem value="medium">Medium</MenuItem>
                <MenuItem value="low">Low</MenuItem>
              </Select>
            </FormControl>
            <FormControl size="small" sx={{ minWidth: 120 }}>
              <InputLabel>Status</InputLabel>
              <Select
                value={statusFilter}
                label="Status"
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <MenuItem value="all">All</MenuItem>
                <MenuItem value="open">Open</MenuItem>
                <MenuItem value="acknowledged">Acknowledged</MenuItem>
                <MenuItem value="fixed">Fixed</MenuItem>
                <MenuItem value="false_positive">False Positive</MenuItem>
              </Select>
            </FormControl>
            <Typography variant="body2" color="text.secondary" sx={{ ml: "auto" }}>
              Showing {filteredVulnerabilities.length} of {vulnerabilities.length} vulnerabilities
            </Typography>
          </Box>
        </CardContent>
      </Card>

      {/* Vulnerabilities Table */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Vulnerability List
          </Typography>
          {filteredVulnerabilities.length === 0 ? (
            <Alert severity="info">
              No vulnerabilities found matching the current filters.
            </Alert>
          ) : (
            <TableContainer component={Paper} sx={{ mt: 2 }}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Severity</TableCell>
                    <TableCell>Host</TableCell>
                    <TableCell>Port/Service</TableCell>
                    <TableCell>Vulnerability</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Discovered</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredVulnerabilities.map((vuln) => (
                    <TableRow key={vuln.id}>
                      <TableCell>
                        <Box display="flex" alignItems="center" gap={1}>
                          {getSeverityIcon(vuln.severity)}
                          <Chip
                            label={vuln.severity}
                            size="small"
                            color={getSeverityColor(vuln.severity)}
                          />
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontFamily="monospace">
                          {vuln.host}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {vuln.port}/{vuln.service}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontWeight="bold">
                          {vuln.vulnerability}
                        </Typography>
                        {vuln.cve !== "N/A" && (
                          <Typography variant="caption" color="text.secondary">
                            {vuln.cve}
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <FormControl size="small">
                          <Select
                            value={vuln.status}
                            onChange={(e) => handleStatusChange(vuln.id, e.target.value)}
                            variant="standard"
                          >
                            <MenuItem value="open">Open</MenuItem>
                            <MenuItem value="acknowledged">Acknowledged</MenuItem>
                            <MenuItem value="fixed">Fixed</MenuItem>
                            <MenuItem value="false_positive">False Positive</MenuItem>
                          </Select>
                        </FormControl>
                      </TableCell>
                      <TableCell>{formatDate(vuln.discoveredDate)}</TableCell>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={() => handleViewDetails(vuln)}
                          color="primary"
                        >
                          <Edit />
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

      {/* Vulnerability Details Dialog */}
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          Vulnerability Details - {selectedVuln?.vulnerability}
        </DialogTitle>
        <DialogContent>
          {selectedVuln && (
            <Box>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    Host:
                  </Typography>
                  <Typography variant="body1" fontFamily="monospace">
                    {selectedVuln.host}:{selectedVuln.port}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    Severity:
                  </Typography>
                  <Chip
                    label={selectedVuln.severity}
                    size="small"
                    color={getSeverityColor(selectedVuln.severity)}
                  />
                </Grid>
              </Grid>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMore />}>
                  <Typography variant="h6">Description</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography>{selectedVuln.description}</Typography>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMore />}>
                  <Typography variant="h6">Impact</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography>{selectedVuln.impact}</Typography>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMore />}>
                  <Typography variant="h6">Recommendation</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography>{selectedVuln.recommendation}</Typography>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMore />}>
                  <Typography variant="h6">References</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Box>
                    {selectedVuln.references.map((ref, idx) => (
                      <Box key={idx} display="flex" alignItems="center" gap={1}>
                        <OpenInNew fontSize="small" />
                        <Link href={ref} target="_blank" rel="noopener noreferrer">
                          {ref}
                        </Link>
                      </Box>
                    ))}
                  </Box>
                </AccordionDetails>
              </Accordion>

              <Box sx={{ mt: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Notes
                </Typography>
                <TextField
                  fullWidth
                  multiline
                  rows={4}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Add notes about this vulnerability..."
                  variant="outlined"
                />
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={handleUpdateNotes} variant="contained">
            Update Notes
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default Vulnerabilities;
