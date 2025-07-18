// Utility functions for SecDash

export const formatTimeAgo = (timestamp) => {
  const now = new Date();
  const date = new Date(timestamp);
  const diffInSeconds = Math.floor((now - date) / 1000);

  if (diffInSeconds < 60) {
    return `${diffInSeconds}s ago`;
  }

  const diffInMinutes = Math.floor(diffInSeconds / 60);
  if (diffInMinutes < 60) {
    return `${diffInMinutes}m ago`;
  }

  const diffInHours = Math.floor(diffInMinutes / 60);
  if (diffInHours < 24) {
    return `${diffInHours}h ago`;
  }

  const diffInDays = Math.floor(diffInHours / 24);
  if (diffInDays < 30) {
    return `${diffInDays}d ago`;
  }

  const diffInMonths = Math.floor(diffInDays / 30);
  if (diffInMonths < 12) {
    return `${diffInMonths}mo ago`;
  }

  const diffInYears = Math.floor(diffInMonths / 12);
  return `${diffInYears}y ago`;
};

export const formatDuration = (startTime, endTime = null) => {
  const start = new Date(startTime);
  const end = endTime ? new Date(endTime) : new Date();
  const diffInSeconds = Math.floor((end - start) / 1000);

  if (diffInSeconds < 60) {
    return `${diffInSeconds}s`;
  }

  const minutes = Math.floor(diffInSeconds / 60);
  const seconds = diffInSeconds % 60;

  if (minutes < 60) {
    return `${minutes}m ${seconds}s`;
  }

  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;

  return `${hours}h ${remainingMinutes}m`;
};

export const getSeverityColor = (severity) => {
  const colors = {
    critical: "#f44336",
    high: "#ff9800", 
    medium: "#2196f3",
    low: "#4caf50",
    info: "#9e9e9e",
  };
  return colors[severity?.toLowerCase()] || colors.info;
};

export const getSeverityScore = (severity) => {
  const scores = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  return scores[severity?.toLowerCase()] || 0;
};

export const getStatusColor = (status) => {
  const colors = {
    running: "info",
    completed: "success",
    failed: "error",
    stopped: "warning",
    pending: "default",
    open: "error",
    acknowledged: "warning",
    fixed: "success",
    false_positive: "default",
    active: "success",
    inactive: "default",
  };
  return colors[status?.toLowerCase()] || "default";
};

export const validateIPAddress = (ip) => {
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipRegex.test(ip);
};

export const validateCIDR = (cidr) => {
  const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-2]?[0-9]|3[0-2])$/;
  return cidrRegex.test(cidr);
};

export const validateURL = (url) => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

export const validateTarget = (target, type) => {
  switch (type) {
    case "host":
      return validateIPAddress(target);
    case "network_range":
      return validateCIDR(target);
    case "web_application":
    case "domain":
      return validateURL(target) || /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(target);
    default:
      return true;
  }
};

export const formatBytes = (bytes, decimals = 2) => {
  if (bytes === 0) return "0 Bytes";

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
};

export const generateScanId = () => {
  const timestamp = Date.now().toString(36);
  const randomPart = Math.random().toString(36).substring(2, 7);
  return `scan_${timestamp}_${randomPart}`;
};

export const exportToCSV = (data, filename) => {
  if (!data || data.length === 0) return;

  const headers = Object.keys(data[0]);
  const csvContent = [
    headers.join(","),
    ...data.map(row => headers.map(header => {
      const cell = row[header];
      // Escape commas and quotes in CSV
      if (typeof cell === "string" && (cell.includes(",") || cell.includes('"'))) {
        return `"${cell.replace(/"/g, '""')}"`;
      }
      return cell;
    }).join(","))
  ].join("\n");

  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const link = document.createElement("a");
  
  if (link.download !== undefined) {
    const url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", filename);
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }
};

export const exportToJSON = (data, filename) => {
  const jsonContent = JSON.stringify(data, null, 2);
  const blob = new Blob([jsonContent], { type: "application/json;charset=utf-8;" });
  const link = document.createElement("a");
  
  if (link.download !== undefined) {
    const url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", filename);
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }
};

export const debounce = (func, wait) => {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
};

export const throttle = (func, limit) => {
  let inThrottle;
  return function() {
    const args = arguments;
    const context = this;
    if (!inThrottle) {
      func.apply(context, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
};

export const parseCommandOutput = (output, tool) => {
  // Parse tool-specific output formats
  switch (tool) {
    case "nmap":
      return parseNmapOutput(output);
    case "zap":
      return parseZapOutput(output);
    default:
      return { raw: output };
  }
};

const parseNmapOutput = (output) => {
  // Basic nmap output parsing
  const lines = output.split('\n');
  const hosts = [];
  let currentHost = null;

  lines.forEach(line => {
    const hostMatch = line.match(/Nmap scan report for (.+)/);
    if (hostMatch) {
      if (currentHost) hosts.push(currentHost);
      currentHost = { host: hostMatch[1], ports: [] };
    }

    const portMatch = line.match(/(\d+)\/(\w+)\s+(\w+)\s+(.+)/);
    if (portMatch && currentHost) {
      currentHost.ports.push({
        port: portMatch[1],
        protocol: portMatch[2],
        state: portMatch[3],
        service: portMatch[4]
      });
    }
  });

  if (currentHost) hosts.push(currentHost);
  return { hosts, raw: output };
};

const parseZapOutput = (output) => {
  // Basic ZAP output parsing - would need to be adapted for actual ZAP output format
  try {
    const parsed = JSON.parse(output);
    return parsed;
  } catch {
    return { raw: output };
  }
};
