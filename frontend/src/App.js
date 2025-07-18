import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { ThemeProvider, createTheme } from "@mui/material/styles";
import CssBaseline from "@mui/material/CssBaseline";
import { AuthProvider } from "./contexts/AuthContext";
import Layout from "./components/Layout";
import Home from "./pages/Home";
import Assets from "./pages/Assets";
import ScanLauncher from "./pages/ScanLauncher";
import Dashboard from "./pages/Dashboard";
import Vulnerabilities from "./pages/Vulnerabilities";
import Settings from "./pages/Settings";

// Dark theme for security dashboard
const darkTheme = createTheme({
  palette: {
    mode: "dark",
    primary: {
      main: "#00e676", // Green accent
    },
    secondary: {
      main: "#ff5722", // Orange for warnings
    },
    background: {
      default: "#0a0a0a",
      paper: "#1a1a1a",
    },
    error: {
      main: "#f44336",
    },
    warning: {
      main: "#ff9800",
    },
    info: {
      main: "#2196f3",
    },
    success: {
      main: "#4caf50",
    },
  },
  typography: {
    fontFamily: '"JetBrains Mono", "Roboto Mono", monospace',
    h1: {
      fontSize: "2.5rem",
      fontWeight: 600,
    },
    h2: {
      fontSize: "2rem",
      fontWeight: 500,
    },
  },
  components: {
    MuiCard: {
      styleOverrides: {
        root: {
          border: "1px solid #333",
        },
      },
    },
  },
});

function App() {
  return (
    <AuthProvider>
      <ThemeProvider theme={darkTheme}>
        <CssBaseline />
        <Router>
          <Layout>
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/assets" element={<Assets />} />
              <Route path="/scan" element={<ScanLauncher />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/vulnerabilities" element={<Vulnerabilities />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </Layout>
        </Router>
      </ThemeProvider>
    </AuthProvider>
  );
}

export default App;
