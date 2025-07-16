import React, { useState } from "react";

function App() {
  // State for input and tracking multiple scans
  const [target, setTarget] = useState("");
  const [scans, setScans] = useState([]); // Array of { scanId, target, status, result }
  const [selectedScan, setSelectedScan] = useState(null); // The scan currently being viewed

  // Submit a scan and add it to history
  const submitScan = async (e) => {
    e.preventDefault();
    const res = await fetch("http://localhost:8000/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    const data = await res.json();
    // Add new scan to scans array
    setScans((prev) => [
      ...prev,
      {
        scanId: data.scan_id,
        target: target,
        status: data.status,
        result: null,
      },
    ]);
    setTarget(""); // Clear input
  };

  // Poll status/result for a specific scan
  const checkScan = async (scanId) => {
    const res = await fetch(`http://localhost:8000/scans/${scanId}`);
    const data = await res.json();
    // Update scans array with latest status/result
    setScans((prev) =>
      prev.map((scan) =>
        scan.scanId === scanId
          ? { ...scan, status: data.status, result: data.result }
          : scan
      )
    );
    // If we're viewing this scan, update the selected scan as well
    if (selectedScan && selectedScan.scanId === scanId) {
      setSelectedScan({
        ...selectedScan,
        status: data.status,
        result: data.result,
      });
    }
  };

  // When clicking "View" for a scan
  const handleViewResult = (scan) => {
    setSelectedScan(scan);
  };

  return (
    <div className="App" style={{ padding: "2rem" }}>
      <h1>SecDash — Scan Dashboard</h1>
      <form onSubmit={submitScan} style={{ marginBottom: 20 }}>
        <label>
          Target:&nbsp;
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="e.g. scanme.nmap.org"
            required
          />
        </label>
        <button type="submit" style={{ marginLeft: 8 }}>
          Start Scan
        </button>
      </form>

      {/* Scan History Table */}
      <h2>Scan History</h2>
      <table style={{ width: "100%", marginBottom: 30, borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ background: "#222", color: "#fff" }}>
            <th style={{ padding: "0.5em", border: "1px solid #444" }}>Scan ID</th>
            <th style={{ padding: "0.5em", border: "1px solid #444" }}>Target</th>
            <th style={{ padding: "0.5em", border: "1px solid #444" }}>Status</th>
            <th style={{ padding: "0.5em", border: "1px solid #444" }}>Action</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.scanId}>
              <td style={{ padding: "0.5em", border: "1px solid #ccc" }}>
                <code style={{ fontSize: "0.9em" }}>{scan.scanId.slice(0, 8)}...</code>
              </td>
              <td style={{ padding: "0.5em", border: "1px solid #ccc" }}>{scan.target}</td>
              <td style={{ padding: "0.5em", border: "1px solid #ccc" }}>{scan.status}</td>
              <td style={{ padding: "0.5em", border: "1px solid #ccc" }}>
                <button onClick={() => checkScan(scan.scanId)} style={{ marginRight: 8 }}>
                  Refresh
                </button>
                <button onClick={() => handleViewResult(scan)}>
                  View
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* Selected Scan Result */}
      {selectedScan && (
        <div style={{ marginTop: 24 }}>
          <h2>Scan Result</h2>
          <p>
            <strong>Scan ID:</strong> {selectedScan.scanId}
            <br />
            <strong>Status:</strong> {selectedScan.status}
          </p>
          <pre
            style={{
              background: "#222",
              color: "#eee",
              padding: "1em",
              borderRadius: "8px",
              overflowX: "auto",
            }}
          >
            {JSON.stringify(selectedScan.result, null, 2)}
          </pre>
          <button style={{ marginTop: 10 }} onClick={() => setSelectedScan(null)}>
            Close
          </button>
        </div>
      )}
    </div>
  );
}

export default App;
