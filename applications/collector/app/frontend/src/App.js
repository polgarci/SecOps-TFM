import React, { useEffect, useState } from "react";
import "./App.css";

function App() {
  const [logs, setLogs] = useState({});
  const [namespace, setNamespace] = useState("secops");
  const [labelSelector, setLabelSelector] = useState("");

  useEffect(() => {
    fetchLogs();
  }, []);

  const fetchLogs = async () => {
    const response = await fetch(
      `/logs?namespace=${namespace}&labelSelector=${labelSelector}`
    );
    const data = await response.json();
    setLogs(data);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    fetchLogs();
  };

  return (
    <div className="app-container">
      <h1>Kubernetes Logs Viewer</h1>
      <form className="log-form" onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Namespace"
          value={namespace}
          onChange={(e) => setNamespace(e.target.value)}
        />
        <input
          type="text"
          placeholder="Label Selector (Optional)"
          value={labelSelector}
          onChange={(e) => setLabelSelector(e.target.value)}
        />
        <button type="submit">Fetch Logs</button>
      </form>

      <div className="logs-container">
        {Object.keys(logs).length === 0 ? (
          <p className="no-logs">No logs to display. Please fetch logs.</p>
        ) : (
          Object.keys(logs).map((date) => (
            <div key={date} className="log-group">
              <h2>Logs for {date}</h2>
              <table className="log-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {logs[date].map((log, index) => (
                    <tr key={index}>
                      <td>{log.timestamp}</td>
                      <td>{log.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default App;
