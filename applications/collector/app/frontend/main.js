import React, { useEffect, useState } from "react";

function App() {
  const [logs, setLogs] = useState({});
  const [namespace, setNamespace] = useState("default");
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
    <div>
      <h1>Kubernetes Logs Viewer</h1>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Namespace"
          value={namespace}
          onChange={(e) => setNamespace(e.target.value)}
        />
        <input
          type="text"
          placeholder="Label Selector"
          value={labelSelector}
          onChange={(e) => setLabelSelector(e.target.value)}
        />
        <button type="submit">Fetch Logs</button>
      </form>
      {Object.keys(logs).map((date) => (
        <div key={date}>
          <h2>{date}</h2>
          <ul>
            {logs[date].map((log, index) => (
              <li key={index}>
                [{log.timestamp}] {log.message}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

export default App;