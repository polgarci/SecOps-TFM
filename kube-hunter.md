2025-01-07 14:00:02,501 INFO kube_hunter.modules.report.collector Started hunting
2025-01-07 14:00:02,501 INFO kube_hunter.modules.report.collector Discovering Open Kubernetes Services
2025-01-07 14:00:02,521 INFO kube_hunter.modules.report.collector Found vulnerability "Read access to pod's service account token" in Local to Pod (kube-hunter-28937640-zvkjc)
2025-01-07 14:00:02,521 INFO kube_hunter.modules.report.collector Found vulnerability "CAP_NET_RAW Enabled" in Local to Pod (kube-hunter-28937640-zvkjc)
2025-01-07 14:00:02,522 INFO kube_hunter.modules.report.collector Found vulnerability "Access to pod's secrets" in Local to Pod (kube-hunter-28937640-zvkjc)
2025-01-07 14:00:02,748 INFO kube_hunter.modules.report.collector Found open service "Kubelet API (readonly)" at 10.0.2.1:10255
2025-01-07 14:00:02,758 INFO kube_hunter.modules.report.collector Found open service "Kubelet API" at 10.0.2.1:10250
2025-01-07 14:00:02,851 INFO kube_hunter.modules.report.collector Found vulnerability "Privileged Container" in 10.0.2.1:10255
2025-01-07 14:00:02,852 INFO kube_hunter.modules.report.collector Found vulnerability "Cluster Health Disclosure" in 10.0.2.1:10255
2025-01-07 14:00:02,857 INFO kube_hunter.modules.report.collector Found vulnerability "Exposed Pods" in 10.0.2.1:10255
2025-01-07 14:00:02,864 INFO kube_hunter.modules.report.collector Found vulnerability "Pod With Mount To /var/log" in 10.0.2.1:10255
2025-01-07 14:00:10,288 INFO kube_hunter.modules.report.collector Found open service "API Server" at 10.128.32.1:443
2025-01-07 14:00:10,370 INFO kube_hunter.modules.report.collector Found vulnerability "Access to API using service account token" in 10.128.32.1:443
2025-01-07 14:00:10,382 INFO kube_hunter.modules.report.collector Found vulnerability "K8s Version Disclosure" in 10.128.32.1:443

Nodes
+-------------+-------------+
| TYPE        | LOCATION    |
+-------------+-------------+
| Node/Master | 10.128.32.1 |
+-------------+-------------+
| Node/Master | 10.0.2.1    |
+-------------+-------------+

Detected Services
+----------------------+-----------------+----------------------+
| SERVICE              | LOCATION        | DESCRIPTION          |
+----------------------+-----------------+----------------------+
| Kubelet API          | 10.0.2.1:10255  | The read-only port   |
| (readonly)           |                 | on the kubelet       |
|                      |                 | serves health        |
|                      |                 | probing endpoints,   |
|                      |                 |     and is relied    |
|                      |                 | upon by many         |
|                      |                 | kubernetes           |
|                      |                 | components           |
+----------------------+-----------------+----------------------+
| Kubelet API          | 10.0.2.1:10250  | The Kubelet is the   |
|                      |                 | main component in    |
|                      |                 | every Node, all pod  |
|                      |                 | operations goes      |
|                      |                 | through the kubelet  |
+----------------------+-----------------+----------------------+
| API Server           | 10.128.32.1:443 | The API server is in |
|                      |                 | charge of all        |
|                      |                 | operations on the    |
|                      |                 | cluster.             |
+----------------------+-----------------+----------------------+

Vulnerabilities
For further information about a vulnerability, search its ID in: 
https://avd.aquasec.com/
+--------+----------------------+----------------------+----------------------+----------------------+----------------------+
| ID     | LOCATION             | MITRE CATEGORY       | VULNERABILITY        | DESCRIPTION          | EVIDENCE             |
+--------+----------------------+----------------------+----------------------+----------------------+----------------------+
| KHV047 | 10.0.2.1:10255       | Privilege Escalation | Pod With Mount To    | A pod can create     | pods: fluentbit-     |
|        |                      | // hostPath mount    | /var/log             | symlinks in the      | gke-247k2            |
|        |                      |                      |                      | /var/log directory   |                      |
|        |                      |                      |                      | on the host, which   |                      |
|        |                      |                      |                      | can lead to a root   |                      |
|        |                      |                      |                      | directory traveral   |                      |
+--------+----------------------+----------------------+----------------------+----------------------+----------------------+
| KHV044 | 10.0.2.1:10255       | Privilege Escalation | Privileged Container | A Privileged         | pod: kube-proxy-gke- |
|        |                      | // Privileged        |                      | container exist on a | secops-cluster-      |
|        |                      | container            |                      | node                 | default-node-        |
|        |                      |                      |                      |     could expose the | pool-e0b01756-2m9b,  |
|        |                      |                      |                      | node/cluster to      | container: kube-     |
|        |                      |                      |                      | unwanted root        | proxy, count: 5      |
|        |                      |                      |                      | operations           |                      |
+--------+----------------------+----------------------+----------------------+----------------------+----------------------+
| None   | Local to Pod (kube-h | Lateral Movement //  | CAP_NET_RAW Enabled  | CAP_NET_RAW is       |                      |
|        | unter-28937640-zvkjc | ARP poisoning and IP |                      | enabled by default   |                      |
|        | )                    | spoofing             |                      | for pods.            |                      |
|        |                      |                      |                      |     If an attacker   |                      |
|        |                      |                      |                      | manages to           |                      |
|        |                      |                      |                      | compromise a pod,    |                      |
|        |                      |                      |                      |     they could       |                      |
|        |                      |                      |                      | potentially take     |                      |
|        |                      |                      |                      | advantage of this    |                      |
|        |                      |                      |                      | capability to        |                      |
|        |                      |                      |                      | perform network      |                      |
|        |                      |                      |                      |     attacks on other |                      |
|        |                      |                      |                      | pods running on the  |                      |
|        |                      |                      |                      | same node            |                      |
+--------+----------------------+----------------------+----------------------+----------------------+----------------------+
| KHV043 | 10.0.2.1:10255       | Initial Access //    | Cluster Health       | By accessing the     | status: ok           |
|        |                      | General Sensitive    | Disclosure           | open /healthz        |                      |
|        |                      | Information          |                      | handler,             |                      |
|        |                      |                      |                      |     an attacker      |                      |
|        |                      |                      |                      | could get the        |                      |
|        |                      |                      |                      | cluster health state |                      |
|        |                      |                      |                      | without              |                      |
|        |                      |                      |                      | authenticating       |                      |
+--------+----------------------+----------------------+----------------------+----------------------+----------------------+
| KHV002 | 10.128.32.1:443      | Initial Access //    | K8s Version          | The kubernetes       | v1.30.6-gke.1125000  |
|        |                      | Exposed sensitive    | Disclosure           | version could be     |                      |
|        |                      | interfaces           |                      | obtained from the    |                      |
|        |                      |                      |                      | /version endpoint    |                      |
+--------+----------------------+----------------------+----------------------+----------------------+----------------------+
| KHV005 | 10.128.32.1:443      | Discovery // Access  | Access to API using  | The API Server port  | b'{"kind":"APIVersio |
|        |                      | the K8S API Server   | service account      | is accessible.       | ns","versions":["v1" |
|        |                      |                      | token                |     Depending on     | ],"serverAddressByCl |
|        |                      |                      |                      | your RBAC settings   | ientCIDRs":[{"client |
|        |                      |                      |                      | this could expose    | CIDR":"0.0.0.0/0","s |
|        |                      |                      |                      | access to or control | ...                  |
|        |                      |                      |                      | of your cluster.     |                      |
+--------+----------------------+----------------------+----------------------+----------------------+----------------------+
| KHV052 | 10.0.2.1:10255       | Discovery // Access  | Exposed Pods         | An attacker could    | count: 19            |
|        |                      | Kubelet API          |                      | view sensitive       |                      |
|        |                      |                      |                      | information about    |                      |
|        |                      |                      |                      | pods that are        |                      |
|        |                      |                      |                      |     bound to a Node  |                      |
|        |                      |                      |                      | using the /pods      |                      |
|        |                      |                      |                      | endpoint             |                      |
+--------+----------------------+----------------------+----------------------+----------------------+----------------------+
| None   | Local to Pod (kube-h | Credential Access // | Access to pod's      | Accessing the pod's  | ['/var/run/secrets/k |
|        | unter-28937640-zvkjc | Access container     | secrets              | secrets within a     | ubernetes.io/service |
|        | )                    | service account      |                      | compromised pod      | account/namespace',  |
|        |                      |                      |                      | might disclose       | '/var/run/secrets/ku |
|        |                      |                      |                      | valuable data to a   | bernetes.io/servicea |
|        |                      |                      |                      | potential attacker   | ...                  |
+--------+----------------------+----------------------+----------------------+----------------------+----------------------+
| KHV050 | Local to Pod (kube-h | Credential Access // | Read access to pod's | Accessing the pod    | eyJhbGciOiJSUzI1NiIs |
|        | unter-28937640-zvkjc | Access container     | service account      | service account      | ImtpZCI6IndiUEV2UDVz |
|        | )                    | service account      | token                | token gives an       | RDBxSnZpb2lUM3FMd0d4 |
|        |                      |                      |                      | attacker the option  | Qm5lVjdpdTYyUzBYeEFE |
|        |                      |                      |                      | to use the server    | dnBCQ00ifQ.eyJhdWQiO |
|        |                      |                      |                      | API                  | ...                  |
+--------+----------------------+----------------------+----------------------+----------------------+----------------------+