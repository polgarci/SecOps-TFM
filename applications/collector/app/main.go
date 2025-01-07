package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

type GroupedLogs map[string][]LogEntry

var clientset *kubernetes.Clientset

func main() {
	var err error
	clientset, err = getKubernetesClient()
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	http.HandleFunc("/logs", handleLogs)
	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func getKubernetesClient() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to load in-cluster configuration: %v", err)
	}
	return kubernetes.NewForConfig(config)
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "secops"
	}
	logs, err := collectCronJobLogs(namespace)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to collect logs: %v", err), http.StatusInternalServerError)
		return
	}

	groupedLogs := groupLogsByDate(logs)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(groupedLogs)
}

func collectCronJobLogs(namespace string) ([]LogEntry, error) {
	podClient := clientset.CoreV1().Pods(namespace)
	pods, err := podClient.List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods in namespace %s: %w", namespace, err)
	}

	var allLogs []LogEntry
	for _, pod := range pods.Items {
		if strings.Contains(pod.Name, "kube-hunter") || strings.Contains(pod.Name, "kube-bench") {
			for _, container := range pod.Spec.Containers {
				log.Printf("Fetching logs for Pod: %s, Container: %s", pod.Name, container.Name)
				logs, err := fetchLogsFromPod(podClient, pod.Name, container.Name)
				if err != nil {
					log.Printf("Error fetching logs for Pod: %s, Container: %s: %v", pod.Name, container.Name, err)
					continue
				}
				allLogs = append(allLogs, logs...)
			}
		}
	}

	return allLogs, nil
}

func fetchLogsFromPod(podClient corev1.PodInterface, podName, containerName string) ([]LogEntry, error) {
	req := podClient.GetLogs(podName, &v1.PodLogOptions{Container: containerName})

	stream, err := req.Stream(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to get log stream: %w", err)
	}
	defer stream.Close()

	var logs []LogEntry
	scanner := bufio.NewScanner(stream)
	for scanner.Scan() {
		line := scanner.Text()
		timestamp, message := parseLogLine(line)

		logs = append(logs, LogEntry{Timestamp: timestamp, Message: message})

	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading log stream: %w", err)
	}

	return logs, nil
}

func parseLogLine(line string) (time.Time, string) {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return time.Time{}, line
	}
	timestamp, err := time.Parse(time.RFC3339, parts[0])
	if err != nil {
		return time.Time{}, line
	}
	return timestamp, parts[1]
}

func groupLogsByDate(logs []LogEntry) GroupedLogs {
	grouped := make(GroupedLogs)
	for _, log := range logs {
		date := log.Timestamp.Format("2006-01-02")
		grouped[date] = append(grouped[date], log)
	}
	return grouped
}
