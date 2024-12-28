#!bin/bash
cd gcp/terraform

#### Cluster
terraform init
terraform apply 
cd ../..

#### Access
gcloud auth login
gcloud config set project eminent-crane-445222-m9 
gcloud container clusters get-credentials secops-cluster --region=europe-west1

#### SecOps
helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard --create-namespace --namespace kubernetes-dashboard --set kong.admin.tls.enabled=false
kubectl apply -f applications/kubernetes-dashboard/cluster-role.yaml -f applications/kubernetes-dashboard/service-account.yaml
kubectl create namespace secops
kubectl apply -f applications/kube-bench/cronjob.yaml -f applications/kube-hunter/job.yaml
kubectl apply -f applications/owasp-juice/deployment.yaml -f applications/owasp-juice/svc.yaml -n secops
kubectl apply -f applications/sock-shop/demo.yaml