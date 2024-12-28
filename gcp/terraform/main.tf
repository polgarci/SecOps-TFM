data "google_client_config" "this"{}

provider "kubernetes"{
    host = "https://${module.gke.endpoint}"
    token =  data.google_client_config.this.access_token
    cluster_ca_certificate = base64decode(module.gke.ca_certificate)
}

provider "google" {
    project = "eminent-crane-445222-m9"
    region  = "europe-west1"
    credentials = "credentials.json"
}

provider "google-beta" {
        project = "eminent-crane-445222-m9"
    region  = "europe-west1"
    credentials = "credentials.json"
}

terraform {
  required_version = ">=0.12.6"

  required_providers {
    google = {
      source = "hashicorp/google"
    }

    null = {
      version = ">= 3.0"
    }
  }
}

###########################################################################
# Google Kubernetes Engine
###########################################################################

module "gke" {
    source          = "terraform-google-modules/kubernetes-engine/google"
    project_id      = "eminent-crane-445222-m9"
    name            = "secops-cluster"
    region          = "europe-west1"
    zones           = [ "europe-west1-b", "europe-west1-c"]
    network         = "gke-vpc"
    subnetwork      = "eu-west1-gks"
    ip_range_pods    = "eu-west1-gks-pods"
    ip_range_services = "eu-west1-gks-svc"
    http_load_balancing = false
    network_policy = false
    horizontal_pod_autoscaling = true
    filestore_csi_driver = false
    dns_cache = false


    node_pools = [{
        name         = "default-node-pool"
        machine_type = "e2-medium"
        node_locations = "europe-west1-b,europe-west1-c"
        min_count       = "1"
        max_count       = "6"
        local_ssd_count = 0
        spot            = true
        disk_size_gb    = 15
        disk_type       = "pd-standard"
        image_type  = "COS_CONTAINERD"
        enable_gcfs = false
        enable_gvnic = false
        logging_variant = "DEFAULT"
        auto_repair = true
        auto_upgrade    = true
        servoce_account = ""
        preemptible = false
        initial_node_count = 1
    }]

    deletion_protection = false

    depends_on = [ module.vpc ]
}

###########################################################################
# VPC Network
###########################################################################

module "vpc"{
    source = "terraform-google-modules/network/google"
    version = "~>10.0.0"

    project_id = "eminent-crane-445222-m9"
    network_name = "gke-vpc"

    subnets = [
        {
            subnet_name = "eu-west1-gks"
            subnet_ip   = "10.128.0.0/22"
            subnet_region = "europe-west1"
        }
    ]

    secondary_ranges = {
        eu-west1-gks = [
            {
                range_name    = "eu-west1-gks-pods"
                ip_cidr_range = "10.0.0.0/10"
            },
            {
                range_name = "eu-west1-gks-svc"
                ip_cidr_range = "10.128.32.0/20"
            }
        ],
    }

    routes = [
        {
            name   = "egress-internet"
            description = "Route trough IGW to access internet"
            destination_range = "0.0.0.0/0"
            tags        = "egress-inet"
            next_hop_internet = "true"     
        }
    ]
}