#! /usr/bin/env sh

demodir=$(pwd)
export TRIVY_DISABLE_NODE_COLLECTOR=true
# note, we see only HIGH/CRITICAL issues throughout the demo
export TRIVY_SEVERITY=HIGH

# scan workloads in cluster
trivy k8s --report summary 
# see details
trivy k8s --report all 
# use a compliance framework
# https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
trivy k8s --report summary --compliance k8s-pss-baseline-0.1

# k8s cluster scanning
trivy k8s --report summary --compliance k8s-cis-1.23