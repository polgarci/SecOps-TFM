module "eks" {
    source = "terraform-aws-modules/eks/aws"
    version = "~> 20.0"

    cluster_name = "tfm-secops"
    cluster_version = "1.31"

    vpc_id = "172.31.0.0/16"
    subnet_ids = ["subnet-06c3979097a6eed0f","subnet-065e259fb5d8ed6cb","subnet-0dc4f768e7a650ea6"]

    eks_managed_node_groups = {
        node_group = {
            ami_type = "AL2_x86_64"
            instance_types = ["t2.large", "t2.xlarge" ]

            min_size = 1
            max_size = 3
            desired_size = 1
        }
    }

    enable_cluster_creator_admin_permissions = true
    
    access_entries = {
        admin = {
            kubernetes_groups = []
            principal_arn     = "arn:aws:iam::123456789012:role/something"

            policy_associations = {
                admin = {
                    policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
                    access_scope = {
                        type = "cluster"
                    }
                }
            }
        }
    }
}