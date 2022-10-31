## create-cluster-kops

#### GIVEN:
  - A developer desktop with docker & git installed (AWS Cloud9)

#### WHEN:
  - I install kops on onto the Cloud9 instance
  - I deploy a Kubernetes cluster with kops to AWS.

#### THEN:
  - I will get a VPC
  - I will get all required IAM Roles & security groups created via terraform
  - I will get an EKS cluster using the existing VPC created via terraform
  - I will get an Amazon Linux 2 Managed Nodegroup created via terraform
  - I will get a Fargate Profile created via terraform
  - I will get IRSA enabled on my EKS cluster
  - I will get the Cluster AutoScaler 'auto' installed on my EKS cluster

#### SO THAT:
  - I can test the Cluster Autoscaler
  - I can run my 2 x tier tv application on Fargate & EC2
  - I can use this cluster for all other 'CNCF' demos that require an EKS cluster

#### [Return to Main Readme](https://github.com/bwer432/mglab-share-eks#demos)

---------------------------------------------------------------
---------------------------------------------------------------
### REQUIRES
- 00-setup-cloud9

---------------------------------------------------------------
---------------------------------------------------------------
### DEMO


#### 0: Reset Cloud9 Instance environ from previous demo(s).
- Reset your region & AWS account variables in case you launched a new terminal session:
```
cd ~/environment/mglab-share-eks/demos/03/create-cluster-terraform/
export C9_REGION=$(curl --silent http://169.254.169.254/latest/dynamic/instance-identity/document |  grep region | awk -F '"' '{print$4}')
export C9_AWS_ACCT=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep accountId | awk -F '"' '{print$4}')
clear
echo $C9_REGION
echo $C9_AWS_ACCT
export KOPS_REGION=$C9_REGION  # change this if desired
```

#### 1: Install the kOps CLI onto the Cloud9 IDE instance.
- Install the 'kops' CLI onto Cloud9
  - [DOC LINK: kOps - Getting Started - Install](https://kops.sigs.k8s.io/getting_started/install/)
```
curl -Lo kops https://github.com/kubernetes/kops/releases/download/$(curl -s https://api.github.com/repos/kubernetes/kops/releases/latest | grep tag_name | cut -d '"' -f 4)/kops-linux-amd64
chmod +x kops
sudo mv kops /usr/local/bin/kops
```

#### 2: Show the `kops` version
- Display the version information for the `kops` install you just completed.
```
kops version
```

#### 3: Create an AWS IAM group and attach policies needed for kOps to create a cluster
- Create an AWS IAM group named "kops" for use with a kOps install.
  - [DOC LINK: kOps - Getting Started - Deploy to AWS](https://kops.sigs.k8s.io/getting_started/aws/)
```
aws iam create-group --group-name kops
```
- Attach policies to your "kops" group to grant permissions needed to create a Kubernetes cluster.
```
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonRoute53FullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/IAMFullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonVPCFullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonSQSFullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/AmazonEventBridgeFullAccess --group-name kops
aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/CloudFrontFullAccess --group-name kops
```

#### 4: Create an AWS IAM user, join them to the group, and create an access key
- Create an AWS IAM user.
```
aws iam create-user --user-name kops
```
- Add this "kops" user to the "kops" group.
```
aws iam add-user-to-group --user-name kops --group-name kops
```
- Create an access key for this user.
```
aws iam create-access-key --user-name kops
```

#### 5: Assign "kops" user access key into Cloud9 session
- Configure the new "kops" user access key into your environment.
```
# configure the aws client to use your new IAM user
aws configure           # Use your new access and secret key here, or assign AWS_PROFILE accordingly
# Because "aws configure" doesn't export these vars for kops to use, we export them now
export AWS_ACCESS_KEY_ID=$(aws configure get aws_access_key_id)
export AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key)
```
#### 6: Assign the cluster's DNS suffix
- Configure a DNS suffix for the cluster, using Gossip DNS rather than Route 53.
  - [DOC LINK: kOps - Gossip DNS](https://kops.sigs.k8s.io/gossip/)
```
KOPS_PREFIX="unique1"     # change this to be unique
KOPS_SUFFIX=".k8s.local"
KOPS_DNSNAME=${KOPS_PREFIX}${KOPS_SUFFIX}
KOPS_NAME=$(echo ${KOPS_PREFIX}${KOPS_SUFFIX} | sed 's/\./-/g')
```

#### 7: Create two Amazon S3 buckets for storing your Kubernetes cluster state and identity trust configuration
- Create an S3 bucket for your cluster state.
```
aws s3api create-bucket \
    --bucket ${KOPS_NAME}-state-store \
    --region $KOPS_REGION \
    --create-bucket-configuration LocationConstraint=$KOPS_REGION
```
- Enable versioning on the cluster configuration bucket.
```
aws s3api put-bucket-versioning --bucket ${KOPS_NAME}-state-store  --versioning-configuration Status=Enabled
```
- Enable bucket encryption.
```
aws s3api put-bucket-encryption --bucket ${KOPS_NAME}-state-store --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
```
- Create an S3 bucket for your OIDC identity trust information.
```
aws s3api create-bucket \
    --bucket ${KOPS_NAME}-oidc-store \
    --region $KOPS_REGION \
    --create-bucket-configuration LocationConstraint=$KOPS_REGION
```
- NOTE: cannot do public read - what permissions do we really need for STS here? --acl public-read was suggested in demo.
- Therefore:
- Create Amazon CloudFront distribution in front of S3 bucket.
```
OAI=$(aws cloudfront create-cloud-front-origin-access-identity \
    --cloud-front-origin-access-identity-config \
        CallerReference="kops-oidc-store-oai",Comment="kOps OIDC store OAI" \
    --query CloudFrontOriginAccessIdentity.Id \
    --output text)
cat <<EOF >kops-oidc-dist-config.json
{

    "CallerReference": "kops-oidc-dist",
    "Comment": "kOps OIDC store distribution",
    "Enabled": true,
    "Origins": {
        "Quantity": 1,
        "Items": [
            {
                "Id": "${KOPS_NAME}-oidc-store.s3.amazonaws.com-kops-oidc-dist",
                "DomainName": "${KOPS_NAME}-oidc-store.s3.amazonaws.com",
                "S3OriginConfig": {
                    "OriginAccessIdentity": "origin-access-identity/cloudfront/${OAI}"
                }
            }
        ]
    },
    "DefaultCacheBehavior": {
        "TargetOriginId": "${KOPS_NAME}-oidc-store.s3.amazonaws.com-kops-oidc-dist",
        "ForwardedValues": {
            "QueryString": false,
            "Cookies": {
                "Forward": "none"
            },
            "Headers": {
                "Quantity": 0
            },
            "QueryStringCacheKeys": {
                "Quantity": 0
            }
        },
        "TrustedSigners": {
            "Enabled": false,
            "Quantity": 0
        },
        "ViewerProtocolPolicy": "allow-all",
        "MinTTL": 0,
        "AllowedMethods": {
            "Quantity": 2,
            "Items": [
                "HEAD",
                "GET"
            ],
            "CachedMethods": {
                "Quantity": 2,
                "Items": [
                    "HEAD",
                    "GET"
                ]
            }
        },
        "SmoothStreaming": false,
        "DefaultTTL": 86400,
        "MaxTTL": 31536000,
        "Compress": false,
        "LambdaFunctionAssociations": {
            "Quantity": 0
        },
        "FieldLevelEncryptionId": ""
    }
}
EOF
OIDC_DIST=$(aws cloudfront create-distribution \
    --distribution-config file://kops-oidc-dist-config.json \
    --query Distribution.Id \
    --output text)
```
- Define permissions for CloudFront distribution identity (OAI) to access bucket.
```
cat <<EOF >kops-oidc-dist-policy.json
{
    "Version": "2012-10-17",
    "Id": "PolicyForCloudFrontPrivateContent",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity ${OAI}"
            },
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::${KOPS_NAME}-oidc-store/*"
        }
    ]
}
EOF
```
- Assign permissions to OIDC store bucket.
```
aws s3api put-bucket-policy --bucket ${KOPS_NAME}-oidc-store --policy file://kops-oidc-dist-policy.json
```
- Get domain name of OIDC distribution.
```
OIDC_DOMAIN=$(aws cloudfront get-distribution \
    --id $OIDC_DIST \
    --query Distribution.DomainName \
    --output text)
```
- Assign variables to be used to refer to state and oidc stores.
```
export KOPS_STATE_STORE=s3://${KOPS_NAME}-state-store
export KOPS_OIDC_STORE=s3://${KOPS_NAME}-oidc-store
export KOPS_OIDC_DIST=https://${OIDC_DOMAIN}
```

#### 8: Create a Kubernetes cluster using `kops create cluster`
- Select availability zones to use for the Kubernetes cluster.
```
KOPS_ZONES=$(aws ec2 describe-availability-zones --region $KOPS_REGION --query AvailabilityZones[].ZoneName --output text | tr '\t' ',')
```
- Create your Kubernetes cluster configuration using `kops create cluster`.
```
kops create cluster \
    --name=${KOPS_DNSNAME} \
    --cloud=aws \
    --zones=${KOPS_ZONES} \
    --discovery-store=${KOPS_OIDC_DIST}/${KOPS_DNSNAME}/discovery
```
- Customize cluster configuration.
```
kops edit cluster --name ${KOPS_DNSNAME}
```
- Build the cluster.
```
kops update cluster --name ${KOPS_DNSNAME} --yes
```


OLD...

#### 4: Generate a kubeconfig & Access the EKS Cluster with kubectl.
- Install kubectl & review your kubeconfig:
```
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
curl -LO "https://dl.k8s.io/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl.sha256"
echo "$(<kubectl.sha256) kubectl" | sha256sum --check
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```
- Confirm your current IAM user configured for use with the CLI:
```
export AWS_ACCESS_KEY_ID=$(cat ~/.aws/credentials | grep aws_access_key_id | awk '{print$3}')
export AWS_SECRET_ACCESS_KEY=$(cat ~/.aws/credentials | grep aws_secret_access_key | awk '{print$3}')
aws sts get-caller-identity
```
- Use aws cli to manually create/update a kubeconfig context to the cluster:
```
aws eks update-kubeconfig --name cluster-terraform --region $C9_REGION
kubectl config use-context arn:aws:eks:$C9_REGION:$C9_AWS_ACCT:cluster/cluster-terraform
kubectl config view --minify
```
- Confirm you now have access to run kubectl commands as well as eksctl commands:
```
kubectl get all -A
kubectl get nodes
```

#### 7: Test the Cluster Autoscaler.

- Confirm the Cluster Autoscaler is functional, use _ctrl-c_ to exit:
```
kubectl logs deployment.app/cluster-autoscaler-aws-cluster-autoscaler -f -n kube-system
```


#### 8: Deploy Wordpress app front end on Fargate & Mysql backend on managed Nodegroup.
- Deploy Wordpress front & back end workloads:
```
cat ../k8s/k8s-all-in-one-fargate.yaml  | sed "s/<REGION>/$C9_REGION/" | kubectl apply -f -
watch kubectl get pods -o wide -n wordpress-fargate
```
- Get all K8s nodes, you should see some additional `fargate` nodes:
```
kubectl get nodes -o wide
```
- Get the URL for our new app and test access in your browser:
```
echo "http://"$(kubectl get svc wordpress -n wordpress-fargate \
--output jsonpath='{.status.loadBalancer.ingress[0].hostname}')
```

---------------------------------------------------------------
---------------------------------------------------------------
### DEPENDENTS

- 04-CNCF*
- 05-CNCF*
- 06-CNCF*
- 07-CNCF*
- 08-CNCF*


---------------------------------------------------------------
---------------------------------------------------------------
### CLEANUP
- Do not cleanup if you plan to run any dependent demos
```
export C9_REGION=$(curl --silent http://169.254.169.254/latest/dynamic/instance-identity/document |  grep region | awk -F '"' '{print$4}')
export C9_AWS_ACCT=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep accountId | awk -F '"' '{print$4}')
export AWS_ACCESS_KEY_ID=$(cat ~/.aws/credentials | grep aws_access_key_id | awk '{print$3}')
export AWS_SECRET_ACCESS_KEY=$(cat ~/.aws/credentials | grep aws_secret_access_key | awk '{print$3}')
kubectl config use-context arn:aws:eks:$C9_REGION:$C9_AWS_ACCT:cluster/cluster-terraform
kubectl delete namespace wordpress-fargate --force
cd ~/environment/mglab-share-eks/demos/03/create-cluster-terraform/artifacts/terraform
terraform destroy -auto-approve
```
