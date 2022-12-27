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
cd ~/environment/mglab-share-eks/demos/03/create-cluster-kops/
export C9_REGION=$(curl --silent http://169.254.169.254/latest/dynamic/instance-identity/document |  grep region | awk -F '"' '{print$4}')
export C9_AWS_ACCT=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep accountId | awk -F '"' '{print$4}')
clear
echo $C9_REGION
echo $C9_AWS_ACCT
export KOPS_REGION=$C9_REGION  # change this if desired
export KOPS_ACCOUNT=$C9_AWS_ACCT  # change this if desired
export KOPS_STATE_ACCOUNT=$KOPS_ACCOUNT # change this to use alternative account for State+OIDC stores.
export KOPS_STATE_ROLE="" # change this to use alternative account for State+OIDC stores.
```
- To use cross-account buckets for the state store and OIDC store, define appropriate values for the that account and role.
- as noted above: "change this to use alternative account for State+OIDC stores."
- e.g. 
  - export KOPS_STATE_ACCOUNT="639366692623" 
  - export KOPS_STATE_ROLE="ExtAccountRole" 

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
kopsAccessKey=$(aws iam create-access-key --user-name kops)
```

#### 5: Assign "kops" user access key into Cloud9 session
- Configure the new "kops" user access key into your environment.
```
# aws configure           # Use your new access and secret key here, or assign AWS_PROFILE accordingly
aws configure set aws_access_key_id $(echo $kopsAccessKey | jq .AccessKey.AccessKeyId) --profile kops
aws configure set aws_secret_access_key $(echo $kopsAccessKey | jq .AccessKey.SecretAccessKey) --profile kops
aws configure set region $KOPS_REGION --profile kops
# LATER, use: export AWS_PROFILE=kops
# configure the aws client to use your new IAM user
# Because "aws configure" doesn't export these vars for kops to use, we export them now
export AWS_ACCESS_KEY_ID=$(aws configure get aws_access_key_id --profile kops)
export AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key --profile kops)
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
#### 7: Switch to an AWS account which can create public S3 buckets.
- Assume a role in another AWS account.
```
if [ "$KOPS_STATE_ROLE" ]
then
  rolearn="arn:aws:iam::${KOPS_STATE_ACCOUNT}:role/${KOPS_STATE_ROLE}"
  rolesession="kopsbucket"
  role=$(aws sts assume-role --role-arn "$rolearn" --role-session-name "$rolesession")
  echo "export AWS_ACCESS_KEY_ID=$(echo $role | jq -r '.Credentials.AccessKeyId')"
  echo "export AWS_SECRET_ACCESS_KEY=$(echo $role | jq -r '.Credentials.SecretAccessKey')"
  echo "export AWS_SESSION_TOKEN=$(echo $role | jq -r '.Credentials.SessionToken')"
  aws sts get-caller-identity
fi
```
#### 8: Create two Amazon S3 buckets for storing your Kubernetes cluster state and identity trust configuration
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
- Define permissions for cross-account access to state bucket.
```
cat <<EOF >kops-state-store-policy.json
{
    "Version": "2012-10-17",
    "Id": "PolicyForCrossAccountAccess",
    "Statement": [
        {
           "Sid": "Cross-account-permissions",
           "Effect": "Allow",
           "Principal": {
              "AWS": [
                  "arn:aws:iam::${KOPS_ACCOUNT}:root",
                  "arn:aws:iam::${KOPS_ACCOUNT}:user/kops",
                  "arn:aws:iam::${KOPS_ACCOUNT}:user/brad",
                  "arn:aws:iam::${KOPS_ACCOUNT}:user/bwer"
               ]
           },
           "Action": [
              "s3:*"
           ],
           "Resource": [
              "arn:aws:s3:::${KOPS_NAME}-state-store/*",
              "arn:aws:s3:::${KOPS_NAME}-state-store"
           ]
        }
    ]
}
EOF
```
- Assign permissions to OIDC store bucket.
```
aws s3api put-bucket-policy --bucket ${KOPS_NAME}-state-store --policy file://kops-state-store-policy.json
```
- Create an S3 bucket for your OIDC identity trust information.
```
aws s3api create-bucket \
    --bucket ${KOPS_NAME}-oidc-store \
    --region $KOPS_REGION \
    --create-bucket-configuration LocationConstraint=$KOPS_REGION \
    --acl public-read
```
- NOTE: some accounts cannot do public read 
- what permissions do we really need for STS here? 
- --acl public-read was suggested in demo.
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
        },
        {
           "Sid": "Cross-account-permissions",
           "Effect": "Allow",
           "Principal": {
              "AWS": [
                  "arn:aws:iam::${KOPS_ACCOUNT}:root",
                  "arn:aws:iam::${KOPS_ACCOUNT}:user/kops",
                  "arn:aws:iam::${KOPS_ACCOUNT}:user/brad",
                  "arn:aws:iam::${KOPS_ACCOUNT}:user/bwer"
               ]
           },
           "Action": [
              "s3:*"
           ],
           "Resource": [
              "arn:aws:s3:::${KOPS_NAME}-oidc-store",
              "arn:aws:s3:::${KOPS_NAME}-oidc-store/*"
           ]
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
#### 9: Switch back to original KOPS account.
- Switch from S3 account back to KOPS account.
```
echo "unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN"
```
- Confirm cross-account access to state and oidc stores.
```
aws s3 ls $KOPS_STATE_STORE
aws s3 ls $KOPS_OIDC_STORE
```
#### 10: Create a Kubernetes cluster using `kops create cluster`
- Select availability zones to use for the Kubernetes cluster.
```
KOPS_ZONES=$(aws ec2 describe-availability-zones --region $KOPS_REGION --query AvailabilityZones[].ZoneName --output text | tr '\t' ',')
```
- Set flexible cross-account S3 bucket default ACLs.
- The kops quickstart guide suggests this:
  - kOps will be able to use buckets configured with cross-account policies by default.
  - In this case you may want to override the object ACLs which kOps places on the state files, as default AWS ACLs will make it possible for an account that has delegated access to write files that the bucket owner cannot read.
  - To do this you should set the environment variable KOPS_STATE_S3_ACL to the preferred object ACL, for example: bucket-owner-full-control.
```
export KOPS_STATE_S3_ACL=bucket-owner-full-control
```
- Create your Kubernetes cluster configuration using `kops create cluster`.
- Be sure to use either KOPS_OIDC_STORE for S3 when allowed,
- or KOPS_OIDC_DIST if using CloudFront is possible.
```
kops create cluster \
    --name=${KOPS_DNSNAME} \
    --cloud=aws \
    --zones=${KOPS_ZONES} \
    --discovery-store=${KOPS_OIDC_STORE}/${KOPS_DNSNAME}/discovery \
    >./kops-cluster-info-$(date +%Y%m%d%H%M%S).txt
```
- Look at YAML representation of cluster configuration.
```
kops get cluster --name $KOPS_DNSNAME -o yaml \
    >./kops-cluster-$(date +%Y%m%d%H%M%S).yaml
```
- Customize cluster configuration.
```
kops edit cluster --name ${KOPS_DNSNAME}
```
- Build the cluster.
```
kops update cluster --name ${KOPS_DNSNAME} --yes
```
#### 11: Test cluster access
- Use admin mode for authentication.
```
kops export kubecfg --admin
```
- Show the condensed version of the ~/.kube/config
```
kubectl config view --minify
```
- Confirm you now have access to run kubectl commands as well as eksctl commands:
```
kubectl get nodes
kubectl get all -A
kops validate cluster --wait 10m
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
cd ~/environment/mglab-share-eks/demos/03/create-cluster-kops/
kops delete cluster --name $KOPS_DNSNAME --yes
```
