## k8s-prometheus-and-grafana

#### GIVEN:
  - A developer desktop with docker & git installed (AWS Cloud9)
  - An EKS cluster created via eksctl from demo 03/create-cluster-eksctl-existing-vpc-advanced


#### WHEN:
  - I create an Amazon Managed Prometheus (AMP) Workspace in us-east-1
  - I deploy CNCF Grafana using a helm chart
  - I deploy Prometheus on my ECS cluster to send metrics to AMP Workspace
  - I create a Grafana dashboard on my AMG Workspace

#### THEN:
  - I will be able to visualize my EKS cluster in Grafana using CNCF Tools

#### SO THAT:
  - I can see how to use EKS with CNCF observability tooling

#### [Return to Main Readme](https://github.com/bwer432/mglab-share-eks#demos)

---------------------------------------------------------------
---------------------------------------------------------------
### REQUIRES
- 00-setup-cloud9
- 03/create-cluster-eksctl-existing-vpc-advanced

---------------------------------------------------------------
---------------------------------------------------------------
### DEMO

#### 0: Reset Cloud9 Instance environ from previous demo(s).
- Reset your region & AWS account variables in case you launched a new terminal session:
```
cd ~/environment/mglab-share-eks/demos/05/k8s-prometheus-and-grafana/
export C9_REGION=$(curl --silent http://169.254.169.254/latest/dynamic/instance-identity/document |  grep region | awk -F '"' '{print$4}')
export C9_AWS_ACCT=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep accountId | awk -F '"' '{print$4}')
export AWS_ACCESS_KEY_ID=$(cat ~/.aws/credentials | grep aws_access_key_id | awk '{print$3}')
export AWS_SECRET_ACCESS_KEY=$(cat ~/.aws/credentials | grep aws_secret_access_key | awk '{print$3}')
clear
echo $C9_REGION
echo $C9_AWS_ACCT
```

#### 1: Create AWS AMP Workspace.
- Update our kubeconfig to interact with the cluster created in 04-create-advanced-cluster-eksctl-existing-vpc.
```
eksctl utils write-kubeconfig --cluster cluster-eksctl --region $C9_REGION --authenticator-role-arn arn:aws:iam::${C9_AWS_ACCT}:role/cluster-eksctl-creator-role
kubectl config view --minify | grep 'cluster-name' -A 1
kubectl get ns
```
- Create AMP Workspace:
```
aws amp create-workspace --region us-east-1 --alias demo-amp-eks
```
- Setup IAM Pre-Reqs, execute the provided bash script to setup an IAM role for Prometheus (running in our K8s cluster) to forward to AMP:
  - Creates an IAM role with an IAM policy that has permissions to remote-write into an AMP workspace.  Our K8s serviceaccount will 'assume' this role.
```
./artifacts/setup-amp.sh cluster-eksctl
```

#### 2: Install the helm cli to help install the Prometheus Forwarder.
- Install helm v3:
```
curl https://raw.githubusercontent.com/kubernetes/helm/master/scripts/get-helm-3 > get_helm.sh
chmod 700 get_helm.sh
./get_helm.sh
```

#### 3: Install/Update Prometheus Forwarder to 'Remote Write' to the AWS AMP Workspace.
- Use helm to update/install Prometheus
```
export AMP_WSID=$(aws amp list-workspaces --region us-east-1 | jq '.workspaces[] | select (.alias=="demo-amp-eks") | .workspaceId' | tr -d '"')
echo $AMP_WSID
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
if [ "$(helm ls -n prometheus | grep prometheus | awk  '{print$1}')" == "prometheus" ]; then kubectl delete ns prometheus --force; fi
kubectl create ns prometheus
helm install prometheus prometheus-community/prometheus \
     --namespace prometheus \
     -f ./artifacts/prometheus-helm-config.yaml \
     --set serviceAccounts.server.annotations."eks\.amazonaws\.com/role-arn"="arn:aws:iam::$C9_AWS_ACCT:role/EKS-AMP-ServiceAccount-Role" \
     --set serviceAccounts.server.name="iamproxy-service-account" \
     --set server.remoteWrite[0].url="https://aps-workspaces.us-east-1.amazonaws.com/workspaces/$AMP_WSID/api/v1/remote_write" \
     --set server.remoteWrite[0].sigv4.region=us-east-1 \
     --set server.service.type="LoadBalancer" \
     --set server.resources.limits.cpu="1000m" \
     --set server.resources.limits.memory="1024Mi"
```

#### 4: Install & Setup CNCF Grafana
- Use helm to update/install Grafana:
```
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
if [ "$(helm ls -n grafana | grep grafana | awk  '{print$1}')" == "grafana" ]; then kubectl delete ns grafana --force; fi
kubectl create ns grafana
helm install grafana grafana/grafana \
     --namespace grafana \
     --set service.type=LoadBalancer \
     --set serviceAccount.name="iamproxy-service-account" \
     --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"="arn:aws:iam::$C9_AWS_ACCT:role/EKS-AMP-ServiceAccount-Role" \
     --set "grafana\.ini".auth.sigv4_auth_enabled=true
```
- Get the Grafana admin password:
```
kubectl get secret --namespace grafana grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo
```
- Get the Grafana LB:
```
echo "http://"$(kubectl get svc grafana -n grafana \
--output jsonpath='{.status.loadBalancer.ingress[0].hostname}')
```
- Open the Grafana web UI, using the credentials you just fetched along with username=admin:
  - Add a Prometheus DataSource in Grafana Console
    - Set Sig4 Auth=enabled
    - Set Default Region=us-east-1
    - Set HTTP URL to the value of the following command:
      ```
      echo "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/$AMP_WSID"
      ```
    - Import Dashboard `6417`

---------------------------------------------------------------
---------------------------------------------------------------
### DEPENDENTS

---------------------------------------------------------------
---------------------------------------------------------------
### CLEANUP
- Do not cleanup if you plan to run any dependent demos
```
export AMP_WSID=$(aws amp list-workspaces --region us-east-1 | jq '.workspaces[] | select (.alias=="demo-amp-eks") | .workspaceId' | tr -d '"')
echo $AMP_WSID
aws amp delete-workspace --region us-east-1 --workspace-id $AMP_WSID
export C9_AWS_ACCT=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep accountId | awk -F '"' '{print$4}')
echo $C9_AWS_ACCT
aws iam detach-role-policy --policy-arn arn:aws:iam::$C9_AWS_ACCT:policy/AWSManagedPrometheusWriteAccessPolicy --role-name EKS-AMP-ServiceAccount-Role
aws iam delete-role --role-name EKS-AMP-ServiceAccount-Role
export C9_REGION=$(curl --silent http://169.254.169.254/latest/dynamic/instance-identity/document |  grep region | awk -F '"' '{print$4}')
echo $C9_REGION
eksctl utils write-kubeconfig --cluster cluster-eksctl --region $C9_REGION --authenticator-role-arn arn:aws:iam::${C9_AWS_ACCT}:role/cluster-eksctl-creator-role
kubectl delete ns prometheus
kubectl delete ns grafana
```
