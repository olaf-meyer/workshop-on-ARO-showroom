#! /bin/bash
set -e

function wait_for_deployment() {
    local deployment=$1
    local namespace=$2
    local timeout=300
    local interval=25
    local elapsed=0
    local ready=0

    while [ $elapsed -lt $timeout ]; do
        ready=$(oc get deployment -n "$namespace" "$deployment" -o jsonpath='{.status.readyReplicas}')
        if [ "$ready" == "1" ]; then
            echo "Operator $deployment is ready"
            return 0
        fi
        sleep $interval
        elapsed=$((elapsed + interval))
    done
    echo "Operator $deployment is not ready after $timeout seconds"
    return 1
}

function wait_for_phase() {
    local dsc=$1
    local objtype=$2
    local status=$3
    local timeout=900
    local interval=5
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        sleep $interval
        elapsed=$((elapsed + interval))
        statusReady=$(oc get "$objtype" "$dsc" -o=jsonpath='{.status.conditions[?(@.type=="'$status'")].status}')
        if [ "$statusReady" == "True" ]; then
            echo "$objtype $dsc is $status"
            return 0
        fi
        echo "$objtype $dsc is not yet $status, waiting another $interval seconds"
    done

	echo "$objtype $dsc is not $status after $timeout seconds"
    return 1
}

oc apply -f-<<EOF
---
apiVersion: v1
kind: Namespace
metadata:
  name: openshift-serverless
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: serverless-operators
  namespace: openshift-serverless
spec: {}
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: serverless-operator
  namespace: openshift-serverless
spec:
  channel: stable
  name: serverless-operator
  installPlanApproval: Automatic
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

oc apply -f-<<EOF
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: servicemeshoperator
  namespace: openshift-operators
spec:
  channel: stable
  name: servicemeshoperator
  installPlanApproval: Automatic
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

oc apply -f-<<EOF
---
apiVersion: v1
kind: Namespace
metadata:
  name: redhat-ods-operator
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: rhods-operator
  namespace: redhat-ods-operator
spec: {}
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: rhods-operator
  namespace: redhat-ods-operator
spec:
  name: rhods-operator
  installPlanApproval: Automatic
  channel: stable
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

echo "############################ Wait for Serverless ########################"
wait_for_deployment knative-openshift openshift-serverless || exit 1

echo "############################ Wait for Service Mesh ########################"
wait_for_deployment istio-operator openshift-operators || exit 1

echo "############################ Wait for OAI ########################"
wait_for_phase default-dsci DSCInitialization Available || exit 1

oc apply -f-<<EOF
---
apiVersion: datasciencecluster.opendatahub.io/v1
kind: DataScienceCluster
metadata:
  name: rhods
  labels:
    app.kubernetes.io/name: datasciencecluster
    app.kubernetes.io/instance: rhods
    app.kubernetes.io/part-of: rhods-operator
    app.kubernetes.io/managed-by: kustomize
    app.kubernetes.io/created-by: rhods-operator
spec:
  components:
    codeflare:
      managementState: Managed
    dashboard:
      managementState: Managed
    datasciencepipelines:
      managementState: Managed
    kserve:
      managementState: Managed
      serving:
        managementState: Managed
        name: knative-serving
        ingressGateway:
          certificate:
            type: SelfSigned
    modelmeshserving:
      managementState: Managed
    ray:
      managementState: Managed
    trustyai:
      managementState: Managed
    workbenches:
      managementState: Managed
EOF

echo "############################ Wait for OAI DSC ########################"
wait_for_phase rhods DataScienceCluster Ready || exit 1


oc adm policy add-cluster-role-to-user cluster-admin admin
oc adm policy add-cluster-role-to-user cluster-admin "kube:admin"

oc apply -f-<<EOF
---
apiVersion: v1
kind: Namespace
metadata:
  name: coco-oai
  labels:
    opendatahub.io/dashboard: "true"
    modelmesh-enabled: "false"
spec:
  displayName: "Run CoCo on OAI"
  kserve:
    enabled: true
EOF

echo "################################################"
echo "Configuration complete. Enjoy testing CoCo on OAI!"
echo "################################################"