#! /bin/bash
set -e

AZ_CID=$(oc get secrets/azure-credentials -n kube-system -o json | jq -r .data.azure_client_id | base64 -d)

AZ_CS=$(oc get secrets/azure-credentials -n kube-system -o json | jq -r .data.azure_client_secret | base64 -d)

AZ_TID=$(oc get secrets/azure-credentials -n kube-system -o json | jq -r .data.azure_tenant_id | base64 -d)

echo azure_client_id $AZ_CID
echo azure_client_secret $AZ_CS
echo azure_tenant_id $AZ_TID

az login --service-principal -u $AZ_CID -p $AZ_CS --tenant $AZ_TID

echo "Login succeeded!"

PODVM=$(az vm list -d --query "[].{Name:name}" -o table | grep podvm)

echo "podvm $PODVM"

ARO_RESOURCE_GROUP=$(oc get infrastructure/cluster -o jsonpath='{.status.platformStatus.azure.resourceGroupName}')

az vm delete --resource-group $ARO_RESOURCE_GROUP --name $PODVM --yes
