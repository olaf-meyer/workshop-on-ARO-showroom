#! /bin/bash

AZ_CID=$(oc get secrets/azure-credentials -n kube-system -o json | jq .data.azure_client_id)

AZ_CS=$(oc get secrets/azure-credentials -n kube-system -o json | jq .data.azure_client_secret)

AZ_TID=$(oc get secrets/azure-credentials -n kube-system -o json | jq .data.azure_tenant_id)

az login --service-principal -u $AZ_CID -p $AZ_CS --tenant $AZ_TID


PODVM=$(az vm list -d --query "[].{Name:name}" -o table | grep podvm)

ARO_RESOURCE_GROUP=$(oc get infrastructure/cluster -o jsonpath='{.status.platformStatus.azure.resourceGroupName}')

az vm delete --resource-group $ARO_RESOURCE_GROUP --name $PODVM
