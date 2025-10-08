#! /bin/bash

NODE_NAME=$(oc get nodes -l node-role.kubernetes.io/kata-oc -o jsonpath='{.items[0].metadata.name}')

if ! oc get node "$NODE_NAME" &> /dev/null; then
    echo -e "ERROR: No node labeled kata-oc found in the cluster." >&2
    exit 1
fi

TEMP_PATH_IN_POD="/host/tmp/$FILENAME"
wget https://people.redhat.com/eesposit/kata-containers-3.17.0-3.rhaos4.16.el9.x86_64.rpm
FILE_TO_COPY=kata-containers-3.17.0-3.rhaos4.16.el9.x86_64.rpm

echo "###### Start debug pod ######"
oc debug node/"$NODE_NAME" -- sleep infinity &> /dev/null &

DEBUG_POD_NAME=""
TIMEOUT=60 # seconds
ELAPSED=0
INTERVAL=2

while [[ -z "$DEBUG_POD_NAME" && $ELAPSED -lt $TIMEOUT ]]; do
    DEBUG_POD_NAME=$(oc get pods --all-namespaces --field-selector spec.nodeName="$NODE_NAME" --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}' 2>/dev/null || true)
    [[ -z "$DEBUG_POD_NAME" ]] && sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))
done

if [[ -z "$DEBUG_POD_NAME" ]]; then
    echo -e "ERROR: Timed out waiting for debug pod to be created on node '$NODE_NAME'." >&2
    exit 1
fi

DEBUG_POD_NAMESPACE=$(oc get pods --all-namespaces --field-selector metadata.name="$DEBUG_POD_NAME" -o jsonpath='{.items[0].metadata.namespace}')
echo "###### Found debug pod: $DEBUG_POD_NAME in namespace $DEBUG_POD_NAMESPACE ######"

echo "###### Waiting for pod to be ready... ######"
if ! oc wait --for=condition=Ready "pod/$DEBUG_POD_NAME" -n "$DEBUG_POD_NAMESPACE" --timeout=120s; then
    echo -e "ERROR: Timed out waiting for pod '$DEBUG_POD_NAME' to become ready." >&2
    oc logs "pod/$DEBUG_POD_NAME" -n "$DEBUG_POD_NAMESPACE" >&2
    exit 1
fi
echo "###### Pod is running and ready ######"


echo "###### Copying rpm in debug pod ######"
oc cp "$FILE_TO_COPY" "${DEBUG_POD_NAMESPACE}/${DEBUG_POD_NAME}:${TEMP_PATH_IN_POD}"

echo "###### Installing the rpm... ######"
oc exec "$DEBUG_POD_NAME" -n "$DEBUG_POD_NAMESPACE" -- chroot /host mount -o remount,rw /usr
oc exec "$DEBUG_POD_NAME" -n "$DEBUG_POD_NAMESPACE" -- chroot /host rpm -Uvh "/tmp/$FILE_TO_COPY"
echo "###### Install succesful ######"

oc delete pod "$DEBUG_POD_NAME" -n "$DEBUG_POD_NAMESPACE" --ignore-not-found=true
rm -f $FILE_TO_COPY

echo "###### Completed! ######"