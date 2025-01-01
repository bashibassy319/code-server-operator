# code-server-operator
// TODO(user): Add simple overview of use/purpose

## Description
// TODO(user): An in-depth paragraph about your project and overview of use


- deployment port 8080
```
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    deployment.kubernetes.io/revision: "1"
    meta.helm.sh/release-name: code-server
    meta.helm.sh/release-namespace: code-server
  creationTimestamp: "2024-12-10T05:29:34Z"
  generation: 1
  labels:
    app.kubernetes.io/instance: code-server
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: code-server
    helm.sh/chart: code-server-3.24.0
  name: code-server
  namespace: code-server
  resourceVersion: "830761"
  uid: a0e7bebd-45c4-4a34-a29e-477250981927
spec:
  progressDeadlineSeconds: 600
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      app.kubernetes.io/instance: code-server
      app.kubernetes.io/name: code-server
  strategy:
    type: Recreate
  template:
    metadata:
      creationTimestamp: null
      labels:
        app.kubernetes.io/instance: code-server
        app.kubernetes.io/name: code-server
    spec:
      containers:
      - env:
        - name: PASSWORD
          valueFrom:
            secretKeyRef:
              key: password
              name: code-server
        image: codercom/code-server:4.93.1
        imagePullPolicy: Always
        livenessProbe:
          failureThreshold: 3
          httpGet:
            path: /
            port: http
            scheme: HTTP
          periodSeconds: 10
          successThreshold: 1
          timeoutSeconds: 1
        name: code-server
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
        readinessProbe:
          failureThreshold: 3
          httpGet:
            path: /
            port: http
            scheme: HTTP
          periodSeconds: 10
          successThreshold: 1
          timeoutSeconds: 1
        resources: {}
        securityContext:
          runAsUser: 1000
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
        volumeMounts:
        - mountPath: /home/coder
          name: data
      dnsPolicy: ClusterFirst
      initContainers:
      - command:
        - sh
        - -c
        - |
          chown -R 1000:1000 /home/coder
        image: busybox:latest
        imagePullPolicy: IfNotPresent
        name: init-chmod-data
        resources: {}
        securityContext:
          runAsUser: 0
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
        volumeMounts:
        - mountPath: /home/coder
          name: data
      restartPolicy: Always
      schedulerName: default-scheduler
      securityContext:
        fsGroup: 1000
      serviceAccount: code-server
      serviceAccountName: code-server
      terminationGracePeriodSeconds: 30
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: code-server
```

- service port 8080
```
apiVersion: v1
kind: Service
metadata:
  annotations:
    meta.helm.sh/release-name: code-server
    meta.helm.sh/release-namespace: code-server
  creationTimestamp: "2024-12-10T05:29:34Z"
  labels:
    app.kubernetes.io/instance: code-server
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: code-server
    helm.sh/chart: code-server-3.24.0
  name: code-server
  namespace: code-server
  resourceVersion: "559222"
  uid: 04bc18eb-a5b4-4a51-8a1d-96bdd00175e5
spec:
  clusterIP: 10.96.241.159
  clusterIPs:
  - 10.96.241.159
  internalTrafficPolicy: Cluster
  ipFamilies:
  - IPv4
  ipFamilyPolicy: SingleStack
  ports:
  - name: http
    port: 8080
    protocol: TCP
    targetPort: http
  selector:
    app.kubernetes.io/instance: code-server
    app.kubernetes.io/name: code-server
  sessionAffinity: None
  type: ClusterIP
status:
  loadBalancer: {}
```

- pvc
```
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  annotations:
    meta.helm.sh/release-name: code-server
    meta.helm.sh/release-namespace: code-server
    pv.kubernetes.io/bind-completed: "yes"
    pv.kubernetes.io/bound-by-controller: "yes"
    volume.beta.kubernetes.io/storage-provisioner: rancher.io/local-path
    volume.kubernetes.io/selected-node: kind-control-plane
    volume.kubernetes.io/storage-provisioner: rancher.io/local-path
  creationTimestamp: "2024-12-10T05:29:34Z"
  finalizers:
  - kubernetes.io/pvc-protection
  labels:
    app.kubernetes.io/instance: code-server
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: code-server
    helm.sh/chart: code-server-3.24.0
  name: code-server
  namespace: code-server
  resourceVersion: "559259"
  uid: 18d9b1c9-ba57-4b1f-bd06-f6b7e14646b2
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: standard
  volumeMode: Filesystem
  volumeName: pvc-18d9b1c9-ba57-4b1f-bd06-f6b7e14646b2
status:
  accessModes:
  - ReadWriteOnce
  capacity:
    storage: 10Gi
  phase: Bound
```

## Getting Started

### Prerequisites
- go version v1.22.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/code-server-operator:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/code-server-operator:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following are the steps to build the installer and distribute this project to users.

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/code-server-operator:tag
```

NOTE: The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without
its dependencies.

2. Using the installer

Users can just run kubectl apply -f <URL for YAML BUNDLE> to install the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/code-server-operator/<tag or branch>/dist/install.yaml
```

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

