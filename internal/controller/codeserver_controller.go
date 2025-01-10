/*
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
*/

package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	appsv1 "k8s.io/api/apps/v1"

	codev1 "github.com/bashibassy319/code-server-operator/api/v1"
)

// CodeServerReconciler reconciles a CodeServer object
type CodeServerReconciler struct {
	client.Client
	Scheme  *runtime.Scheme
	recoder record.EventRecorder
}

const pvcNamePrefix = "codeserver-data-pvc-"
const deploymentNamePrefix = "codeserver-deployment-"
const svcNamePrefix = "codeserver-service-"
const secretNamePrefix = "codeserver-secret-"

// +kubebuilder:rbac:groups=code.code-server.io,resources=codeservers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=code.code-server.io,resources=codeservers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=code.code-server.io,resources=codeservers/finalizers,verbs=update
// +kubebuilder:rbac:groups=code.code-server.io,resources=codeservers/events,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the CodeServer object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.1/pkg/reconcile
func (r *CodeServerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// your logic here
	codeserver := &codev1.CodeServer{}
	if err := r.Get(ctx, req.NamespacedName, codeserver); err != nil {
		log.Error(err, "unable to fetch CodeServer")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	pvcReady := false
	deploymentReady := false
	serviceReady := false
	secretReady := false
	log.Info("Reconciling CodeServer", "namespace", codeserver.ObjectMeta.Namespace, "name", codeserver.ObjectMeta.Name)

	if err := r.addOrUpdateSecret(ctx, codeserver); err != nil {
		log.Error(err, "Failed to create Secret")
		addCodition(&codeserver.Status, "SecretNotReady", metav1.ConditionFalse, "SecretNotReady", "Failed to create Secret")
		return ctrl.Result{}, err
	} else {
		secretReady = true
		addCodition(&codeserver.Status, "SecretReady", metav1.ConditionTrue, "SecretReady", "Secret created successfully")
	}

	if err := r.createPVCIfNotExists(ctx, codeserver); err != nil {
		log.Error(err, "Failed to create PVC")
		addCodition(&codeserver.Status, "PVCNotReady", metav1.ConditionFalse, "PVCNotReady", "Failed to create PVC")
		return ctrl.Result{}, err
	} else {
		pvcReady = true
		addCodition(&codeserver.Status, "PVCReady", metav1.ConditionTrue, "PVCReady", "PVC created successfully")
	}

	if err := r.addOrUpdateDeployment(ctx, codeserver); err != nil {
		log.Error(err, "Failed to create Deployment")
		addCodition(&codeserver.Status, "DeploymentNotReady", metav1.ConditionFalse, "DeploymentNotReady", "Failed to create Deployment")
		return ctrl.Result{}, err
	} else {
		deploymentReady = true
		addCodition(&codeserver.Status, "DeploymentReady", metav1.ConditionTrue, "DeploymentReady", "Deployment created successfully")
	}

	if err := r.addOrUpdateService(ctx, codeserver); err != nil {
		log.Error(err, "Failed to create Service")
		addCodition(&codeserver.Status, "ServiceNotReady", metav1.ConditionFalse, "ServiceNotReady", "Failed to create Service")

		return ctrl.Result{}, err
	} else {
		serviceReady = true
		addCodition(&codeserver.Status, "ServiceReady", metav1.ConditionTrue, "ServiceReady", "Service created successfully")
		if err := r.updateStatus(ctx, codeserver); err != nil {
			log.Error(err, "Failed to update status")
			return ctrl.Result{}, err
		}
	}

	if pvcReady && deploymentReady && serviceReady && secretReady {
		addCodition(&codeserver.Status, "ReconciliationSuccess", metav1.ConditionTrue, "ReconciliationSuccess", "Reconciliation completed successfully")
	}
	log.Info("Reconciliation completed", "namespace", codeserver.ObjectMeta.Namespace, "name", codeserver.ObjectMeta.Name)
	if err := r.updateStatus(ctx, codeserver); err != nil {
		log.Error(err, "Failed to update status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CodeServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recoder = mgr.GetEventRecorderFor("codeserver-controller")
	return ctrl.NewControllerManagedBy(mgr).
		For(&codev1.CodeServer{}).
		Named("codeserver").
		Complete(r)
}

func (r *CodeServerReconciler) createPVCIfNotExists(ctx context.Context, codeserver *codev1.CodeServer) error {
	log := log.FromContext(ctx)

	pvc := &corev1.PersistentVolumeClaim{}
	namespace := codeserver.ObjectMeta.Namespace
	pvcName := pvcNamePrefix + codeserver.ObjectMeta.Name
	err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: pvcName}, pvc)
	if err == nil {
		// PVC exists
		log.Info("PVC already exists", "namespace", namespace, "name", pvcName)
		return nil
	}

	// PVC does not exist
	log.Info("Creating PVC", "namespace", namespace, "name", pvcName)
	desiredPVC := generateDesiredPVC(codeserver, pvcName)
	if err := controllerutil.SetControllerReference(codeserver, desiredPVC, r.Scheme); err != nil {
		return err
	}

	if err := r.Create(ctx, desiredPVC); err != nil {
		return err
	}

	r.recoder.Event(codeserver, corev1.EventTypeNormal, "PVCReady", "Created PVC successfully")
	log.Info("PVC created successfully", "namespace", namespace, "name", pvcName)

	return nil
}

func generateDesiredPVC(codeserver *codev1.CodeServer, pvcName string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pvcName,
			Namespace: codeserver.ObjectMeta.Namespace,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("10Gi"),
				},
			},
		},
	}
}

func (r *CodeServerReconciler) addOrUpdateDeployment(ctx context.Context, codeserver *codev1.CodeServer) error {
	log := log.FromContext(ctx)

	deploymentList := &appsv1.DeploymentList{}
	labelSelector := labels.Set{"app": "codeserver-" + codeserver.ObjectMeta.Namespace}

	err := r.List(ctx, deploymentList, &client.ListOptions{
		Namespace:     codeserver.ObjectMeta.Namespace,
		LabelSelector: labelSelector.AsSelector(),
	})

	if err != nil {
		return err
	}

	if len(deploymentList.Items) > 0 {
		// Deployment already exists, update it
		existingDeployment := &deploymentList.Items[0]
		desiredDeployment := generateDesiredDeployment(codeserver)
		log.Info("Deployment already exists", "namespace", codeserver.ObjectMeta.Namespace, "name", existingDeployment.Name)

		if existingDeployment.Spec.Template.Spec.Containers[0].Image != desiredDeployment.Spec.Template.Spec.Containers[0].Image {
			log.Info("Updating Deployment", "namespace", codeserver.ObjectMeta.Namespace, "name", existingDeployment.Name)
			existingDeployment.Spec = desiredDeployment.Spec
			if err := r.Update(ctx, existingDeployment); err != nil {
				return err
			}
			r.recoder.Event(codeserver, corev1.EventTypeNormal, "DeploymentUpdated", "Updated Deployment successfully")
			log.Info("Deployment updated successfully", "namespace", codeserver.ObjectMeta.Namespace, "name", existingDeployment.Name)
		} else {
			log.Info("Deployment is up to date", "namespace", codeserver.ObjectMeta.Namespace, "name", existingDeployment.Name)
		}
		return nil
	}

	// Deployment does not exist, create it
	desiredDeployment := generateDesiredDeployment(codeserver)
	if err := controllerutil.SetControllerReference(codeserver, desiredDeployment, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, desiredDeployment); err != nil {
		return err
	}
	r.recoder.Event(codeserver, corev1.EventTypeNormal, "DeploymentCreated", "Deployment created successfully")
	log.Info("Deployment created", "team", codeserver.ObjectMeta.Namespace)
	return nil
}

func generateDesiredDeployment(codeserver *codev1.CodeServer) *appsv1.Deployment {
	replicas := int32(1)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: deploymentNamePrefix,
			Namespace:    codeserver.ObjectMeta.Namespace,
			Labels: map[string]string{
				"app": "codeserver-" + codeserver.ObjectMeta.Namespace,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "codeserver-" + codeserver.ObjectMeta.Namespace,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "codeserver-" + codeserver.ObjectMeta.Namespace,
					},
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:  "init-chmod-data",
							Image: "busybox:latest",
							Command: []string{
								"sh",
								"-c",
								"chown -R 1000:1000 /home/coder",
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "codeserver-data",
									MountPath: "/home/coder",
								},
							},
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:  &[]int64{0}[0],
								RunAsGroup: &[]int64{0}[0],
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "codeserver",
							Image: "codercom/code-server:" + codeserver.Spec.ImageTag,
							Env: []corev1.EnvVar{
								{
									Name: "PASSWORD",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											Key: "password",
											LocalObjectReference: corev1.LocalObjectReference{
												Name: secretNamePrefix + codeserver.ObjectMeta.Name,
											},
										},
									},
								},
							},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 8080,
								},
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/",
										Port: intstr.FromInt(8080),
									},
								},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/",
										Port: intstr.FromInt(8080),
									},
								},
							},
							SecurityContext: &corev1.SecurityContext{
								RunAsUser: &[]int64{1000}[0],
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "codeserver-data",
									MountPath: "/home/coder",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "codeserver-data",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: pvcNamePrefix + codeserver.ObjectMeta.Name,
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *CodeServerReconciler) addOrUpdateService(ctx context.Context, codeserver *codev1.CodeServer) error {
	log := log.FromContext(ctx)

	service := &corev1.Service{}
	err := r.Get(ctx, client.ObjectKey{Namespace: codeserver.ObjectMeta.Namespace, Name: svcNamePrefix + codeserver.ObjectMeta.Namespace}, service)
	if err != nil && client.IgnoreNotFound(err) != nil {
		return err
	}

	if err == nil {
		// Service already exists
		return nil
	}

	// Service does not exist, create it
	log.Info("Creating Service", "namespace", codeserver.ObjectMeta.Namespace, "name", svcNamePrefix+codeserver.ObjectMeta.Namespace)
	desiredService := generateDesiredService(codeserver)
	if err := controllerutil.SetControllerReference(codeserver, desiredService, r.Scheme); err != nil {
		return err
	}

	if err := r.Create(ctx, desiredService); err != nil {
		return err
	}

	r.recoder.Event(codeserver, corev1.EventTypeNormal, "ServiceCreated", "Created Service successfully")
	log.Info("Service created successfully", "namespace", codeserver.ObjectMeta.Namespace, "name", svcNamePrefix+codeserver.ObjectMeta.Namespace)

	return nil

}

func generateDesiredService(codeserver *codev1.CodeServer) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcNamePrefix + codeserver.ObjectMeta.Namespace,
			Namespace: codeserver.ObjectMeta.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "codeserver-" + codeserver.ObjectMeta.Namespace,
			},
			Ports: []corev1.ServicePort{
				{
					Port:       8080,
					TargetPort: intstr.FromInt(8080),
				},
			},
		},
	}
}

// reconcileSecret reconciles the secret for the password
func (r *CodeServerReconciler) addOrUpdateSecret(ctx context.Context, codeserver *codev1.CodeServer) error {
	log := log.FromContext(ctx)

	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Namespace: codeserver.ObjectMeta.Namespace, Name: secretNamePrefix + codeserver.ObjectMeta.Name}, secret)
	if err != nil && client.IgnoreNotFound(err) != nil {
		return err
	}

	if err == nil {
		// Secret already exists
		return nil
	}

	// Secret does not exist, create it
	log.Info("Creating Secret", "namespace", codeserver.ObjectMeta.Namespace, "name", secretNamePrefix+codeserver.ObjectMeta.Name)
	desiredSecret := generateDesiredSecret(codeserver)
	if err := controllerutil.SetControllerReference(codeserver, desiredSecret, r.Scheme); err != nil {
		return err
	}

	if err := r.Create(ctx, desiredSecret); err != nil {
		return err
	}

	r.recoder.Event(codeserver, corev1.EventTypeNormal, "SecretCreated", "Created Secret successfully")
	log.Info("Secret created successfully", "namespace", codeserver.ObjectMeta.Namespace, "name", secretNamePrefix+codeserver.ObjectMeta.Name)

	return nil
}

// Generate Secret for password
func generateDesiredSecret(codeserver *codev1.CodeServer) *corev1.Secret {
	password := ""
	if codeserver.Spec.Password == "" {
		password = generateRandomPassword()
	} else {
		password = codeserver.Spec.Password
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretNamePrefix + codeserver.ObjectMeta.Name,
			Namespace: codeserver.ObjectMeta.Namespace,
		},
		StringData: map[string]string{
			"password": password,
		},
	}
}

func generateRandomPassword() string {
	randBytes := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, randBytes)
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.WithPadding(base64.NoPadding).EncodeToString(randBytes)
}

func addCodition(status *codev1.CodeServerStatus, conditionType string, statusType metav1.ConditionStatus, reason, message string) {
	for i, existingCondition := range status.Conditions {
		if existingCondition.Type == conditionType {
			status.Conditions[i].Status = statusType
			status.Conditions[i].Reason = reason
			status.Conditions[i].Message = message
			status.Conditions[i].LastTransitionTime = metav1.Now()
			return
		}
	}

	condition := metav1.Condition{
		Type:               conditionType,
		Status:             statusType,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	}
	status.Conditions = append(status.Conditions, condition)
}

func (r *CodeServerReconciler) updateStatus(ctx context.Context, codeserver *codev1.CodeServer) error {
	log := log.FromContext(ctx)
	log.Info("Updating status", "namespace", codeserver.ObjectMeta.Namespace, "name", codeserver.ObjectMeta.Name)

	if err := r.Status().Update(ctx, codeserver); err != nil {
		log.Error(err, "Failed to update status")
		return err
	}

	log.Info("Status updated successfully", "namespace", codeserver.ObjectMeta.Namespace, "name", codeserver.ObjectMeta.Name)
	return nil
}
