./minikube start --vm-driver hyperv --hyperv-virtual-switch hh


./minikube start --docker-env http_proxy=http://172.25.0.88:80 --docker-env https_proxy=http://172.25.0.88:80 --docker-env no_proxy=172.25.100.0/24

C:\Users\appeon\.minikube\cache\iso
https://storage.googleapis.com/minikube/iso/minikube-v1.24.0.iso

Linux:
https://storage.googleapis.com/kubernetes-release/release/v1.22.3/bin/linux/amd64/kubelet?checksum=file
https://storage.googleapis.com/kubernetes-release/release/v1.22.3/bin/linux/amd64/kubelet.sha256

https://storage.googleapis.com/kubernetes-release/release/v1.22.3/bin/linux/amd64/kubeadm?checksum=file
https://storage.googleapis.com/kubernetes-release/release/v1.22.3/bin/linux/amd64/kubeadm.sha256

https://storage.googleapis.com/kubernetes-release/release/v1.22.3/bin/linux/amd64/kubectl?checksum=file
https://storage.googleapis.com/kubernetes-release/release/v1.22.3/bin/linux/amd64/kubectl.sha256


windows:
https://storage.googleapis.com/kubernetes-release/release/v1.22.3/bin/windows/amd64/kubectl.exe?checksum=file:https://storage.googleapis.com/kubernetes-release/release/v1.22.3/bin/windows/amd64/kubectl.exe.sha256
https://storage.googleapis.com/kubernetes-release/release/v1.22.3/bin/windows/amd64/kubectl.exe?checksum=file:https://storage.googleapis.com/kubernetes-release/release/v1.22.3/bin/windows/amd64/kubectl.exe.sha256


set HTTP_PROXY=http://172.25.0.88:80
set HTTPS_PROXY=https://172.25.0.88:80
set NO_PROXY=localhost,127.0.0.1,10.96.0.0/12,192.168.59.0/24,192.168.39.0/24

