# tproxy-pod

Install a transparent server that is able to respond to http traffic sent to the Pods in an specific port

The Tranparent proxy kernel feature allows to intercept traffic and redirect it to a specific socket.

This socket has to use the IP_TRANSPARENT feature that allows it to bind to non existing IPs.


## Demo

1. Install a kubernetes cluster, in this case we are using kind

```sh
kind create cluster
```

2. Install the tproxy-pod using the manifest in this repo

```sh
kubectl apply -f install.yaml
```

The manifest will install the tproxy-pods as a daemonset with enough network privilages
to create a socket with IP_TRANSPARENT and install the corresponding iptables and ip route
rules.

3. Install a pod with a webserver

```
kubectl run test --image httpd:2
```

4. Install a route from the host to the pod to simulate an external client trying to access the pod

```
kubectl get pods -o wide 
NAME   READY   STATUS    RESTARTS   AGE   IP           NODE                 NOMINATED NODE   READINESS GATES
test   1/1     Running   0          45m   10.244.0.5   kind-control-plane   <none>           <none>
```

```
sudo ip route add 10.244.0.0/24 via 192.168.8.2
```

5. Check that we can reach the pod server from outside

```
curl 10.244.0.5
<html><body><h1>It works!</h1></body></html>
```

6. Check that the tproxy-pod interceps the request to the captured port (hardcoded in the iptables rules in this example)

```
curl 10.244.0.5:8180
Request received from 10.244.0.5:8180 destination / : &{GET / HTTP/1.1 1 1 map[Accept:[*/*] User-Agent:[curl/7.88.1]] {} <nil> 0 [] false 10.244.0.5:8180 map[] map[] <nil> map[] 192.168.8.1:54998 / <nil> <nil> <nil> 0xc000228320}
```

We can also verify in the pod logs that we actually captured the request
```
kubectl -n kube-system logs tproxypod-kksrr
2023/08/21 22:59:15 error trying to do AnyIP to the table 100: exit status 2
2023/08/21 22:59:15 Binding TCP TProxy listener to 0.0.0.0:1
2023/08/21 22:59:38 Received request to / : &{Method:GET URL:/ Proto:HTTP/1.1 ProtoMajor:1 ProtoMinor:1 Header:map[Accept:[*/*] User-Agent:[curl/7.88.1]] Body:{} GetBody:<nil> ContentLength:0 TransferEncoding:[] Close:false Host:10.244.0.5:8180 Form:map[] PostForm:map[] MultipartForm:<nil> Trailer:map[] RemoteAddr:192.168.8.1:55760 RequestURI:/ TLS:<nil> Cancel:<nil> Response:<nil> ctx:0xc000228280}
2023/08/21 23:05:58 Received request to / : &{Method:GET URL:/ Proto:HTTP/1.1 ProtoMajor:1 ProtoMinor:1 Header:map[Accept:[*/*] User-Agent:[curl/7.88.1]] Body:{} GetBody:<nil> ContentLength:0 TransferEncoding:[] Close:false Host:10.244.0.5:8180 Form:map[] PostForm:map[] MultipartForm:<nil> Trailer:map[] RemoteAddr:192.168.8.1:54998 RequestURI:/ TLS:<nil> Cancel:<nil> Response:<nil> ctx:0xc000228320}
```