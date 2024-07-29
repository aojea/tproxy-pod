# tproxy-pod

Container that implements a transparent TLS direct and reverse proxy to be used as a sidecar solution to implement mTLS across Pods.

** NOTE: Not Service mesh, this is just about mTLS between Pods **

```
 bin/tproxy -h
Usage: tls-tproxy [options]

  -cert string
        certifcate
  -key string
        certificate key
  -tcp-port int
        port to listen on TCP (default 1)
  -tls-port int
        port to listen on TLS (default 2)
  -v value
        number for the log level verbosity
```


The container requires CAP_NET_ADMIN privileges and uses multiple technologies in the Kernel to transparently proxy mTLS:

- [IP route policies, TPROXY netfilter and IP_TRANSPARENT socketa](https://docs.kernel.org/networking/tproxy.html)
- TODO [eBPF SOCKHASH](https://docs.kernel.org/bpf/map_sockmap.html)

The proxy implements two behaviors:

- Ingress traffic to the Pod: The traffic is transparently redirected on the ingress path (netfilter PREROUTING hook) to the mTLS proxy (TPROXY) that listens by default on the TCP port 2. 
After doing the TLS handshake, the content is proxied to the internal application. TODO: This is not yet conserving the original IP, so the end application
sees the connection from the Pod.

- Egress traffic from the Pod: The traffic that is originated inside the Pod namespace and destined outside is recirculated on the OUTPUT path (ip rule fwmark 0xa)
so it can be transparently redirected to the TCP proxy (TPROXY) that listens by default on the TCP port 1. The proxies initiates the mTLS connection with the destination, and if
succesful it forwards the connection from the client.


## TODO

- [ ] Retain source IP and Port on the Ingress traffic
- [ ] Webhook injection example
- [ ] Do a proper demo with certificates mounted on the Pod and associated to the Service account, per example https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity
- [ ] UDP support
- [ ] Filter to apply mTLS to a specific set of addresses
- [ ] Handle TCP And HTTP kubelet probes
- [ ] Run TCP benchmarks encrypted vs un-encrypted



## References

- https://wiki.nftables.org/wiki-nftables/index.php/Main_Page
- https://www.netfilter.org/projects/nftables/manpage.html
- https://ebpf-docs.dylanreimerink.nl/
- https://docs.kernel.org/networking/tproxy.html
- https://github.com/flomesh-io/pipy/tree/main/samples/bpf/transparent-proxy
- https://levelup.gitconnected.com/ebpf-sk-lookup-socket-lookup-and-redirection-08643062fab2
- https://blog.cloudflare.com/sockmap-tcp-splicing-of-the-future
- https://www.usenix.org/system/files/srecon23emea-slides_sitnicki.pdf
- https://jimmysong.io/en/blog/sidecar-injection-iptables-and-traffic-routing/



## Demo

1. Install a kubernetes cluster, in this case we are using kind

```sh
kind create cluster
```

2. Install the tproxy-pod using the manifest in this repo

```sh
make kind-image
```

or

```sh
kubectl apply -f install.yaml
```

The manifest will install two pods, each Pod contains a webserver and a sidecar container with the mTLS proxy

3. Install a pod with an https webserver

```
kubectl apply -f https://gist.githubusercontent.com/aojea/38c6ec34141882c0664caafa50db33ad/raw/961cbff7eac8121cad928bb2085eff9f6031123b/https.yaml
```

4. Check the IPs assigned to the Pods

```
kubectl get pods -o wide
NAME                            READY   STATUS    RESTARTS   AGE     IP            NODE           NOMINATED NODE   READINESS GATES
https-server-7585448b5c-s8lrj   1/1     Running   0          3h39m   10.244.2.21   kind-worker2   <none>           <none>
tproxy-6bfccf88fb-sq789         2/2     Running   0          68m     10.244.1.24   kind-worker    <none>           <none>
tproxy-6bfccf88fb-sv75h         2/2     Running   0          68m     10.244.2.26   kind-worker2   <none>           <none>
```

5. Check that from one application pod inside the `tproxy-pods` we can reach: Internet, the https-server, the other tproxy Pods and the internal application

```sh
$ kubectl exec -it tproxy-6bfccf88fb-sq789 -c app bash
kubectl exec [POD] [COMMAND] is DEPRECATED and will be removed in a future version. Use kubectl exec [POD] -- [COMMAND] instead.

bash-5.0# curl www.google.es
<!doctype html><html itemscope="" itemtype="http://schema.org/WebPage" lang="en"><head><meta content="Search the world's information, including webpages, images, videos a

```

In this test the certificates are only allowing localhost, so all the other mTLS connections in the Pod fail with the following error
```
$ kubectl exec -it tproxy-6bfccf88fb-sq789 -c app bash
kubectl exec [POD] [COMMAND] is DEPRECATED and will be removed in a future version. Use kubectl exec [POD] -- [COMMAND] instead.

bash-5.0# curl http://10.244.2.21:443/clientip
curl: (56) Recv failure: Connection reset by peer
```

```
$ kubectl logs tproxy-6bfccf88fb-sq789  -c proxy

I0729 15:34:17.034015       1 main.go:211] Accepting TCP connection from 10.244.1.24:42018 with destination of 10.244.2.21:443
I0729 15:34:17.034036       1 main.go:220] Connecting to [10.244.2.21:443]
I0729 15:34:17.036041       1 main.go:224] Failed to connect to original destination [10.244.2.21:443]: tls: failed to verify certificate: x509: certificate is valid for 127.0.0.1, ::1, not 10.244.2.21
```

```
$ kubectl logs tproxy-6bfccf88fb-sq789  -c proxy

curl http://10.244.2.26/clientip
curl: (56) Recv failure: Connection reset by peer
```

```
I0729 15:44:26.823295       1 main.go:211] Accepting TCP connection from 10.244.1.24:52044 with destination of 10.244.2.26:80
I0729 15:44:26.823320       1 main.go:220] Connecting to [10.244.2.26:80]
I0729 15:44:26.825429       1 main.go:224] Failed to connect to original destination [10.244.2.26:80]: tls: failed to verify certificate: x509: certificate is valid for 127.0.0.1, ::1, not 10.244.2.26
```


6. Check that an external connection to the exposed app uses TLS

```sh
root@kind-worker:/# curl -k https://10.244.1.26:80/clientip
curl: (56) OpenSSL SSL_read: OpenSSL/3.0.11: error:0A00045C:SSL routines::tlsv13 alert certificate required, errno 0

root@kind-worker:/#  curl  http://10.244.1.24:80/clientip
curl: (52) Empty reply from server

```
