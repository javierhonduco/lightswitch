This dockerfile is for ease of use on ARM64 MacOS for compilation/running tests locally

Specifically for the k8s feature, I develop and run tests on my mac mini, then ship to my k8s cluster for testing.

```
# javier - replace this with whatever you need to if you decide to accept this,
# this builds a docker image ready for use in a kubernetes manifest.
docker build --platform linux/amd64 -t ghcr.io/xlanor/lightswitch:k8s -f docker/Dockerfile .
docker push ghcr.io/xlanor/lightswitch:k8s
kubectl rollout restart daemonset/lightswitch -n lightswitch
```

```
# build once and run tests
docker build --platform linux/amd64 --target builder -t lightswitch-builder -f docker/Dockerfile .
docker build --platform linux/amd64 -t lightswitch-test -f docker/Dockerfile.test .
docker run --rm --platform linux/amd64 -v "$(pwd)":/src -w /src lightswitch-test cargo test -p lightswitch-k8s
```