{
  pkgs,
  image ? "lightswitch:latest",
  namespace ? "lightswitch",
  pyroscopeUrl ? "http://pyroscope:4040",
  pyroscopeAppName ? "lightswitch",
}:

let
  labels = {
    "app.kubernetes.io/name" = "lightswitch";
    "app.kubernetes.io/part-of" = "lightswitch";
  };
  yaml = pkgs.formats.yaml { };
in
yaml.generate "lightswitch-k8s.yaml" {
  apiVersion = "v1";
  kind = "List";
  items = [
    {
      apiVersion = "v1";
      kind = "Namespace";
      metadata = {
        name = namespace;
        labels = labels;
      };
    }
    {
      apiVersion = "v1";
      kind = "ServiceAccount";
      metadata = {
        name = "lightswitch";
        namespace = namespace;
        labels = labels;
      };
    }
    {
      apiVersion = "rbac.authorization.k8s.io/v1";
      kind = "ClusterRole";
      metadata = {
        name = "lightswitch";
        labels = labels;
      };
      rules = [
        {
          apiGroups = [ "" ];
          resources = [ "pods" ];
          verbs = [
            "get"
            "list"
            "watch"
          ];
        }
      ];
    }
    {
      apiVersion = "rbac.authorization.k8s.io/v1";
      kind = "ClusterRoleBinding";
      metadata = {
        name = "lightswitch";
        labels = labels;
      };
      roleRef = {
        apiGroup = "rbac.authorization.k8s.io";
        kind = "ClusterRole";
        name = "lightswitch";
      };
      subjects = [
        {
          kind = "ServiceAccount";
          name = "lightswitch";
          namespace = namespace;
        }
      ];
    }
    {
      apiVersion = "apps/v1";
      kind = "DaemonSet";
      metadata = {
        name = "lightswitch";
        namespace = namespace;
        labels = labels;
      };
      spec = {
        selector.matchLabels = labels;
        template = {
          metadata.labels = labels;
          spec = {
            serviceAccountName = "lightswitch";
            hostPID = true;
            tolerations = [
              {
                operator = "Exists";
              }
            ];
            containers = [
              {
                name = "lightswitch";
                image = image;
                imagePullPolicy = "IfNotPresent";
                args = [
                  "--sender=pyroscope"
                  "--server-url=$(PYROSCOPE_URL)"
                  "--pyroscope-app-name=$(PYROSCOPE_APP_NAME)"
                  "--kubernetes"
                  "--node-name=$(NODE_NAME)"
                ];
                env = [
                  {
                    name = "NODE_NAME";
                    valueFrom.fieldRef.fieldPath = "spec.nodeName";
                  }
                  {
                    name = "PYROSCOPE_URL";
                    value = pyroscopeUrl;
                  }
                  {
                    name = "PYROSCOPE_APP_NAME";
                    value = pyroscopeAppName;
                  }
                ];
                securityContext = {
                  privileged = true;
                  runAsUser = 0;
                };
                volumeMounts = [
                  {
                    name = "sys";
                    mountPath = "/sys";
                  }
                  {
                    name = "tmp";
                    mountPath = "/tmp";
                  }
                ];
              }
            ];
            volumes = [
              {
                name = "sys";
                hostPath = {
                  path = "/sys";
                  type = "Directory";
                };
              }
              {
                name = "tmp";
                hostPath = {
                  path = "/tmp";
                  type = "Directory";
                };
              }
            ];
          };
        };
      };
    }
  ];
}
