"""
ts=2026-02-04T10:39:48.881831466Z caller=frontend_scheduler_worker.go:131 level=info component=frontend msg="adding connection to query-scheduler" addr=192.168.215.2:4040
ts=2026-02-04T10:39:53.381534347Z caller=distributor.go:445 component=distributor tenant=anonymous user=anonymous level=debug msg="profile accepted" service_name=my_service profile_id=734FD599-6865-419E-9475-932762D8F469 profile_type=process_cpu matched_usage_groups=[] detected_language=unknown profile_time=2026-02-04T10:33:03.133Z ingestion_delay=6m50.244s decompressed_size=580935 sample_count=1761
ts=2026-02-04T10:39:53.382068682Z caller=http.go:346 level=debug traceID=1005f23612613857 method=POST uri=/push.v1.PusherService/Push status=200 duration=19.632756ms request_body_size=757KiB request_body_read_duration=2.724923ms msg="http request processed"
"""

import requests
import base64
body = {
    "series": [
      {
        "labels": [
          {
            "name": "__name__",
            "value": "process_cpu"
          },
          {
            "name": "service_name",
            "value": "my_service"
          }
        ],
        "samples": [
          {
            "ID": "734FD599-6865-419E-9475-932762D8F469",
            "rawProfile": base64.b64encode(open('profile.pb', 'rb').read()).decode('ascii')
          }
        ]
      }
    ]
  }
url = 'http://docker.orb.internal:4040/push.v1.PusherService/Push'
# docker.orb.internal
resp = requests.post(url, json=body)
print(resp)
print(resp.content)
