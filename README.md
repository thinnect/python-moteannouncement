# python-moteannouncement
Python library for device announcement protocol.

Includes a basic test application for querying devices directly.

## Basics of the API

The `DAReceiver` class is constructed using the connection string
for the connection, the address of the radio device (`int`) and
the minimum send period:

```
receiver = DAReceiver('sf@localhost:9002', 0x1234, 10)
```

Then, the devices in the network can be queried by using the `query`
method:

```
receiver.query('FFFFFFFFFFFF0102', info=True, description=True, features=False)
```

The `DAReceiver` instance must be polled for the response:

```
response = receiver.poll()
```

The if a response is not ready yet, a `None` value is returned. The
user must also be aware that responses are also returned when a
broadcast `DeviceAnnouncement` message is received even though the
node has not been queried.

The `poll` method _must_ be periodically called for the network
traffic to function properly.

### `Response` objects

The `Response` object separates the information received from the
nodes into several groups. It has fields for each group, but the
`description` and `features` fields are optional and will be set
to `None` if not available.

The structure of the `Response` object can roughly be summarized
with the following example (YAML notation):

```
Response:
  version: "0.2.0"
  arrival: "2018-06-20T10:29:03.759308"
  device:
    guid: "70B3D558900102A9"
    application: "00000000-0000-0000-0000-000000000000"
    position_type: U
    latitude: 59.4339
    longitude: 24.7549
    elevation: 0
    ident_timestamp: "59f9ded5"
  boot:
    boot_number: 950
    boot_time: "2016-04-16T13:21:44"
    uptime: 5605045
    lifetime: 36425213
    announcement: 334
  feature_list_hash: "af90af90"
  description:
    platform: "00000000-0000-0000-0000-000000000000"
    manufacturer: "00000000-0000-0000-0000-000000000000"
    production: "2015-02-10T13:29:34"
    software_version: "0.91.0"
  features:
    - "00000000-0000-0000-0000-000000000000"
```

The `Response` object has the attribute `as_dict` that returns an
`OrderedDict` instance of its members that is safe to serialize
into a JSON object.

The `version` field notes the version of the structure. Version
`0.2.0` has the `device.position_type` field.

## Library usage examples

```
from moteannouncement import DAReceiver
import time

conn = 'sf@localhost:9002'
addr = 0x0315 # address of the device running this application
receiver = DAReceiver(
    connection_string=conn,
    address=addr,
    period=10
)

with receiver:
    receiver.query(
        "FFFFFFFFFFFF0610",
        info=True, description=True, features=True
    )
    while True:
        try:
            response = receiver.poll()
        except KeyboardInterrupt:
            break
        else:
            if response is not None:
                print(response)
        time.sleep(0.01)
```

# Example application usage
...

## Installation
Install the following dependencies:
https://github.com/proactivity-lab/python-moteconnection/releases
https://github.com/thinnect/serdepa/releases

Then install moteannaouncement.
