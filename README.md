# python-moteannouncement
Python library for device announcement protocol.

Includes a basic test application for querying devices directly.

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
            packet = receiver.poll()
        except KeyboardInterrupt:
            break
        else:
            if packet is not None:
                print(packet)
        time.sleep(0.01)
```

# Example application usage
...

## Installation
Install the following dependencies:
https://github.com/proactivity-lab/python-moteconnection/releases
https://github.com/thinnect/serdepa/releases

Then install moteannaouncement.