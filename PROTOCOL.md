# Device announcement protocol

# Protocol description
The device announcement protocol is intended to allow devices to
let other devices know about their existence in the networks and
their properties. Therefore devices periodically broadcast
announcement packets.

**PROTOCOL VERISON 1**

**All data types in the packet are BigEndian**

### Announcement packet
```
uint8  header;            // 00
uint8  version;           // Protocol version
uint8  guid[8];           // Device EUI64
uint32 boot_number;       // Current boot number

time64 boot_time;         // Unix timestamp, seconds
uint32 uptime;            // Uptime since boot, seconds
uint32 lifetime;          // Total uptime since production, potentially lossy, seconds
uint32 announcement;      // Announcement number since boot

uuid   uuid;              // Application UUID (general feature set)

int32  latitude;          // 1E6
int32  longitude;         // 1E6
int32  elevation;         // centimeters

time64 ident_timestamp;   // Compilation time, unix timestamp, seconds

uint32 feature_list_hash; // hash of feature UUIDs
```
The announcement packet provides the EUI64 and the application UUID
of the device. Additionally the geographic location of the device is
included, but should be used carefully, since it may be unset or only
specify the general area.

The information in the announcement packet may be expanded on by
querying the device for a description and for a list of features.
The announcement packet includes the ident_timestamp which is tied
to the contents of the description and the feature_list_hash, which
allows the receiver become aware of changes in either set of data.

#### Active query
It is possible to actively search for devices through the device
announcement protocol. The packet with the following payload should
be sent to the broadcast address:
```
uint8 header;  // 0x10
uint8 version; // 0x01
```

### Device description packet
Provides additional information about a device, needs to be specifically
queried. Can be cached based on the uuid and ident_timestamp fields
in the announcement packet.

```
uint8  header;           // 00
uint8  version;          // Protocol version
uint8  guid[8];          // Device EUI64
uint32 boot_number;      // Current boot number

uuid   platform;         // Platform UUID - platform is a combination of a BOARD and peripherals
uuid   manufacturer;     // Manufacturer UUID
time64 production;       // When the device was produced, unix timestamp, seconds

time64 ident_timestamp;  // Compilation time, unix timestamp, seconds
uint8  sw_major_version;
uint8  sw_minor_version;
uint8  sw_patch_version;

```
### Device description query
The packet with the following payload should
be sent to the broadcast address
```
uint8 header;  // 0x11
uint8 version; // 0x01
```

### Feature list packets
Provides a list of feature UUIDs, which indicate the features
present and active on a device. For example listing available
sensor sources and actuator devices.

TODO Describe further ...
