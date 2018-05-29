# Device announcement protocol

# Protocol description

The device announcement protocol is intended to allow devices to
let other devices know about their existence in the networks and
their properties. Therefore devices periodically broadcast
announcement packets.

**All data types in the packet are BigEndian**

## **PROTOCOL VERISON 1 and 2**

Active queries will always receive a response no matter the version. The device
will try to match the version specified in the query, but if it cannot, then it
will respond with the latest version it is aware of.

Version 1 and 2 only have differences in the announcement packets themselves.
Periodic announcements are always sent using the latest version on the device.

### Announcement packet version 1

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

### Announcement packet version 2

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

char   position_type;     // F - fix, C - coordinator, G - gps, L - local, A - area. U - unknown.
int32  latitude;          // 1E6
int32  longitude;         // 1E6
int32  elevation;         // centimeters

time64 ident_timestamp;   // Compilation time, unix timestamp, seconds

uint32 feature_list_hash; // hash of feature UUIDs
```

The announcement packet provides the EUI64 and the application UUID
of the device. Additionally the geographic location of the device is
included, but should be used carefully for version 1, since it may be unset
or only specify the general area. Version 2 adds a position type specifier,
eliminating this problem.

The position type field is a single character, always uppercase:
 * U - position is not known, latitude, longitude and elevation values invalid.
 * A - position information has been averaged based on coordinates of surrounding
   devices. area size is not known or indicated.
 * L - position information has been obtained using local positioning methods.
 * G - position information has been obtained from a Global Navigation Satellite System.
 * F - position information has been given during deployment.
 * C - position information has been given during deployment and has been verified somehow.

### Additional information

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
uint8 version; // 0x02
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
uint8 version; // 0x02
```

### Feature list packets

Provides a list of feature UUIDs, which indicate the features
present and active on a device. For example listing available
sensor sources and actuator devices.

TODO Describe further ...
