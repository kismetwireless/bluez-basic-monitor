# BLUEZ-BASIC-MONITOR

An extraction of the bluez dbus monitoring code simplified to perform signal and device monitoring only, intended as a simple base for inclusion in other tools.

The majority of this code is from the bluez-5.46 project (and is noted as such in the comments and directories); 

bluez-monitor uses dbus to do the bulk of the heavy lifting, but requires several libraries and bluetoothd and dbus to be available.

bluez-monitor-mgmtsock uses the raw management socket interface and should work without the external userspace infrastructure.

