/* Simplified bluez monitoring interface
 *
 *  Derived from the mgmt-api docs
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <string.h>
#include <sys/ioctl.h>

#include "mgmtlib/bluetooth.h"
#include "mgmtlib/hci.h"
#include "mgmtlib/mgmt.h"

#include "linux_bt_rfkill.h"
#include "simple_ringbuf_c.h"

#include "btsnoop.h"

typedef struct {
    /* Target interface */
    char *bt_interface;
    char *bt_interface_str_address;

    /* Raw (inverse) bdaddress */
    uint8_t bt_interface_address[6];

    /* Are we already controlling it */
    int state_powering_on;
    int state_scanning_on;

    /* bluez management interface socket */
    int mgmt_fd;
    int monitor_fd;
    unsigned int devid;

    /* Read ringbuf */
    kis_simple_ringbuf_t *read_rbuf;
    kis_simple_ringbuf_t *read_monitor_rbuf;

    /* Scanning type */
    uint8_t scan_type;
} local_bluetooth_t;

#define SCAN_TYPE_BREDR (1 << BDADDR_BREDR)
#define SCAN_TYPE_LE ((1 << BDADDR_LE_PUBLIC) | (1 << BDADDR_LE_RANDOM))
#define SCAN_TYPE_DUAL (SCAN_TYPE_BREDR | SCAN_TYPE_LE)

/* Outbound commands */
typedef struct {
    uint16_t opcode;
    uint16_t index;
    uint16_t length;
    uint8_t param[0];
} bluez_mgmt_command_t;

/* Device discovered inner packet */
typedef struct {
    uint8_t macaddr[6];
    uint8_t rssi;
    uint32_t flags;
    uint16_t data_len;
    uint8_t data[0];
} bluez_monitor_discovered_t;

static const struct {
	uint8_t bit;
	const char *str;
} eir_flags_table[] = {
	{ 0, "LE Limited Discoverable Mode"		},
	{ 1, "LE General Discoverable Mode"		},
	{ 2, "BR/EDR Not Supported"			},
	{ 3, "Simultaneous LE and BR/EDR (Controller)"	},
	{ 4, "Simultaneous LE and BR/EDR (Host)"	},
	{ }
};

static const struct {
	uint8_t bit;
	const char *str;
} mgmt_address_type_table[] = {
	{  0, "BR/EDR"		},
	{  1, "LE Public"	},
	{  2, "LE Random"	},
	{ }
};

/* Convert an address to a string; string must hold at least 18 bytes */
#define BDADDR_STR_LEN      18
void bdaddr_to_string(const uint8_t *bdaddr, char *str) {
    snprintf(str, 18, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
            bdaddr[5], bdaddr[4], bdaddr[3],
            bdaddr[2], bdaddr[1], bdaddr[0]);
}

/* Connect to the bluez management system */
int mgmt_connect() {
    int fd;
    struct sockaddr_hci addr;

    if ((fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 
                    BTPROTO_HCI)) < 0) {
        return -errno;
    }

    memset(&addr, 0, sizeof(addr));
    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev = HCI_DEV_NONE;
    addr.hci_channel = HCI_CHANNEL_CONTROL;

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        int err = -errno;
        close(fd);
        return err;
    }
    
    return fd;
}

/* Connect to the bluez management system, monitor channel */
int monitor_connect() {
    int fd;
    struct sockaddr_hci addr;

    if ((fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 
                    BTPROTO_HCI)) < 0) {
        return -errno;
    }

    memset(&addr, 0, sizeof(addr));
    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev = HCI_DEV_NONE;
    addr.hci_channel = HCI_CHANNEL_MONITOR;

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        int err = -errno;
        close(fd);
        return err;
    }
    
    return fd;

}

/* Write a request to the management socket ringbuffer, serviced by the
 * select() loop */
int mgmt_write_request(int mgmt_fd, uint16_t opcode, uint16_t index, 
        uint16_t length, const void *param) {
    bluez_mgmt_command_t *cmd;
    size_t pksz = sizeof(bluez_mgmt_command_t) + length;
    ssize_t written_sz;

    if (opcode == 0) {
        return -1;
    }

    if (length > 0 && param == NULL) {
        return -1;
    }

    cmd = (bluez_mgmt_command_t *) malloc(pksz);

    cmd->opcode = htole16(opcode);
    cmd->index = htole16(index);
    cmd->length = htole16(length);

    if (length != 0 && param != NULL) {
        memcpy(cmd->param, param, length);
    }

    if ((written_sz = send(mgmt_fd, cmd, pksz, 0)) < 0) {
        fprintf(stderr, "FATAL - Failed to send to mgmt sock: %s\n",
                strerror(errno));
        free(cmd);
        exit(1);
    }

    free(cmd);

    return 1;
}

/* Initiate finding a device */
int cmd_start_discovery(local_bluetooth_t *localbt) {
    struct mgmt_cp_start_discovery cp;

    memset(&cp, 0, sizeof(cp));
    cp.type = localbt->scan_type;

    return mgmt_write_request(localbt->mgmt_fd, MGMT_OP_START_DISCOVERY, 
            localbt->devid, sizeof(cp), &cp);
}

/* Enable BREDR */
int cmd_enable_bredr(local_bluetooth_t *localbt) {
    uint8_t val = 0x01;

    return mgmt_write_request(localbt->mgmt_fd, MGMT_OP_SET_BREDR, localbt->devid, 
            sizeof(val), &val);
}

/* Enable BTLE */
int cmd_enable_btle(local_bluetooth_t *localbt) {
    uint8_t val = 0x01;

    return mgmt_write_request(localbt->mgmt_fd, MGMT_OP_SET_LE, localbt->devid, 
            sizeof(val), &val);
}

/* Probe the controller */
int cmd_get_controller_info(local_bluetooth_t *localbt) {
    return mgmt_write_request(localbt->mgmt_fd, MGMT_OP_READ_INFO, localbt->devid, 0, NULL);
}

int cmd_enable_controller(local_bluetooth_t *localbt) {
    uint8_t val = 0x1;

    return mgmt_write_request(localbt->mgmt_fd, MGMT_OP_SET_POWERED, localbt->devid, 
            sizeof(val), &val);
}

/* Handle controller info response */
void resp_controller_info(local_bluetooth_t *localbt, uint8_t status, uint16_t len, 
        const void *param) {
    const struct mgmt_rp_read_info *rp = (struct mgmt_rp_read_info *) param;
    char bdaddr[BDADDR_STR_LEN];

    uint32_t current, supported;

    if (len < sizeof(struct mgmt_rp_read_info)) {
        fprintf(stderr, "DEBUG - insufficient data in controller info\n");
        return;
    }

    bdaddr_to_string(rp->bdaddr.b, bdaddr);

    fprintf(stderr, "INTERFACE - Got interface info for %s\n", bdaddr);

    current = le32toh(rp->current_settings);
    supported = le32toh(rp->supported_settings);

    /* Figure out if we support BDR/EDR and BTLE */
    if (supported & MGMT_SETTING_BREDR) {
        fprintf(stderr, "    Supports BR/EDR\n");
    } else {
        fprintf(stderr, "    No EDR/SDR support\n");
        localbt->scan_type &= ~SCAN_TYPE_BREDR;
    }

    if (supported & MGMT_SETTING_LE) {
        fprintf(stderr, "    Supports BTLE\n");
    } else {
        fprintf(stderr, "    No BTLE support\n");
        localbt->scan_type &= ~SCAN_TYPE_LE;
    }

    /* Is it currently powered? */
    if (current & MGMT_SETTING_POWERED)
        fprintf(stderr, "    Powered\n");
    else
        fprintf(stderr, "    Down\n");

    /* Is BREDR enabled? If not, turn it on */
    if ((supported & MGMT_SETTING_BREDR) && !(current & MGMT_SETTING_BREDR)) {
        cmd_enable_bredr(localbt);    
        return;
    }

    /* Is BLE enabled? If not, turn it on */
    if ((supported & MGMT_SETTING_LE) && !(current & MGMT_SETTING_LE)) {
        cmd_enable_btle(localbt);    
        return;
    }

    if (!(current & MGMT_SETTING_POWERED)) {
        /* If the interface is off, turn it on */
        fprintf(stderr, "DEBUG - Powering on interface\n");
        cmd_enable_controller(localbt);
    } else {
        /* If the interface is on, start scanning */
        cmd_start_discovery(localbt);
    }
}

void resp_controller_power(local_bluetooth_t *localbt, uint8_t status, uint16_t len,
        const void *param) {
    uint32_t *rsettings = (uint32_t *) param;
   
    uint32_t settings;

    if (len < sizeof(uint32_t)) {
        fprintf(stderr, "DEBUG - insufficient data in controller power\n");
        return;
    }

    settings = le32toh(*rsettings);

    if (settings & MGMT_SETTING_POWERED) {
        fprintf(stderr, "DEBUG - Interface powered on\n");

        /* Initiate scanning mode */
        cmd_start_discovery(localbt);
    } else {
        fprintf(stderr, "FATAL - Interface was asked to power on and failed\n");
        exit(1);
    }
}

void evt_controller_discovering(local_bluetooth_t *localbt, uint16_t len, const void *param) {
    struct mgmt_ev_discovering *dsc = (struct mgmt_ev_discovering *) param;

    const char *dsc_type;

    if (len < sizeof(struct mgmt_ev_discovering)) {
        fprintf(stderr, "DEBUG - insufficient data in discovering event\n");
        return;
    }

    if ((dsc->type & SCAN_TYPE_DUAL) == SCAN_TYPE_DUAL) {
        dsc_type = "BREDR/LE";
    } else if (dsc->type & SCAN_TYPE_BREDR) {
        dsc_type = "BDEDR";
    } else if (dsc->type & SCAN_TYPE_LE) {
        dsc_type = "BTLE";
    } else {
        dsc_type = "NONE";
    }

    fprintf(stderr, "DISCOVERY - %s - %s\n",
            dsc->discovering ? "enabled" : "disabled", dsc_type);

    if (!dsc->discovering) {
        fprintf(stderr, "DEBUG - Restarting discovery mode\n");
        cmd_start_discovery(localbt);
    }

}

static char *eir_get_name(const uint8_t *eir, uint16_t eir_len) {
    uint8_t parsed = 0;

    if (eir_len < 2)
        return NULL;

    while (parsed < eir_len - 1) {
        uint8_t field_len = eir[0];

        if (field_len == 0)
            break;

        parsed += field_len + 1;

        if (parsed > eir_len)
            break;

        /* Check for short of complete name */
        if (eir[1] == 0x09 || eir[1] == 0x08)
            return strndup((char *) &eir[2], field_len - 1);

        eir += field_len + 1;
    }

    return NULL;
}

static unsigned int eir_get_flags(const uint8_t *eir, uint16_t eir_len) {
    uint8_t parsed = 0;

    if (eir_len < 2)
        return 0;

    while (parsed < eir_len - 1) {
        uint8_t field_len = eir[0];

        if (field_len == 0)
            break;

        parsed += field_len + 1;

        if (parsed > eir_len)
            break;

        /* Check for flags */
        if (eir[1] == 0x01)
            return eir[2];

        eir += field_len + 1;
    }

    return 0;
}

/* Actual device found in scan trigger */
void evt_device_found(local_bluetooth_t *localbt, uint16_t len, const void *param) {
    struct mgmt_ev_device_found *dev = (struct mgmt_ev_device_found *) param;
    char addr[BDADDR_STR_LEN];
    uint32_t flags;
    uint16_t eirlen;

	static const char *str[] = { "BR/EDR", "LE Public", "LE Random" };
    const char *typestr;

    char *name;

    if (len < sizeof(struct mgmt_ev_device_found)) {
        fprintf(stderr, "DEBUG - insufficient data in device event\n");
        return;
    }

    /* Extract the type and make it a string */
    if (dev->addr.type >= 0 && dev->addr.type < BDADDR_LE_RANDOM)
        typestr = str[dev->addr.type];
    else
        typestr = "UNKNOWN";

    /* Convert the mac */
    bdaddr_to_string(dev->addr.bdaddr.b, addr);

    /* Endian flip the flags */
    flags = le32toh(dev->flags);

    /* Extract the name from EIR */
    eirlen = le16toh(dev->eir_len);
    name = eir_get_name(dev->eir, eirlen);

    fprintf(stderr, "DEVICE - %s (%s) \"%s\" %d\n", addr, typestr, name, dev->rssi);

    free(name);
}

void handle_mgmt_response(local_bluetooth_t *localbt) {
    /* Top-level command */
    bluez_mgmt_command_t *evt;

    /* Buffer loading sizes */
    size_t bufsz;
    size_t peekedsz;

    /* Interpreted codes from response */
    uint16_t ropcode;
    uint16_t rlength;
    uint16_t rindex;

    /* Nested records */
    struct mgmt_ev_cmd_complete *crec;
    struct mgmt_ev_cmd_status *cstat;

    while ((bufsz = kis_simple_ringbuf_used(localbt->read_rbuf)) >= 
            sizeof(bluez_mgmt_command_t)) {
        evt = (bluez_mgmt_command_t *) malloc(bufsz);

        if ((peekedsz = kis_simple_ringbuf_peek(localbt->read_rbuf, (void *) evt, bufsz)) < 
                sizeof(bluez_mgmt_command_t)) {
            fprintf(stderr, "DEBUG - peeked less than we need for minimum record\n");
            free(evt);
            return;
        }

        ropcode = le16toh(evt->opcode);
        rindex = le16toh(evt->index);
        rlength = le16toh(evt->length);

        if (rlength + sizeof(bluez_mgmt_command_t) > peekedsz) {
            fprintf(stderr, "DEBUG - didn't peek enough for this packet\n");
            free(evt);
            return;
        }

        /* Consume this object from the buffer */
        kis_simple_ringbuf_read(localbt->read_rbuf, NULL, 
                sizeof(bluez_mgmt_command_t) + rlength);

        /* Ignore events not for us */
        if (rindex != localbt->devid) {
            fprintf(stderr, "DEBUG - Got information about an interface we don't care "
                    "about (hci%u)\n", rindex);
            continue;
        }

        if (ropcode == MGMT_EV_CMD_COMPLETE) {
            if (rlength < sizeof(struct mgmt_ev_cmd_complete)) {
                fprintf(stderr, "DEBUG - status response too small for response rec\n");
                free(evt);
                continue;
            }

            crec = (struct mgmt_ev_cmd_complete *) evt->param;

            ropcode = le16toh(crec->opcode);

            /* Handle the different opcodes */
            switch (ropcode) {
                case MGMT_OP_READ_INFO:
                    resp_controller_info(localbt, crec->status, 
                            rlength - sizeof(struct mgmt_ev_cmd_complete),
                            crec->data);
                    break;
                case MGMT_OP_SET_POWERED:
                    resp_controller_power(localbt, crec->status,
                            rlength - sizeof(struct mgmt_ev_cmd_complete),
                            crec->data);
                    break;
                case MGMT_OP_START_DISCOVERY:
                    if (crec->status != 0) {
                        fprintf(stderr, "FATAL: Discovery command failed\n");
                        exit(1);
                    }
                    break;
                case MGMT_OP_SET_BREDR:
                    if (crec->status != 0) {
                        fprintf(stderr, "FATAL: Enabling BREDR failed\n");
                        exit(1);
                    }

                    fprintf(stderr, "DEBUG - BREDR setting complete, probing controller\n");
                    cmd_get_controller_info(localbt);
                    break;
                case MGMT_OP_SET_LE:
                    if (crec->status != 0) {
                        fprintf(stderr, "FATAL: Enabling LE failed\n");
                        exit(1);
                    }

                    fprintf(stderr, "DEBUG - BLE setting complete, probing controller\n");
                    cmd_get_controller_info(localbt);
                    break;
                default:
                    fprintf(stderr, "COMMAND - unhandled command complete "
                            "0x%x hci%u len %u\n", 
                            ropcode, rindex, rlength);
            }
        } else if (ropcode == MGMT_EV_CMD_STATUS) {
            fprintf(stderr, "DEBUG - command status hci%u len %u\n", rindex, rlength);
        } else {
            switch (ropcode) {
                case MGMT_EV_DISCOVERING:
                    evt_controller_discovering(localbt, 
                            rlength - sizeof(bluez_mgmt_command_t),
                            evt->param);
                    break;
                case MGMT_EV_DEVICE_FOUND:
                    evt_device_found(localbt,
                            rlength - sizeof(bluez_mgmt_command_t),
                            evt->param);
                    break;
                case MGMT_EV_INDEX_REMOVED:
                    fprintf(stderr, "FATAL: hci%u removed\n", rindex);
                    exit(1);
                    break;
                default:
                    fprintf(stderr, "DEBUG - Unhandled event 0x%x hci%u len %u\n", 
                            ropcode, rindex, rlength);
            }
        }

        /* Dump the temp object */
        free(evt);
    }
}

void handle_eir(local_bluetooth_t *localbt, uint16_t eir_len, 
        const uint8_t *eir_data, unsigned int le) {
    uint16_t len;

	if (eir_len == 0)
		return;

	while (len < eir_len - 1) {
		uint8_t field_len = eir_data[0];
		const uint8_t *data = &eir_data[2];
		uint8_t data_len;
		char name[239], label[100];
		uint8_t flags, mask;
		int i;

		if (field_len == 0)
			break;

		len += field_len + 1;

		/* Do not continue EIR Data parsing if got incorrect length */
		if (len > eir_len) {
			len -= field_len + 1;
			break;
		}

		data_len = field_len - 1;

		switch (eir_data[1]) {
		case BT_EIR_FLAGS:
			flags = *data;
			mask = flags;

			print_field("Flags: 0x%2.2x", flags);

			for (i = 0; eir_flags_table[i].str; i++) {
				if (flags & (1 << eir_flags_table[i].bit)) {
					print_field("  %s",
							eir_flags_table[i].str);
					mask &= ~(1 << eir_flags_table[i].bit);
				}
			}

			if (mask)
				print_text(COLOR_UNKNOWN_SERVICE_CLASS,
					"  Unknown flags (0x%2.2x)", mask);
			break;

		case BT_EIR_UUID16_SOME:
			if (data_len < sizeof(uint16_t))
				break;
			print_uuid16_list("16-bit Service UUIDs (partial)",
							data, data_len);
			break;

		case BT_EIR_UUID16_ALL:
			if (data_len < sizeof(uint16_t))
				break;
			print_uuid16_list("16-bit Service UUIDs (complete)",
							data, data_len);
			break;

		case BT_EIR_UUID32_SOME:
			if (data_len < sizeof(uint32_t))
				break;
			print_uuid32_list("32-bit Service UUIDs (partial)",
							data, data_len);
			break;

		case BT_EIR_UUID32_ALL:
			if (data_len < sizeof(uint32_t))
				break;
			print_uuid32_list("32-bit Service UUIDs (complete)",
							data, data_len);
			break;

		case BT_EIR_UUID128_SOME:
			if (data_len < 16)
				break;
			print_uuid128_list("128-bit Service UUIDs (partial)",
								data, data_len);
			break;

		case BT_EIR_UUID128_ALL:
			if (data_len < 16)
				break;
			print_uuid128_list("128-bit Service UUIDs (complete)",
								data, data_len);
			break;

		case BT_EIR_NAME_SHORT:
			memset(name, 0, sizeof(name));
			memcpy(name, data, data_len);
			print_field("Name (short): %s", name);
			break;

		case BT_EIR_NAME_COMPLETE:
			memset(name, 0, sizeof(name));
			memcpy(name, data, data_len);
			print_field("Name (complete): %s", name);
			break;

		case BT_EIR_TX_POWER:
			if (data_len < 1)
				break;
			print_field("TX power: %d dBm", (int8_t) *data);
			break;

		case BT_EIR_CLASS_OF_DEV:
			if (data_len < 3)
				break;
			print_dev_class(data);
			break;

		case BT_EIR_SSP_HASH_P192:
			if (data_len < 16)
				break;
			print_hash_p192(data);
			break;

		case BT_EIR_SSP_RANDOMIZER_P192:
			if (data_len < 16)
				break;
			print_randomizer_p192(data);
			break;

		case BT_EIR_DEVICE_ID:
			/* SMP TK has the same value as Device ID */
			if (le)
				print_hex_field("SMP TK", data, data_len);
			else if (data_len >= 8)
				print_device_id(data, data_len);
			break;

		case BT_EIR_SMP_OOB_FLAGS:
			print_field("SMP OOB Flags: 0x%2.2x", *data);
			break;

		case BT_EIR_SLAVE_CONN_INTERVAL:
			if (data_len < 4)
				break;
			print_field("Slave Conn. Interval: 0x%4.4x - 0x%4.4x",
							get_le16(&data[0]),
							get_le16(&data[2]));
			break;

		case BT_EIR_SERVICE_UUID16:
			if (data_len < sizeof(uint16_t))
				break;
			print_uuid16_list("16-bit Service UUIDs",
							data, data_len);
			break;

		case BT_EIR_SERVICE_UUID128:
			if (data_len < 16)
				break;
			print_uuid128_list("128-bit Service UUIDs",
							data, data_len);
			break;

		case BT_EIR_SERVICE_DATA:
			if (data_len < 2)
				break;
			sprintf(label, "Service Data (UUID 0x%4.4x)",
							get_le16(&data[0]));
			print_hex_field(label, &data[2], data_len - 2);
			break;

		case BT_EIR_RANDOM_ADDRESS:
			if (data_len < 6)
				break;
			print_addr("Random Address", data, 0x01);
			break;

		case BT_EIR_PUBLIC_ADDRESS:
			if (data_len < 6)
				break;
			print_addr("Public Address", data, 0x00);
			break;

		case BT_EIR_GAP_APPEARANCE:
			if (data_len < 2)
				break;
			print_appearance(get_le16(data));
			break;

		case BT_EIR_SSP_HASH_P256:
			if (data_len < 16)
				break;
			print_hash_p256(data);
			break;

		case BT_EIR_SSP_RANDOMIZER_P256:
			if (data_len < 16)
				break;
			print_randomizer_p256(data);
			break;

		case BT_EIR_3D_INFO_DATA:
			print_hex_field("3D Information Data", data, data_len);
			if (data_len < 2)
				break;

			flags = *data;
			mask = flags;

			print_field("  Features: 0x%2.2x", flags);

			for (i = 0; eir_3d_table[i].str; i++) {
				if (flags & (1 << eir_3d_table[i].bit)) {
					print_field("    %s",
							eir_3d_table[i].str);
					mask &= ~(1 << eir_3d_table[i].bit);
				}
			}

			if (mask)
				print_text(COLOR_UNKNOWN_FEATURE_BIT,
					"      Unknown features (0x%2.2x)", mask);

			print_field("  Path Loss Threshold: %d", data[1]);
			break;

		case BT_EIR_MANUFACTURER_DATA:
			if (data_len < 2)
				break;
			print_manufacturer_data(data, data_len);
			break;

		default:
			sprintf(label, "Unknown EIR field 0x%2.2x", eir[1]);
			print_hex_field(label, data, data_len);
			break;
		}

		eir += field_len + 1;
	}

	if (len < eir_len && eir[0] != 0)
		packet_hexdump(eir, eir_len - len);
}

void handle_monitor_device_discovered(local_bluetooth_t *localbt, uint16_t len,
        const void *param) {
    bluez_monitor_discovered_t *discovery = (bluez_monitor_discovered_t *) param;

    if (len < sizeof(bluez_monitor_discovered_t)) {
        fprintf(stderr, "ERROR - Invalid discovered device size\n");
        return;
    }

    printf("    MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            discovery->macaddr[5],
            discovery->macaddr[4],
            discovery->macaddr[3],
            discovery->macaddr[2],
            discovery->macaddr[1],
            discovery->macaddr[0]);
    printf("   RSSI: %d\n", discovery->rssi);

}

void handle_monitor_ctrl_event(local_bluetooth_t *localbt, uint16_t len, 
        const void *param) {

    uint16_t ctl_opcode;

	if (len < 4) {
        fprintf(stderr, "ERROR - Invalid ctrl event size\n");
        return;
    }

    /* We don't care about the cookie */

    param += 4;
    len -= 4;

    if (len < 2) {
        fprintf(stderr, "ERROR - invalid ctrl event size\n");
        return;
    }

    memcpy(&ctl_opcode, param, 2);

    ctl_opcode = le16toh(ctl_opcode);

    param += 2;
    len -= 2;

    if (ctl_opcode == 0x12) {
        printf("    CTRL - device found\n");
        handle_monitor_device_discovered(localbt, len, param);
    } else {
        printf("    CTRL OPCODE %x\n", ctl_opcode);
    }

}

void handle_monitor_response(local_bluetooth_t *localbt) {
    /* Top-level command */
    bluez_mgmt_command_t *evt;

    /* Buffer loading sizes */
    size_t bufsz;
    size_t peekedsz;

    /* Interpreted codes from response */
    uint16_t ropcode;
    uint16_t rlength;
    uint16_t rindex;

    while ((bufsz = kis_simple_ringbuf_used(localbt->read_monitor_rbuf)) >= 
            sizeof(bluez_mgmt_command_t)) {
        evt = (bluez_mgmt_command_t *) malloc(bufsz);

        if ((peekedsz = kis_simple_ringbuf_peek(localbt->read_monitor_rbuf, 
                        (void *) evt, bufsz)) < sizeof(bluez_mgmt_command_t)) {
            fprintf(stderr, "DEBUG - peeked less than we need for minimum record\n");
            free(evt);
            return;
        }

        ropcode = le16toh(evt->opcode);
        rindex = le16toh(evt->index);
        rlength = le16toh(evt->length);

        if (rlength + sizeof(bluez_mgmt_command_t) > peekedsz) {
            fprintf(stderr, "DEBUG - didn't peek enough for this packet\n");
            free(evt);
            return;
        }

        /* Consume this object from the buffer */
        kis_simple_ringbuf_read(localbt->read_monitor_rbuf, NULL, 
                sizeof(bluez_mgmt_command_t) + rlength);

        /* Ignore events not for us */
        if (rindex != localbt->devid) {
            fprintf(stderr, "DEBUG - Got information about an interface we don't care "
                    "about (hci%u)\n", rindex);
            continue;
        }

        if (ropcode == 2) {
            printf("COMMAND\n");
        } else if (ropcode == 16) {
            printf("CTRLCOMMAND\n");
        } else if (ropcode == 17) {
            printf("CTRLEVENT\n");
            handle_monitor_ctrl_event(localbt, rlength, evt->param);
        } else {
            printf("UNKNOWN opcode %u (don't care)\n", ropcode);
        }

        /* Dump the temp object */
        free(evt);
    }
}

int main(int argc, char *argv[]) {
    local_bluetooth_t localbt = {
        .bt_interface = NULL,
        .bt_interface_str_address = NULL,
        .state_powering_on = 0,
        .state_scanning_on = 0,
        .devid = 0,
        .mgmt_fd = 0,
        .read_rbuf = NULL,
        .read_monitor_rbuf = NULL,
        .scan_type = SCAN_TYPE_DUAL,
    };

    /* Local socket info for extracting MAC address of hci interface */
    int hci_sock;
    static struct hci_dev_info di;
    char bdaddr[BDADDR_STR_LEN];

    /* Ringbuffer and select mgmt stuff */
    fd_set rset;

    if (argc < 2) {
        fprintf(stderr, "FATAL - expected %s [interface]\n", argv[0]);
        exit(1);
    }

    localbt.bt_interface = strdup(argv[1]);

    fprintf(stderr, "DEBUG - Targetting interface %s\n", localbt.bt_interface);

    if ((hci_sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
        fprintf(stderr, "FATAL - %s couldn't create HCI socket: %s\n", 
                localbt.bt_interface, strerror(errno));
        exit(1);
    }

    if (sscanf(localbt.bt_interface, "hci%u", &(localbt.devid)) != 1) {
        fprintf(stderr, "FATAL - %s couldn't parse device id\n", localbt.bt_interface);
        exit(1);
    }

    di.dev_id = localbt.devid;

    if (ioctl(hci_sock, HCIGETDEVINFO, (void *) &di)) {
        fprintf(stderr, "FATAL - %s couldn't get device info\n", localbt.bt_interface);
        exit(1);
    }

    memcpy(localbt.bt_interface_address, di.bdaddr.b, 6);

    bdaddr_to_string(di.bdaddr.b, bdaddr);

    fprintf(stderr, "DEBUG - %s %s\n", localbt.bt_interface, bdaddr);

    localbt.bt_interface_str_address = strdup(bdaddr);

    /* Reset the interface */
    fprintf(stderr, "DEBUG - Resetting %s\n", localbt.bt_interface);
    if (ioctl(hci_sock, HCIDEVDOWN, localbt.devid) < 0) {
        fprintf(stderr, "DEBUG - Could not reset device %s: %s\n",
                localbt.bt_interface, strerror(errno));
    }
    if (ioctl(hci_sock, HCIDEVUP, localbt.devid) < 0) {
        fprintf(stderr, "DEBUG - Could not reset device %s: %s\n",
                localbt.bt_interface, strerror(errno));
    }

    close(hci_sock);

    if (linux_sys_get_bt_rfkill(localbt.bt_interface, LINUX_BT_RFKILL_TYPE_HARD)) {
        fprintf(stderr, "FATAL - %s rfkill hardkill blocked\n", localbt.bt_interface);
        exit(1);
    } else {
        fprintf(stderr, "DEBUG - %s rfkill hardkill unblocked\n", localbt.bt_interface);
    }

    if (linux_sys_get_bt_rfkill(localbt.bt_interface, LINUX_BT_RFKILL_TYPE_SOFT)) {
        fprintf(stderr, "DEBUG - %s rfkill softkill blocked\n", localbt.bt_interface);

        if (linux_sys_clear_bt_rfkill(localbt.bt_interface) < 0) {
            fprintf(stderr, "DEBUG - %s rfkill softkill, could not unblock", 
                    localbt.bt_interface);
            exit(1);
        }
    } else {
        fprintf(stderr, "DEBUG - %s rfkill softkill unblocked\n", localbt.bt_interface);
    }

    if ((localbt.mgmt_fd = mgmt_connect()) < 0) {
        fprintf(stderr, "FATAL - could not connect management socket: %s\n",
                strerror(localbt.mgmt_fd * -1));
        exit(1);
    }

    fprintf(stderr, "DEBUG - management fd %d\n", localbt.mgmt_fd);

    if ((localbt.monitor_fd = monitor_connect()) < 0) {
        fprintf(stderr, "FATAL - could not connect management socket: %s\n",
                strerror(localbt.mgmt_fd * -1));
        exit(1);
    }

    fprintf(stderr, "DEBUG - monitor fd %d\n", localbt.mgmt_fd);

    /* Set up our ringbuffers */
    localbt.read_rbuf = kis_simple_ringbuf_create(4096);

    if (localbt.read_rbuf == NULL) {
        fprintf(stderr, "FATAL: Could not allocate ringbuffer\n");
        exit(1);
    }

    localbt.read_monitor_rbuf = kis_simple_ringbuf_create(4096);

    if (localbt.read_monitor_rbuf == NULL) {
        fprintf(stderr, "FATAL: Could not allocate monitor ringbuffer\n");
        exit(1);
    }

    fprintf(stderr, "DEBUG - sending controller info command\n");
    cmd_get_controller_info(&localbt);

    int max_fd = 0;

    while (1) {
        FD_ZERO(&rset);

        /* Always set read buffer */
        FD_SET(localbt.mgmt_fd, &rset);
        FD_SET(localbt.monitor_fd, &rset);

        if (max_fd < localbt.mgmt_fd)
            max_fd = localbt.mgmt_fd;
        if (max_fd < localbt.monitor_fd)
            max_fd = localbt.monitor_fd;

        if (select(max_fd + 1, &rset, NULL, NULL, NULL) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                fprintf(stderr, "FATAL: Select failed %s\n", strerror(errno));
                exit(1);
            }

            continue;
        }

        if (FD_ISSET(localbt.mgmt_fd, &rset)) {
            while (kis_simple_ringbuf_available(localbt.read_rbuf)) {
                ssize_t amt_read;
                size_t amt_buffered;
                uint8_t rbuf[512];

                if ((amt_read = read(localbt.mgmt_fd, rbuf, 512)) <= 0) {
                    if (errno != EINTR && errno != EAGAIN) {
                        fprintf(stderr, "FATAL: read failed %s\n", strerror(errno));
                        exit(1);
                    } else {
                        break;
                    }
                }

                amt_buffered = kis_simple_ringbuf_write(localbt.read_rbuf, rbuf, amt_read);

                if ((ssize_t) amt_buffered != amt_read) {
                    fprintf(stderr, "FATAL: failed to put read data in ringbuf\n");
                    exit(1);
                }

                handle_mgmt_response(&localbt);
            }
        }

        if (FD_ISSET(localbt.monitor_fd, &rset)) {
            while (kis_simple_ringbuf_available(localbt.read_monitor_rbuf)) {
                ssize_t amt_read;
                size_t amt_buffered;
                uint8_t rbuf[512];

                if ((amt_read = read(localbt.monitor_fd, rbuf, 512)) <= 0) {
                    if (errno != EINTR && errno != EAGAIN) {
                        fprintf(stderr, "FATAL: read failed %s\n", strerror(errno));
                        exit(1);
                    } else {
                        break;
                    }
                }

                amt_buffered = kis_simple_ringbuf_write(localbt.read_monitor_rbuf, rbuf, amt_read);

                if ((ssize_t) amt_buffered != amt_read) {
                    fprintf(stderr, "FATAL: failed to put read data in ringbuf\n");
                    exit(1);
                }

                handle_monitor_response(&localbt);
            }
        }

    }

    return 0;
}

