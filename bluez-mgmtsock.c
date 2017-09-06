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
    unsigned int devid;

    /* Read ringbuf */
    kis_simple_ringbuf_t *read_rbuf;
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
int cmd_start_discovery(local_bluetooth_t *localbt, uint8_t scan_type) {
    struct mgmt_cp_start_discovery cp;

    memset(&cp, 0, sizeof(cp));
    cp.type = scan_type;

    return mgmt_write_request(localbt->mgmt_fd, MGMT_OP_START_DISCOVERY, 
            localbt->devid, sizeof(cp), &cp);
}

/* Probe the controller */
int cmd_get_controller_info(local_bluetooth_t *localbt) {
    return mgmt_write_request(localbt->mgmt_fd, MGMT_OP_READ_INFO, localbt->devid, 0, NULL);
}

/* Handle controller info response */
void resp_controller_info(local_bluetooth_t *localbt, uint8_t status, uint16_t len, 
        const void *param) {
    const struct mgmt_rp_read_info *rp = (struct mgmt_rp_read_info *) param;
    char bdaddr[BDADDR_STR_LEN];

    if (len < sizeof(struct mgmt_rp_read_info)) {
        fprintf(stderr, "DEBUG - insufficient data in controller info\n");
        return;
    }

    bdaddr_to_string(rp->bdaddr.b, bdaddr);

    fprintf(stderr, "INTERFACE - Got interface info for %s\n", bdaddr);

    if (rp->supported_settings & MGMT_SETTING_BREDR) 
        fprintf(stderr, "    Supports EDR/SDR\n");
    if (rp->supported_settings & MGMT_SETTING_LE) 
        fprintf(stderr, "    Supports BTLE\n");


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

        if (ropcode == MGMT_EV_CMD_COMPLETE) {
            if (rlength < sizeof(struct mgmt_ev_cmd_complete)) {
                fprintf(stderr, "debug - status response too small for response rec\n");
                free(evt);
                continue;
            }

            crec = (struct mgmt_ev_cmd_complete *) evt->param;

            ropcode = le16toh(crec->opcode);

            fprintf(stderr, "COMMAND - command complete 0x%x hci%u len %u\n", 
                    ropcode, rindex, rlength);

            /* Handle the different opcodes */
            switch (ropcode) {
                case MGMT_OP_READ_INFO:
                    resp_controller_info(localbt, crec->status, 
                            rlength - sizeof(struct mgmt_ev_cmd_complete),
                            crec->data);
                    break;
                default:
                    fprintf(stderr, "DEBUG - Unhandled command\n");
            }
        } else if (ropcode == MGMT_EV_CMD_STATUS) {
            fprintf(stderr, "DEBUG - command status hci%u len %u\n", rindex, rlength);
        } else {
            fprintf(stderr, "DEBUG - event 0x%x hci%u len %u\n", ropcode, rindex, rlength);
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

    /* Set up our ringbuffers */
    localbt.read_rbuf = kis_simple_ringbuf_create(4096);

    if (localbt.read_rbuf == NULL) {
        fprintf(stderr, "FATAL: Could not allocate ringbuffers\n");
        exit(1);
    }

    fprintf(stderr, "DEBUG - sending controller info command\n");
    cmd_get_controller_info(&localbt);

    while (1) {
        FD_ZERO(&rset);

        /* Always set read buffer */
        FD_SET(localbt.mgmt_fd, &rset);

        if (select(localbt.mgmt_fd + 1, &rset, NULL, NULL, NULL) < 0) {
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

    }

    return 0;
}

