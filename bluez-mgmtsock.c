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

/* Target interface */
const char *bt_interface;
const char *bt_interface_address;

/* Are we already controlling it */
int state_powering_on = 0;
int state_scanning_on = 0;

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

/* Incoming commands */
typedef struct {
    uint16_t event_code __attribute__((packed));
    uint16_t controller_index __attribute__((packed));
    uint8_t parameter[0];
} bluez_event_t;

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
int mgmt_write_request(kis_simple_ringbuf_t *ringbuf, uint16_t opcode, uint16_t index, 
        uint16_t length, const void *param) {
    bluez_mgmt_command_t *cmd;
    size_t pksz = sizeof(bluez_mgmt_command_t) + length;

    if (opcode == 0) {
        return -1;
    }

    if (length > 0 && param == NULL) {
        return -1;
    }

    if (kis_simple_ringbuf_available(ringbuf) < pksz) {
        return -1;
    }

    cmd = (bluez_mgmt_command_t *) malloc(pksz);

    cmd->opcode = htole16(opcode);
    cmd->index = htole16(index);
    cmd->length = htole16(length);

    if (length != 0 && param != NULL) {
        memcpy(cmd->param, param, length);
    }

    if (kis_simple_ringbuf_write(ringbuf, cmd, pksz) != pksz) {
        return -1;
    }

    free(cmd);

    return 1;
}


/* Initiate finding a device */
int cmd_start_discovery(kis_simple_ringbuf_t *ringbuf, int index, uint8_t scan_type) {
    struct mgmt_cp_start_discovery cp;

    memset(&cp, 0, sizeof(cp));
    cp.type = scan_type;

    return mgmt_write_request(ringbuf, MGMT_OP_START_DISCOVERY, index, sizeof(cp), &cp);
}

void handle_mgmt_event(kis_simple_ringbuf_t *ringbuf, int index) {

}

int main(int argc, char *argv[]) {
    /* Local socket info for extracting MAC address of hci interface */
    int hci_sock;
    static struct hci_dev_info di;
    char bdaddr[18];

    /* bluez management interface socket */
    int mgmt_fd;
    unsigned int devid = 0;

    /* Ringbuffer and select mgmt stuff */
    fd_set rset, wset;
    kis_simple_ringbuf_t *write_rbuf;
    kis_simple_ringbuf_t *read_rbuf;

    if (argc < 2) {
        fprintf(stderr, "FATAL - expected %s [interface]\n", argv[0]);
        exit(1);
    }

    bt_interface = strdup(argv[1]);

    fprintf(stderr, "DEBUG - Targetting interface %s\n", bt_interface);

    if ((hci_sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
        fprintf(stderr, "FATAL - %s couldn't create HCI socket: %s\n", 
                bt_interface, strerror(errno));
        exit(1);
    }

    if (sscanf(bt_interface, "hci%u", &devid) != 1) {
        fprintf(stderr, "FATAL - %s couldn't parse device id\n", bt_interface);
        exit(1);
    }

    di.dev_id = devid;

    if (ioctl(hci_sock, HCIGETDEVINFO, (void *) &di)) {
        fprintf(stderr, "FATAL - %s couldn't get device info\n", bt_interface);
        exit(1);
    }

    snprintf(bdaddr, 18, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
            di.bdaddr.b[5], di.bdaddr.b[4], di.bdaddr.b[3],
            di.bdaddr.b[2], di.bdaddr.b[1], di.bdaddr.b[0]);

    fprintf(stderr, "DEBUG - %s %s\n", bt_interface, bdaddr);

    bt_interface_address = strdup(bdaddr);

    close(hci_sock);

    if (linux_sys_get_bt_rfkill(bt_interface, LINUX_BT_RFKILL_TYPE_HARD)) {
        fprintf(stderr, "FATAL - %s rfkill hardkill blocked\n", bt_interface);
        exit(1);
    } else {
        fprintf(stderr, "DEBUG - %s rfkill hardkill unblocked\n", bt_interface);
    }

    if (linux_sys_get_bt_rfkill(bt_interface, LINUX_BT_RFKILL_TYPE_SOFT)) {
        fprintf(stderr, "DEBUG - %s rfkill softkill blocked\n", bt_interface);

        if (linux_sys_clear_bt_rfkill(bt_interface) < 0) {
            fprintf(stderr, "DEBUG - %s rfkill softkill, could not unblock", bt_interface);
            exit(1);
        }
    } else {
        fprintf(stderr, "DEBUG - %s rfkill softkill unblocked\n", bt_interface);
    }

    if ((mgmt_fd = mgmt_connect()) < 0) {
        fprintf(stderr, "FATAL - could not connect management socket: %s\n",
                strerror(mgmt_fd * -1));
        exit(1);
    }

    fprintf(stderr, "DEBUG - management fd %d\n", mgmt_fd);

    /* Set up our ringbuffers */
    write_rbuf = kis_simple_ringbuf_create(4096);
    read_rbuf = kis_simple_ringbuf_create(4096);

    if (write_rbuf == NULL || read_rbuf == NULL) {
        fprintf(stderr, "FATAL: Could not allocate ringbuffers\n");
        exit(1);
    }

    fprintf(stderr, "DEBUG - sending start discovery command\n");
    cmd_start_discovery(write_rbuf, devid, SCAN_TYPE_DUAL);

    while (1) {
        fprintf(stderr, "DEBUG - select loop\n");

        FD_ZERO(&rset);
        FD_ZERO(&wset);

        /* Always set read buffer */
        FD_SET(mgmt_fd, &rset);

        if (kis_simple_ringbuf_used(write_rbuf)) {
            fprintf(stderr, "DEBUG - pending write data\n");
            FD_SET(mgmt_fd, &wset);
        }

        if (select(mgmt_fd + 1, &rset, &wset, NULL, NULL) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                fprintf(stderr, "FATAL: Select failed %s\n", strerror(errno));
                exit(1);
            }

            continue;
        }

        if (FD_ISSET(mgmt_fd, &rset)) {
            fprintf(stderr, "DEBUG - rset set\n");

            while (kis_simple_ringbuf_available(read_rbuf)) {
                ssize_t amt_read;
                size_t amt_buffered;
                uint8_t rbuf[512];

                if ((amt_read = read(mgmt_fd, rbuf, 512)) <= 0) {
                    if (errno != EINTR && errno != EAGAIN) {
                        fprintf(stderr, "FATAL: read failed %s\n", strerror(errno));
                        exit(1);
                    } else {
                        break;
                    }
                }

                amt_buffered = kis_simple_ringbuf_write(read_rbuf, rbuf, amt_read);

                if ((ssize_t) amt_buffered != amt_read) {
                    fprintf(stderr, "FATAL: failed to put read data in ringbuf\n");
                    exit(1);
                }

                fprintf(stderr, "DEBUG - got %lu from mgmtsock\n", amt_buffered);

                /* TODO process rx data */
            }
        }

        if (FD_ISSET(mgmt_fd, &wset)) {
            fprintf(stderr, "DEBUG - wset set\n");

            ssize_t written_sz;
            size_t peek_sz;
            size_t peeked_sz;
            uint8_t *peek_buf;

            peek_sz = kis_simple_ringbuf_used(write_rbuf);

            if (peek_sz == 0)
                continue;

            peek_buf = (uint8_t *) malloc(peek_sz);

            if (peek_buf == NULL) {
                fprintf(stderr, "FATAL - could not allocate peek buffer for writing\n");
                exit(1);
            }

            peeked_sz = kis_simple_ringbuf_peek(write_rbuf, peek_buf, peek_sz);

            fprintf(stderr, "DEBUG - peeked %lu buffer %p\n", peeked_sz, peek_buf);

            /*
            if ((written_sz = write(mgmt_fd, peek_buf, peeked_sz)) < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    fprintf(stderr, "FATAL - Failed to write to mgmt sock: %s\n",
                            strerror(errno));
                    free(peek_buf);
                    exit(1);
                }
            }
            */

            if ((written_sz = send(mgmt_fd, peek_buf, peeked_sz, 0)) < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    fprintf(stderr, "FATAL - Failed to send to mgmt sock: %s\n",
                            strerror(errno));
                    free(peek_buf);
                    exit(1);
                }
            }

            free(peek_buf);

            kis_simple_ringbuf_read(write_rbuf, NULL, (size_t) written_sz);

            fprintf(stderr, "DEBUG - wrote %lu\n", written_sz);
        }
    }

    return 0;
}

