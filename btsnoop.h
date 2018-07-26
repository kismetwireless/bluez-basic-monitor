/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __BTSNOOP_H__
#define __BTSNOOP_H__

#include <stdint.h>

#define BTSNOOP_FORMAT_INVALID		0
#define BTSNOOP_FORMAT_HCI		1001
#define BTSNOOP_FORMAT_UART		1002
#define BTSNOOP_FORMAT_BCSP		1003
#define BTSNOOP_FORMAT_3WIRE		1004
#define BTSNOOP_FORMAT_MONITOR		2001
#define BTSNOOP_FORMAT_SIMULATOR	2002

#define BTSNOOP_FLAG_PKLG_SUPPORT	(1 << 0)

#define BTSNOOP_OPCODE_NEW_INDEX	0
#define BTSNOOP_OPCODE_DEL_INDEX	1
#define BTSNOOP_OPCODE_COMMAND_PKT	2
#define BTSNOOP_OPCODE_EVENT_PKT	3
#define BTSNOOP_OPCODE_ACL_TX_PKT	4
#define BTSNOOP_OPCODE_ACL_RX_PKT	5
#define BTSNOOP_OPCODE_SCO_TX_PKT	6
#define BTSNOOP_OPCODE_SCO_RX_PKT	7
#define BTSNOOP_OPCODE_OPEN_INDEX	8
#define BTSNOOP_OPCODE_CLOSE_INDEX	9
#define BTSNOOP_OPCODE_INDEX_INFO	10
#define BTSNOOP_OPCODE_VENDOR_DIAG	11
#define BTSNOOP_OPCODE_SYSTEM_NOTE	12
#define BTSNOOP_OPCODE_USER_LOGGING	13
#define BTSNOOP_OPCODE_CTRL_OPEN	14
#define BTSNOOP_OPCODE_CTRL_CLOSE	15
#define BTSNOOP_OPCODE_CTRL_COMMAND	16
#define BTSNOOP_OPCODE_CTRL_EVENT	17

#define BTSNOOP_MAX_PACKET_SIZE		(1486 + 4)

#define BTSNOOP_TYPE_PRIMARY	0
#define BTSNOOP_TYPE_AMP	1

#define BTSNOOP_BUS_VIRTUAL	0
#define BTSNOOP_BUS_USB		1
#define BTSNOOP_BUS_PCCARD	2
#define BTSNOOP_BUS_UART	3
#define BTSNOOP_BUS_RS232	4
#define BTSNOOP_BUS_PCI		5
#define BTSNOOP_BUS_SDIO	6
#define BTSNOOP_BUS_SPI		7
#define BTSNOOP_BUS_I2C		8
#define BTSNOOP_BUS_SMD		9

struct btsnoop_opcode_new_index {
	uint8_t  type;
	uint8_t  bus;
	uint8_t  bdaddr[6];
	char     name[8];
} __attribute__((packed));

struct btsnoop_opcode_index_info {
	uint8_t  bdaddr[6];
	uint16_t manufacturer;
} __attribute__((packed));

#define BTSNOOP_PRIORITY_EMERG		0
#define BTSNOOP_PRIORITY_ALERT		1
#define BTSNOOP_PRIORITY_CRIT		2
#define BTSNOOP_PRIORITY_ERR		3
#define BTSNOOP_PRIORITY_WARNING	4
#define BTSNOOP_PRIORITY_NOTICE		5
#define BTSNOOP_PRIORITY_INFO		6
#define BTSNOOP_PRIORITY_DEBUG		7

struct btsnoop_opcode_user_logging {
	uint8_t  priority;
	uint8_t  ident_len;
} __attribute__((packed));

struct btsnoop;

#define BT_EIR_FLAGS			0x01
#define BT_EIR_UUID16_SOME		0x02
#define BT_EIR_UUID16_ALL		0x03
#define BT_EIR_UUID32_SOME		0x04
#define BT_EIR_UUID32_ALL		0x05
#define BT_EIR_UUID128_SOME		0x06
#define BT_EIR_UUID128_ALL		0x07
#define BT_EIR_NAME_SHORT		0x08
#define BT_EIR_NAME_COMPLETE		0x09
#define BT_EIR_TX_POWER			0x0a
#define BT_EIR_CLASS_OF_DEV		0x0d
#define BT_EIR_SSP_HASH_P192		0x0e
#define BT_EIR_SSP_RANDOMIZER_P192	0x0f
#define BT_EIR_DEVICE_ID		0x10
#define BT_EIR_SMP_TK			0x10
#define BT_EIR_SMP_OOB_FLAGS		0x11
#define BT_EIR_SLAVE_CONN_INTERVAL	0x12
#define BT_EIR_SERVICE_UUID16		0x14
#define BT_EIR_SERVICE_UUID128		0x15
#define BT_EIR_SERVICE_DATA		0x16
#define BT_EIR_PUBLIC_ADDRESS		0x17
#define BT_EIR_RANDOM_ADDRESS		0x18
#define BT_EIR_GAP_APPEARANCE		0x19
#define BT_EIR_ADVERTISING_INTERVAL	0x1a
#define BT_EIR_LE_DEVICE_ADDRESS	0x1b
#define BT_EIR_LE_ROLE			0x1c
#define BT_EIR_SSP_HASH_P256		0x1d
#define BT_EIR_SSP_RANDOMIZER_P256	0x1e
#define BT_EIR_SERVICE_UUID32		0x1f
#define BT_EIR_SERVICE_DATA32		0x20
#define BT_EIR_SERVICE_DATA128		0x21
#define BT_EIR_LE_SC_CONFIRM_VALUE	0x22
#define BT_EIR_LE_SC_RANDOM_VALUE	0x23
#define BT_EIR_URI			0x24
#define BT_EIR_INDOOR_POSITIONING	0x25
#define BT_EIR_TRANSPORT_DISCOVERY	0x26
#define BT_EIR_LE_SUPPORTED_FEATURES	0x27
#define BT_EIR_CHANNEL_MAP_UPDATE_IND	0x28
#define BT_EIR_3D_INFO_DATA		0x3d
#define BT_EIR_MANUFACTURER_DATA	0xff

#endif

