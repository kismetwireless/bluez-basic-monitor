/* Simplified bluez monitoring interface
 *
 *  Originally based on bluez-5.46 client code, 
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <string.h>

#include <glib.h>

#include "gdbus/gdbus.h"

static GMainLoop *main_loop;
static DBusConnection *dbus_connection;

static GDBusProxy *agent_manager;

struct gdbus_bluez_adapter {
    GDBusProxy *proxy;
    GList *devices;
};


static void connect_handler(DBusConnection *connection, void *user_data) {
    fprintf(stderr, "DEBUG - connect_handler\n");
}

static void handle_device(GDBusProxy *proxy, const char *description) {
    DBusMessageIter iter;
    const char *address, *alias;

    if (!g_dbus_proxy_get_property(proxy, "Address", &iter)) {
        return;
    }

    dbus_message_iter_get_basic(&iter, &address);

    if (g_dbus_proxy_get_property(proxy, "Alias", &iter)) {
        dbus_message_iter_get_basic(&iter, &alias);
    } else {
        alias = NULL;
    }

    fprintf(stderr, "DEBUG - device address %s alias %s\n", address, alias);
}

static void dbus_proxy_added(GDBusProxy *proxy, void *user_data) {
    const char *interface;

    interface = g_dbus_proxy_get_interface(proxy);

    if (!strcmp(interface, "org.bluez.Device1")) {
        // device_added(proxy);
        fprintf(stderr, "debug - proxy - device added\n");
    } else if (!strcmp(interface, "org.bluez.Adapter1")) {
        // adapter_added(proxy);
        fprintf(stderr, "debug - adapter added\n");
    }
}

static void dbus_proxy_removed(GDBusProxy *proxy, void *user_data) {
    const char *interface;

    interface = g_dbus_proxy_get_interface(proxy);

    if (!strcmp(interface, "org.bluez.Device1")) {
        // device_removed(proxy);
        fprintf(stderr, "debug - proxy - device removed\n");
    } else if (!strcmp(interface, "org.bluez.Adapter1")) {
        // adapter_removed(proxy);
        fprintf(stderr, "debug - proxy - adapter removed\n");
    }
}

static void dbus_property_changed(GDBusProxy *proxy, const char *name,
        DBusMessageIter *iter, void *user_data) {

    const char *interface;

    interface = g_dbus_proxy_get_interface(proxy);

    if (!strcmp(interface, "org.bluez.Device1")) {
        DBusMessageIter addr_iter;
        char *str;

        if (g_dbus_proxy_get_property(proxy, "Address", &addr_iter) == TRUE) {
            const char *address;
            dbus_message_iter_get_basic(&addr_iter, &address);

            fprintf(stderr, "debug - property changed device addr %s\n", address);
        } 
    } else if (!strcmp(interface, "org.bluez.Adapter1")) {
        DBusMessageIter addr_iter;
        char *str;

        if (g_dbus_proxy_get_property(proxy, "Address", &addr_iter) == TRUE) {
            const char *address;

            dbus_message_iter_get_basic(&addr_iter, &address);

            fprintf(stderr, "debug - controller changed %s\n", address);
        }
    }
}

static void dbus_client_ready(GDBusClient *client, void *user_data) {
    const char *method = "StartDiscovery";

    fprintf(stderr, "debug - client ready\n");

}

int main(int argc, char *argv[]) {
    GError *error = NULL;
    GDBusClient *client;

    main_loop = g_main_loop_new(NULL, FALSE);
    dbus_connection = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);
    g_dbus_attach_object_manager(dbus_connection);

    client = g_dbus_client_new(dbus_connection, "org.bluez", "/org/bluez");

    g_dbus_client_set_proxy_handlers(client, dbus_proxy_added, 
            dbus_proxy_removed, dbus_property_changed, NULL);

    g_dbus_client_set_ready_watch(client, dbus_client_ready, NULL);

    g_main_loop_run(main_loop);

    g_dbus_client_unref(client);
    dbus_connection_unref(dbus_connection);
    g_main_loop_unref(main_loop);

    return 0;
}

