/* 
 * Copyright (C) 2013 Lars Marowsky-Bree <lmb@suse.com>
 * 
 * Based on crm_mon.c, which was:
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "sbd.h"

#include <errno.h>

#include <config.h>
#include <crm_config.h>

#include <crm/cluster.h>
#include <crm/common/mainloop.h>

//undef SUPPORT_PLUGIN
//define SUPPORT_PLUGIN 1

static int reconnect_msec = 1000;
static GMainLoop *mainloop = NULL;
static guint notify_timer = 0;

#if SUPPORT_PLUGIN
static void
sbd_plugin_membership_dispatch(cpg_handle_t handle,
                           const struct cpg_name *groupName,
                           uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    if(msg_len > 0) {
        set_servant_health(pcmk_health_online, LOG_INFO,
                           "Connected to %s", name_for_cluster_type(get_cluster_type()));
    } else {
        set_servant_health(pcmk_health_unclean, LOG_WARNING,
                           "Broken %s message", name_for_cluster_type(get_cluster_type()));
    }
    notify_parent();
    return;
}
#endif

#if SUPPORT_COROSYNC
void
sbd_cpg_membership_dispatch(cpg_handle_t handle,
                    const struct cpg_name *groupName,
                    const struct cpg_address *member_list, size_t member_list_entries,
                    const struct cpg_address *left_list, size_t left_list_entries,
                    const struct cpg_address *joined_list, size_t joined_list_entries)
{
    if(member_list_entries > 0) {
        set_servant_health(pcmk_health_online, LOG_INFO,
                           "Connected to %s", name_for_cluster_type(get_cluster_type()));
    } else {
        set_servant_health(pcmk_health_unclean, LOG_WARNING,
                           "Empty %s membership", name_for_cluster_type(get_cluster_type()));
    }
    notify_parent();
}
#endif

static gboolean
notify_timer_cb(gpointer data)
{
    enum cluster_type_e stack = get_cluster_type();
    switch (stack) {
        case pcmk_cluster_classic_ais:
            send_cluster_text(crm_class_quorum, NULL, TRUE, NULL, crm_msg_ais);
            break;

        case pcmk_cluster_corosync:
        case pcmk_cluster_cman:
            /* TODO - Make a CPG call and only call notify_parent() when we get a reply */
            notify_parent();
            break;

        default:
            break;
    }
    return TRUE;
}

static void
sbd_membership_destroy(gpointer user_data)
{
    cl_log(LOG_WARNING, "Lost connection to %s", name_for_cluster_type(get_cluster_type()));
    set_servant_health(pcmk_health_unclean, LOG_ERR, "Cluster connection terminated");
    notify_parent();
    exit(1);
}

static void
clean_up(int rc)
{
    return;
}

static void
cluster_shutdown(int nsig)
{
    clean_up(0);
}

int
servant_cluster(const char *diskname, int mode, const void* argp)
{
    crm_cluster_t cluster;
    enum cluster_type_e cluster_stack = get_cluster_type();

    switch (cluster_stack) {

#if SUPPORT_PLUGIN
        case pcmk_cluster_classic_ais:
            cluster.destroy = sbd_membership_destroy;
            cluster.cpg.cpg_deliver_fn = sbd_plugin_membership_dispatch;
            break;
#endif

#if SUPPORT_COROSYNC
        case pcmk_cluster_corosync:
        case pcmk_cluster_cman:
            cluster.destroy = sbd_membership_destroy;
            cluster.cpg.cpg_confchg_fn = sbd_cpg_membership_dispatch;
            break;
#endif
        case pcmk_cluster_unknown:
            /* Go looking for the pacemaker remote process */
            break;

        default:
            cl_log(LOG_ERR, "Unsupported cluster type: %s", name_for_cluster_type(cluster_stack));
            exit(1);
            break;
    }

    while (!crm_cluster_connect(&cluster)) {
        cl_log(LOG_INFO, "Waiting to sign in with cluster ...");
        sleep(reconnect_msec / 1000);
    }

    /* stonith_our_uname = cluster.uname; */
    /* stonith_our_uuid = cluster.uuid; */

    set_servant_health(pcmk_health_transient, LOG_INFO,
                       "Empty %s membership", name_for_cluster_type(get_cluster_type()));

    mainloop = g_main_new(FALSE);
    notify_timer = g_timeout_add(timeout_loop * 1000, notify_timer_cb, NULL);

    mainloop_add_signal(SIGTERM, cluster_shutdown);
    mainloop_add_signal(SIGINT, cluster_shutdown);

    
    g_main_run(mainloop);
    g_main_destroy(mainloop);
    
    clean_up(0);
    return 0;                   /* never reached */
}
