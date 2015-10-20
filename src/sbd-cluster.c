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

/* TODO list:
 *
 * - Trying to shutdown a node if no devices are up will fail, since SBD
 * currently uses a message via the disk to achieve this.
 *
 * - Shutting down cluster nodes while the majority of devices is down
 * will eventually take the cluster below the quorum threshold, at which
 * time the remaining cluster nodes will all immediately suicide.
 *
 */

#include "sbd.h"

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/utsname.h>

#include <config.h>

#include <crm_config.h>
#include <crm/msg_xml.h>
#include <crm/common/util.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include <crm/common/mainloop.h>

#ifdef SUPPORT_PLUGIN
#  include <crm/cluster.h>
static guint timer_id_ais = 0;
static struct timespec t_last_quorum;
static int check_ais = 0;
#endif

extern int servant_count;
enum pcmk_health cluster_healthy;
static int last_state = 0;
static int reconnect_msec = 1000;
static GMainLoop *mainloop = NULL;

static void
set_cluster_health(enum pcmk_health healthy)
{
	cluster_healthy = healthy;
	notify_parent(cluster_healthy);
}

static enum cluster_type_e cluster_stack = pcmk_cluster_unknown;

void
update_status(void)
{
    enum pcmk_health healthy = pcmk_health_unknown;
#ifdef SUPPORT_PLUGIN
    if (check_ais) {
        struct timespec	t_now;
        int quorum_age = t_now.tv_sec - t_last_quorum.tv_sec;

        clock_gettime(CLOCK_MONOTONIC, &t_now);

        if (quorum_age > (int)(timeout_io+timeout_loop)) {
            if (t_last_quorum.tv_sec != 0)
                LOGONCE(pcmk_health_transient, LOG_WARNING, "AIS: Quorum outdated");

        } else if (crm_have_quorum) {
            LOGONCE(pcmk_health_online, LOG_INFO, "AIS: We have quorum");

        } else {
            LOGONCE(pcmk_health_unclean, LOG_WARNING, "AIS: We do NOT have quorum");
        }
    }
#endif
    set_cluster_health(healthy);
}

#ifdef SUPPORT_PLUGIN
static gboolean
plugin_timer(gpointer data)
{
	if (timer_id_ais > 0) {
		g_source_remove(timer_id_ais);
	}

	send_cluster_text(crm_class_quorum, NULL, TRUE, NULL, crm_msg_ais);

	/* The timer is set in the response processing */
	return FALSE;
}

static void
plugin_membership_destroy(gpointer user_data)
{
	cl_log(LOG_ERR, "AIS connection terminated - corosync down?");

#if SUPPORT_PLUGIN
    ais_fd_sync = -1;
#endif

    /* TODO: Is recovery even worth it here? After all, this means
	 * that corosync died ... */
	exit(1);
}

static void
plugin_membership_dispatch(cpg_handle_t handle,
                          const struct cpg_name *groupName,
                          uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
	uint32_t kind = 0;
	const char *from = NULL;
	char *data = pcmk_message_common_cs(handle, nodeid, pid, msg, &kind, &from);

	if (!data) {
		return;
	}
	free(data);
	data = NULL;

	if (kind != crm_class_quorum) {
		return;
	}

	DBGLOG(LOG_INFO, "AIS quorum state: %d", (int)crm_have_quorum);
	clock_gettime(CLOCK_MONOTONIC, &t_last_quorum);
        update_status();

	timer_id_ais = g_timeout_add(timeout_loop * 1000, plugin_timer, NULL);
	return;
}
#endif


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
    crm_cluster_t crm_cluster;

    cluster_stack = get_cluster_type();

#ifdef SUPPORT_PLUGIN

	if (cluster_stack != pcmk_cluster_classic_ais) {
		check_ais = 0;
	} else {
		check_ais = 1;
		cl_log(LOG_INFO, "Legacy plug-in detected, AIS quorum check enabled");
		if(is_openais_cluster()) {
		    crm_cluster.destroy = plugin_membership_destroy;
		    crm_cluster.cpg.cpg_deliver_fn = plugin_membership_dispatch;
		    /* crm_cluster.cpg.cpg_confchg_fn = pcmk_cpg_membership; TODO? */
		    crm_cluster.cpg.cpg_confchg_fn = NULL;
		}

		while (!crm_cluster_connect(&crm_cluster)) {
			cl_log(LOG_INFO, "Waiting to sign in with cluster ...");
			sleep(reconnect_msec / 1000);
		}
	}

	if (check_ais) {
		timer_id_ais = g_timeout_add(timeout_loop * 1000, plugin_timer, NULL);
	}
#endif
	mainloop = g_main_new(FALSE);

	mainloop_add_signal(SIGTERM, cluster_shutdown);
	mainloop_add_signal(SIGINT, cluster_shutdown);

	g_main_run(mainloop);
	g_main_destroy(mainloop);

	clean_up(0);
	return 0;                   /* never reached */
}


