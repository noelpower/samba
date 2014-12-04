/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (C)
 *
 *  Based on fssd.c:
 *  Copyright (c)  2012 David Disseldorp
 *  Copyright (c)  2016 Noel Power
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#include "serverid.h"
#include "ntdomain.h"
#include "messages.h"

#include "rpc_server/srv_pipe.h"
#include "rpc_server/rpc_server.h"
#include "lib/tsocket/tsocket.h"
#include "lib/util/tevent_ntstatus.h"
#include "rpc_server/wsp/wsp_gss.h"
#include "rpc_server/wsp/wsp_srv_tracker-sparql.h"
#include "rpc_server/rawpipe.h"
#include <signal.h>

#define DAEMON_NAME "wspd"

struct wspd_state
{
	struct gss_state *gss_state;
	struct wspd_client_state *client_state;
};

void start_wspd(struct tevent_context *ev_ctx,
		struct messaging_context *msg_ctx, bool is_external);

static void wspd_reopen_logs(void)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *lfile = NULL;
	int rc;

	lfile = lp_logfile(NULL, lp_sub);
	if (lfile == NULL || lfile[0] == '\0') {
		rc = asprintf(&lfile, "%s/log.%s", get_dyn_LOGFILEBASE(), DAEMON_NAME);
		if (rc > 0) {
			lp_set_logfile(lfile);
			SAFE_FREE(lfile);
		}
	} else {
		if (strstr(lfile, DAEMON_NAME) == NULL) {
			rc = asprintf(&lfile, "%s.%s",
				lp_logfile(NULL, lp_sub), DAEMON_NAME);
			if (rc > 0) {
				lp_set_logfile(lfile);
				SAFE_FREE(lfile);
			}
		}
	}

	reopen_logs();
}

static void wspd_smb_conf_updated(struct messaging_context *msg,
				  void *private_data,
				  uint32_t msg_type,
				  struct server_id server_id,
				  DATA_BLOB *data)
{
	DBG_DEBUG("Got message saying smb.conf was updated. Reloading.\n");
	change_to_root_user();
	lp_load_with_shares(get_dyn_CONFIGFILE());
	wspd_reopen_logs();
}

static void wspd_sig_term_handler(struct tevent_context *ev,
				  struct tevent_signal *se,
				  int signum,
				  int count,
				  void *siginfo,
				  void *private_data)
{
	DBG_ERR("got sigterm!!\n");
	exit_server_cleanly("terminationstruct tevent_context *ev_ctx signal");
}

static void wspd_setup_sig_term_handler(struct tevent_context *ev_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGTERM, 0,
			       wspd_sig_term_handler,
			       NULL);
	if (se == NULL) {
		exit_server("failed to setup SIGTERM handler");
	}
}

static void wspd_sig_hup_handler(struct tevent_context *ev,
				    struct tevent_signal *se,
				    int signum,
				    int count,
				    void *siginfo,
				    void *private_data)
{
	change_to_root_user();

	DBG_NOTICE("reopening logs after SIGHUP\n");
	wspd_reopen_logs();
}

static void wspd_setup_sig_hup_handler(struct tevent_context *ev_ctx,
				       struct messaging_context *msg_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGHUP, 0,
			       wspd_sig_hup_handler,
			       msg_ctx);
	if (se == NULL) {
		exit_server("failed to setup SIGHUP handler");
	}
}

static void pipe_destroyed(void *private_data);
static void* wsp_pipe_opened(struct dcerpc_ncacn_conn *npc,
			    void *private_data)
{
	struct gss_state *gss_state = talloc_get_type_abort(private_data,
							struct gss_state);
	struct wspd_state *wsp_state = talloc_zero(gss_state, struct wspd_state);
	DBG_NOTICE("starting wsp server loop \n");

	wsp_state->gss_state = gss_state;

	if (!gss_init(gss_state)) {
		/*
		 * #FIXME should we return bool and have an out param or
		 * abort or....
		 */
		DBG_ERR("Failed to initialise the gss\n");
		exit(1);
	}
	wsp_state->client_state = create_client_state(npc, gss_state);
	return wsp_state;
}

static struct tevent_req *process_wsp_pipe_request(TALLOC_CTX *ctx,
				struct dcerpc_ncacn_conn *npc,
				void *state)
{
	struct tevent_req *subreq;
	struct wspd_state *wspd_state =
			talloc_get_type_abort(state,
					      struct wspd_state);
        TALLOC_CTX *frame = talloc_stackframe();
	subreq = do_wsp_request_send(ctx, wspd_state->client_state);

	if (!subreq) {
		goto done;
	}
done:
        TALLOC_FREE(frame);
	return subreq;
}

static void pipe_destroyed(void *private_data)
{
	struct wspd_state *wsp_state = talloc_get_type_abort(private_data,
							     struct wspd_state);
	client_disconnected(wsp_state->client_state);
	TALLOC_FREE(wsp_state);
}

void start_wspd(struct tevent_context *ev_ctx,
		struct messaging_context *msg_ctx,
		bool is_external)
{
	NTSTATUS status;
	struct gss_state *gss_state;
	pid_t pid;
	int rc;

	gss_state = gss_state_create(ev_ctx, msg_ctx);
	common_rawpipe_register("msftewds", FILE_TYPE_MESSAGE_MODE_PIPE,
				wsp_pipe_opened,
				pipe_destroyed,
				process_wsp_pipe_request,
				gss_state);
	if (is_external == false) {
		DBG_NOTICE("WSP is internal\n");
		return;
	}
	DBG_NOTICE("Forking WSP Daemon\n");

	pid = fork();

	if (pid == -1) {
		DBG_ERR("failed to fork wsp daemon [%s], "
			  "aborting ...\n", strerror(errno));
		exit(1);
	}

	if (pid) {
		/* parent */
		return;
	}

	/* child */
	status = reinit_after_fork(msg_ctx,
				   ev_ctx,
				   true, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("reinit_after_fork() failed\n");
		smb_panic("reinit_after_fork() failed");
	}

	wspd_reopen_logs();

	wspd_setup_sig_term_handler(ev_ctx);
	wspd_setup_sig_hup_handler(ev_ctx, msg_ctx);

	messaging_register(msg_ctx,
			   ev_ctx,
			   MSG_SMB_CONF_UPDATED,
			   wspd_smb_conf_updated);

	/*
	 * here is where the init and shutdown callbacks were handled
	 * for rpc, need to figure out what similar thing I can do
	 */
	status = dcesrv_setup_ncacn_np_socket("msftewds", ev_ctx, msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to open wsp named pipe!\n");
		exit(1);
	}
	DBG_NOTICE("WSP Daemon Started (%d)\n", getpid());
	/* loop forever */
	rc = tevent_loop_wait(ev_ctx);

	TALLOC_FREE(gss_state);
	/* should not be reached */
	DBG_ERR("tevent_loop_wait() exited with %d - %s\n",
		 rc, (rc == 0) ? "out of events" : strerror(errno));
	DBG_ERR("server exiting\n");
	exit(1);
}
