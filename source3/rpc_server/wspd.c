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
#include "libcli/named_pipe_auth/npa_tstream.h"
#include "librpc/gen_ndr/auth.h"

#include <signal.h>

#define DAEMON_NAME "wspd"

void start_wspd(struct tevent_context *ev_ctx,
		struct messaging_context *msg_ctx);

struct wspd_state
{
	struct gss_state *gss_state;
	struct wspd_client_state *client_state;
};

struct listen_state {
	int fd;
	char *name;
	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	void *private_data;
};

struct wsp_pipe_send_state {
	DATA_BLOB buffer;
	struct iovec in;
	struct tstream_context *stream;
	struct tevent_context *ev;
};

static int named_pipe_destructor(struct named_pipe_client *npc)
{
	if (npc->term_fn) {
		npc->term_fn(npc->private_data);
	}
	return 0;
}

static void named_pipe_wsp_accept_done(struct tevent_req *subreq);

static void named_pipe_wsp_accept_function(struct tevent_context *ev_ctx,
			        struct messaging_context *msg_ctx,
				const char *pipe_name, int fd,
				named_pipe_termination_fn *term_fn,
				void *private_data)
{
	struct named_pipe_client *npc;
	struct tstream_context *plain;
	struct tevent_req *subreq;
	int ret;

	npc = talloc_zero(ev_ctx, struct named_pipe_client);
	if (!npc) {
		DBG_ERR("Out of memory!\n");
		close(fd);
		return;
	}

	npc->pipe_name = talloc_strdup(npc, pipe_name);
	if (npc->pipe_name == NULL) {
		DBG_ERR("Out of memory!\n");
		TALLOC_FREE(npc);
		close(fd);
		return;
	}
	npc->ev = ev_ctx;
	npc->msg_ctx = msg_ctx;
	npc->term_fn = term_fn;
	npc->private_data = private_data;
	talloc_set_destructor(npc, named_pipe_destructor);

	/* make sure socket is in NON blocking state */
	ret = set_blocking(fd, false);
	if (ret != 0) {
		DBG_ERR("Failed to make socket non-blocking\n");
		TALLOC_FREE(npc);
		close(fd);
		return;
	}

	ret = tstream_bsd_existing_socket(npc, fd, &plain);
	if (ret != 0) {
		DBG_ERR("Failed to create tstream socket\n");
		TALLOC_FREE(npc);
		close(fd);
		return;
	}

	npc->file_type = FILE_TYPE_MESSAGE_MODE_PIPE;
	npc->device_state = 0xff | 0x0400 | 0x0100;
	npc->allocation_size = 4096;

	subreq = tstream_npa_accept_existing_send(npc, npc->ev, plain,
						  npc->file_type,
						  npc->device_state,
						  npc->allocation_size);
	if (!subreq) {
		DBG_ERR("Failed to start async accept procedure\n");
		TALLOC_FREE(npc);
		close(fd);
		return;
	}
	tevent_req_set_callback(subreq, named_pipe_wsp_accept_done, npc);
}

static void* wsp_pipe_opened(struct named_pipe_client *npc,
			    void *private_data);
static void wsp_pipe_destroyed(void *private_data);

static NTSTATUS wsp_pipe_read_recv(struct tevent_req *req,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *buffer)
{
	struct wsp_pipe_send_state *state = tevent_req_data(req,
						struct wsp_pipe_send_state);
	NTSTATUS status;

	DBG_DEBUG("wsp_pipe_read_recv\n");
	if (tevent_req_is_nterror(req, &status)) {
		DBG_ERR("wsp_pipe_read_recv nterror %s\n", nt_errstr(status));
		tevent_req_received(req);
		return status;
	}

	if (buffer) {
		buffer->data = talloc_move(mem_ctx, &state->buffer.data);
		buffer->length = state->buffer.length;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static void read_wsp_pipe_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct wsp_pipe_send_state *state =
		tevent_req_data(req, struct wsp_pipe_send_state);
	int ret;
	int sys_errno;
	int to_read;
	ssize_t ofs = 0;
	NTSTATUS status;

	DBG_DEBUG("read_wsp_pipe_done\n");
	ret = tstream_readv_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		status = map_nt_error_from_unix_common(sys_errno);
		tevent_req_nterror(req, status);
		return;
	}
	/*
	 * initial read is just for waiting for at lest 1 byte, see if
	 * there is any additional bytes to read.
	 */
	to_read = tstream_pending_bytes(state->stream);
	if (!to_read) {
		/* we're done */
		tevent_req_done(req);
		return;
	}

	ofs = state->buffer.length;
	state->buffer.data = talloc_realloc(state,
					   state->buffer.data,
					   uint8_t,
					   to_read + ofs);
	state->buffer.length = to_read + state->buffer.length;
	state->in.iov_base = (void *) (state->buffer.data + ofs);
	state->in.iov_len = state->buffer.length - ofs;
	subreq = tstream_readv_send(state,
				    state->ev,
				    state->stream,
				    &state->in,
				    1);
	if (tevent_req_nomem(subreq, req)) {
		tevent_req_post(req, state->ev);
		return;
	}

	tevent_req_set_callback(subreq, read_wsp_pipe_done, req);
}

static struct tevent_req *read_wsp_pipe_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct tstream_context *stream)
{
	struct tevent_req *req;
	struct wsp_pipe_send_state *state;
	struct tevent_req *subreq;
	req = tevent_req_create(mem_ctx, &state,
				struct wsp_pipe_send_state);
	if (req == NULL) {
		return NULL;
	}

	state->buffer.length = 1;
	state->buffer.data = talloc_zero_array(mem_ctx,
					       uint8_t,
					       state->buffer.length);
	state->stream = stream;
	state->in.iov_base = state->buffer.data;
	state->in.iov_len = state->buffer.length;
	state->ev = ev;
	DBG_DEBUG("read_wsp_pipe_send stream %p\n", stream);
	subreq = tstream_readv_send(state, ev,
					stream,
					&state->in,
					1);
	tevent_req_set_callback(subreq, read_wsp_pipe_done, req);
	return req;
}

void wsp_pipe_process(struct tevent_req *subreq);
static struct tevent_req *wsp_server_loop(struct named_pipe_client *npc)
{
	struct tevent_req *subreq;

	subreq = read_wsp_pipe_send(npc, npc->ev, npc->tstream);
	if (!subreq) {
		DBG_ERR("Failed to start receving packets\n");
		goto fail;
	}
	tevent_req_set_callback(subreq, wsp_pipe_process, npc);
fail:
	return subreq;
}

static void process_wsp_pipe_request_done(struct tevent_req *subreq);
static struct tevent_req *process_wsp_pipe_request(TALLOC_CTX *mem_ctx,
					struct named_pipe_client *npc);

void wsp_pipe_process(struct tevent_req *subreq)
{
	struct named_pipe_client *npc =
		tevent_req_callback_data(subreq, struct named_pipe_client);
	DATA_BLOB recv_buffer = data_blob_null;
	NTSTATUS status;

	DBG_DEBUG("wsp_pipe_process \n");
	status = wsp_pipe_read_recv(subreq, npc, &recv_buffer);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	npc->p->in_data.pdu_needed_len = 0;
	npc->p->in_data.pdu = recv_buffer;

	subreq = process_wsp_pipe_request(npc->p->mem_ctx, npc);
	tevent_req_set_callback(subreq, process_wsp_pipe_request_done, npc);
	talloc_free(recv_buffer.data);
	return;
fail:
	DBG_ERR("Fatal error(%s). "
		  "Terminating client(%s) connection!\n",
		  nt_errstr(status), npc->client_name);
	/* terminate client connection */
	talloc_free(npc);
	return;
}

static void wsp_pipe_process_done(struct tevent_req *subreq);
static void process_wsp_pipe_request_done(struct tevent_req *subreq)
{
	uint32_t to_send;
	struct named_pipe_client *npc;
	struct _output_data *out;
	NTSTATUS status;
	DBG_DEBUG("process_wsp_pipe_done\n");
	npc = tevent_req_callback_data(subreq, struct named_pipe_client);
	out = &npc->p->out_data;
	to_send = out->rdata.length;
	TALLOC_FREE(subreq);
	if (to_send) {
		npc->iov = talloc_zero(npc, struct iovec);
		if (!npc->iov) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		npc->count = 1;

		npc->iov[0].iov_len = to_send;
		npc->iov[0].iov_base = out->rdata.data;
		DBG_DEBUG("sending %lu bytes to tstream !!\n",
		      npc->iov[0].iov_len );
		subreq = tstream_writev_queue_send(npc, npc->ev, npc->tstream,
						   npc->write_queue,
						   npc->iov,
						   1);
		if (!subreq) {
			DBG_ERR("Failed to send response for raw pipe\n");
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		tevent_req_set_callback(subreq, wsp_pipe_process_done, npc);
	} else {
		/*
		 * we don't respond to some messages (e.g. CPMDisconnect from
		 * MS-WSP), make sure we restart the server loop in anycase.
		 */
		subreq = wsp_server_loop(npc);
		if (!subreq) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
	}
	return;
fail:
	DBG_ERR("Fatal error(%s). "
		  "Terminating client(%s) connection!\n",
		  nt_errstr(status), npc->client_name);
	/* terminate client connection */
	talloc_free(npc);
	return;
}

static void wsp_pipe_process_done(struct tevent_req *subreq)
{
	struct named_pipe_client *npc =
		tevent_req_callback_data(subreq, struct named_pipe_client);
	int sys_errno;
	int ret;

	DBG_DEBUG("wsp_pipe_process_done \n");
	ret = tstream_writev_queue_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		DBG_ERR("Writev failed!\n");
		goto fail;
	}
	if (tevent_queue_length(npc->write_queue) > 0) {
		return;
	}

	npc->count = 0;
	TALLOC_FREE(npc->iov);
	data_blob_free(&npc->p->in_data.data);
	data_blob_free(&npc->p->out_data.frag);
	data_blob_free(&npc->p->out_data.rdata);

	talloc_free_children(npc->p->mem_ctx);
	subreq = wsp_server_loop(npc);
	if (!subreq) {
		goto fail;
	}
	return;
fail:
	DBG_ERR("Fatal error(%s). "
		  "Terminating client(%s) connection!\n",
		  strerror(sys_errno), npc->client_name);
	/* terminate client connection */
	talloc_free(npc);
	return;
}

static struct tevent_req *process_wsp_pipe_request(TALLOC_CTX *mem_ctx,
					struct named_pipe_client *npc)
{
	struct tevent_req *subreq;
	struct pipes_struct *p = npc->p;
	TALLOC_CTX *frame = talloc_stackframe();
	struct wspd_state *wspd_state =
			talloc_get_type_abort(npc->private_data,
					      struct wspd_state);
	if (!pipe_init_outgoing_data(p)) {
		subreq = NULL;
		goto done;
	}

	subreq = do_wsp_request_send(mem_ctx, wspd_state->client_state);
	if (!subreq) {
		goto done;
	}
done:
	TALLOC_FREE(frame);
	return subreq;
}

static void named_pipe_wsp_accept_done(struct tevent_req *subreq)
{
	struct auth_session_info_transport *session_info_transport;
	struct named_pipe_client *npc =
		tevent_req_callback_data(subreq, struct named_pipe_client);
	int error;
	int ret;

	ret = tstream_npa_accept_existing_recv(subreq, &error, npc,
						&npc->tstream,
						&npc->client,
						&npc->client_name,
						&npc->server,
						&npc->server_name,
						&session_info_transport);

	npc->session_info = talloc_move(npc, &session_info_transport->session_info);

	TALLOC_FREE(subreq);
	if (ret != 0) {
		DBG_ERR("Failed to accept named pipe connection! (%s)\n",
			  strerror(error));
		TALLOC_FREE(npc);
		return;
	}

	ret = make_server_pipes_struct(npc,
				       npc->msg_ctx,
				       npc->pipe_name, NCACN_NP,
				       npc->server,
				       npc->client,
				       npc->session_info,
				       &npc->p, &error);
	if (ret != 0) {
		DBG_ERR("Failed to create pipes_struct! (%s)\n",
			  strerror(error));
		goto fail;
	}

	npc->write_queue = tevent_queue_create(npc, "np_server_write_queue");
	if (!npc->write_queue) {
		DBG_ERR("Failed to set up write queue!\n");
		goto fail;
	}
	/*
	 * replace previous contents of private_data (gss_state)
	 * with wspd_state
	 */
	npc->private_data = wsp_pipe_opened(npc, npc->private_data);

	if (!npc->private_data) {
		DBG_ERR("failed after opening pipe\n");
		goto fail;
	}

	npc->term_fn = wsp_pipe_destroyed;

	subreq = wsp_server_loop(npc);
	if (!subreq) {
		DBG_ERR("Failed to start receving packets\n");
		goto fail;
	}

	return;

fail:
	DBG_ERR("Fatal error. Terminating client(%s) connection!\n",
		  npc->client_name);
	/* terminate client connection */
	talloc_free(npc);
	return;
}

static void named_pipe_listener(struct tevent_context *ev,
				struct tevent_fd *fde,
				uint16_t flags,
				void *private_data)
{
	struct listen_state *state =
			talloc_get_type_abort(private_data,
					      struct listen_state);
	struct sockaddr_un sunaddr;
	socklen_t len;
	int sd = -1;

	/* TODO: should we have a limit to the number of clients ? */

	len = sizeof(sunaddr);

	sd = accept(state->fd,
		    (struct sockaddr *)(void *)&sunaddr, &len);

	if (sd == -1) {
		if (errno != EINTR) {
			DBG_INFO("Failed to get a valid socket [%s]\n",
				  strerror(errno));
		}
		return;
	}

	DBG_INFO("Accepted socket %d\n", sd);

	named_pipe_wsp_accept_function(state->ev_ctx,
				   state->msg_ctx,
				   state->name,
				   sd, NULL, state->private_data);
}

static bool setup_wsp_named_pipe_socket(const char *pipe_name,
					struct tevent_context *ev_ctx,
					struct messaging_context *msg_ctx,
					void *private_data)
{
	struct listen_state *state;
	struct tevent_fd *fde;
	int rc;

	state = talloc(ev_ctx, struct listen_state);
	if (!state) {
		DBG_ERR("Out of memory\n");
		return false;
	}
	state->name = talloc_strdup(state, pipe_name);
	if (state->name == NULL) {
		DBG_ERR("Out of memory\n");
		goto out;
	}
	state->fd = create_named_pipe_socket(pipe_name);
	if (state->fd == -1) {
		goto out;
	}
	state->private_data = private_data;
	rc = listen(state->fd, 5);
	if (rc < 0) {
		DBG_ERR("Failed to listen on pipe socket %s: %s\n",
			  pipe_name, strerror(errno));
		goto out;
	}

	state->ev_ctx = ev_ctx;
	state->msg_ctx = msg_ctx;

	DBG_DEBUG("Openened pipe socket fd %d for %s\n",
		   state->fd, pipe_name);

	fde = tevent_add_fd(ev_ctx,
			    state, state->fd, TEVENT_FD_READ,
			    named_pipe_listener, state);
	if (!fde) {
		DBG_ERR("Failed to add event handler!\n");
		goto out;
	}

	tevent_fd_set_auto_close(fde);
	return true;

out:
	if (state->fd != -1) {
		close(state->fd);
	}
	TALLOC_FREE(state);
	return false;
}

static void wspd_reopen_logs(void)
{
	char *lfile = lp_logfile(NULL);
	int rc;

	if (lfile == NULL || lfile[0] == '\0') {
		rc = asprintf(&lfile, "%s/log.%s", get_dyn_LOGFILEBASE(), DAEMON_NAME);
		if (rc > 0) {
			lp_set_logfile(lfile);
			SAFE_FREE(lfile);
		}
	} else {
		if (strstr(lfile, DAEMON_NAME) == NULL) {
			rc = asprintf(&lfile, "%s.%s", lp_logfile(NULL), DAEMON_NAME);
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

static void* wsp_pipe_opened(struct named_pipe_client *npc,
			    void *private_data)
{
	struct gss_state *gss_state = talloc_get_type_abort(private_data,
							struct gss_state);
	struct wspd_state *wsp_state = talloc_zero(gss_state, struct wspd_state);
	DBG_NOTICE("starting wsp server loop \n");

	wsp_state->gss_state = gss_state;

	if (!gss_init(gss_state)) {
		DBG_ERR("Failed to initialise the gss\n");
		return NULL;
	}
	wsp_state->client_state = create_client_state(npc, gss_state);
	return wsp_state;
}

static void wsp_pipe_destroyed(void *private_data)
{
	struct wspd_state *wsp_state =
		talloc_get_type_abort(private_data, struct wspd_state);
	client_disconnected(wsp_state->client_state);
	TALLOC_FREE(wsp_state);
}

void start_wspd(struct tevent_context *ev_ctx,
		struct messaging_context *msg_ctx)
{
	NTSTATUS status;
	struct gss_state *gss_state;
	pid_t pid;
	bool ok;
	int rc;

	gss_state = gss_state_create(ev_ctx, msg_ctx);
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

	ok = serverid_register(messaging_server_id(msg_ctx),
			       FLAG_MSG_GENERAL |
			       FLAG_MSG_PRINT_GENERAL);
	if (!ok) {
		DBG_ERR("Failed to register serverid in wspd!\n");
		exit(1);
	}

	messaging_register(msg_ctx,
			   ev_ctx,
			   MSG_SMB_CONF_UPDATED,
			   wspd_smb_conf_updated);

	ok = setup_wsp_named_pipe_socket("msftewds", ev_ctx, msg_ctx, gss_state);
	if (!ok) {
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
