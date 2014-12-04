/*
 *  Unix SMB/CIFS implementation.
 *
 *  RawPipe server loop
 *
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
#include "rawpipe.h"
#include <tevent.h>
#include "rpc_common.h"
#include "rpc_server/srv_pipe.h"
#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_pipes.h"
#include "rpc_server/rpc_config.h"
#include "lib/tsocket/tsocket.h"
#include "lib/util/tevent_ntstatus.h"

struct common_rawpipe_ctx
{
	rawpipe_init init;
	rawpipe_close dtor;
	rawpipe_fn handler;
	void *private_data;
};

struct common_rawpipe_loop_ctx
{
	void *init_ctx;
	struct common_rawpipe_ctx *reg_ctx;
};

static struct tevent_req *process_rawpipe_request(TALLOC_CTX *mem_ctx,
						   struct named_pipe_client *npc)
{
	struct tevent_req *subreq = NULL;
	struct pipes_struct *p = npc->p;
	struct common_rawpipe_loop_ctx *ctx =
			talloc_get_type_abort(npc->private_data,
					      struct common_rawpipe_loop_ctx);
	TALLOC_CTX *frame = talloc_stackframe();

	if (!pipe_init_outgoing_data(p)) {
		goto done;
	}

	subreq = ctx->reg_ctx->handler(mem_ctx, npc, ctx->init_ctx);

	if (!subreq) {
		goto done;
	}
done:
	TALLOC_FREE(frame);
	return subreq;
}

struct rawpipe_send_state {
	DATA_BLOB buffer;
	struct iovec in;
	struct tstream_context *stream;
	struct tevent_context *ev;
};

static void read_rawpipe_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct rawpipe_send_state *state =
		tevent_req_data(req, struct rawpipe_send_state);
	int ret;
	int sys_errno;
	int to_read;
	ssize_t ofs = 0;
	NTSTATUS status;

	DEBUG(10,("read_rawpipe_done\n"));
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

	tevent_req_set_callback(subreq, read_rawpipe_done, req);
}

static struct tevent_req *read_rawpipe_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct tstream_context *stream)
{
	struct tevent_req *req;
	struct rawpipe_send_state *state;
	struct tevent_req *subreq;
	req = tevent_req_create(mem_ctx, &state,
				struct rawpipe_send_state);
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
	DEBUG(10,("read_rawpipe_send stream %p\n", stream));
	subreq = tstream_readv_send(state, ev,
					stream,
					&state->in,
					1);
	tevent_req_set_callback(subreq, read_rawpipe_done, req);
	return req;
}

static NTSTATUS rawpipe_read_recv(struct tevent_req *req,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *buffer)
{
	struct rawpipe_send_state *state = tevent_req_data(req,
						struct rawpipe_send_state);
	NTSTATUS status;

	DEBUG(10,("rawpipe_read_recv\n"));
	if (tevent_req_is_nterror(req, &status)) {
		DEBUG(0,("rawpipe_read_recv nterror %s\n", nt_errstr(status)));
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

void rawpipe_process(struct tevent_req *subreq);

static void common_destroy_pipe(void *private_data)
{
	struct common_rawpipe_loop_ctx *loop_ctx =
			talloc_get_type_abort(private_data,
					      struct common_rawpipe_loop_ctx);
	loop_ctx->reg_ctx->dtor(loop_ctx->init_ctx);
}

static struct tevent_req *start_common_rawpipe_loop(struct named_pipe_client *npc,
						void *private_data);
static struct tevent_req *common_rawpipe_loop(struct named_pipe_client *npc);

static void rawpipe_process_done(struct tevent_req *subreq)
{
	struct named_pipe_client *npc =
		tevent_req_callback_data(subreq, struct named_pipe_client);
	int sys_errno;
	int ret;

	DEBUG(10,("rawpipe_process_done \n"));
	ret = tstream_writev_queue_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		DEBUG(2, ("Writev failed!\n"));
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
	subreq = common_rawpipe_loop(npc);
	if (!subreq) {
		goto fail;
	}
	return;
fail:
	DEBUG(0, ("Fatal error(%s). "
		  "Terminating client(%s) connection!\n",
		  strerror(sys_errno), npc->remote_client_name));
	/* terminate client connection */
	talloc_free(npc);
	return;
}

static void process_rawpipe_request_done(struct tevent_req *subreq);
void rawpipe_process(struct tevent_req *subreq)
{
	struct named_pipe_client *npc =
		tevent_req_callback_data(subreq, struct named_pipe_client);
	DATA_BLOB recv_buffer = data_blob_null;
	NTSTATUS status;

	DEBUG(10,("rawpipe_process \n"));
	status = rawpipe_read_recv(subreq, npc, &recv_buffer);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	npc->p->in_data.pdu_needed_len = 0;
	npc->p->in_data.pdu = recv_buffer;

	subreq = process_rawpipe_request(npc->p->mem_ctx, npc);
	if (!subreq) {
		goto fail;
	}
	tevent_req_set_callback(subreq, process_rawpipe_request_done, npc);
	talloc_free(recv_buffer.data);
	return;
fail:
	DEBUG(0, ("Fatal error(%s). "
		  "Terminating client(%s) connection!\n",
		  nt_errstr(status), npc->remote_client_name));
	/* terminate client connection */
	talloc_free(npc);
	return;
}

static void process_rawpipe_request_done(struct tevent_req *subreq)
{
	uint32_t to_send;
	struct named_pipe_client *npc;
	struct _output_data *out;
	NTSTATUS status;
	DEBUG(10,("process_rawpipe_done\n"));
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
		DEBUG(10,("sending %lu bytes to tstream !!\n",
		      npc->iov[0].iov_len ));
		subreq = tstream_writev_queue_send(npc, npc->ev, npc->tstream,
						   npc->write_queue,
						   npc->iov,
						   1);
		if (!subreq) {
			DEBUG(2, ("Failed to send response for raw pipe\n"));
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		tevent_req_set_callback(subreq, rawpipe_process_done, npc);
	} else {
		/*
		 * we don't respond to some messages (e.g. CPMDisconnect from
		 * MS-WSP), make sure we restart the server loop in anycase.
		 */
		subreq = common_rawpipe_loop(npc);
		if (!subreq) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
	}
	return;
fail:
	DEBUG(0, ("Fatal error(%s). "
		  "Terminating client(%s) connection!\n",
		  nt_errstr(status), npc->remote_client_name));
	/* terminate client connection */
	talloc_free(npc);
	return;
}

static struct tevent_req *common_rawpipe_loop(struct named_pipe_client *npc)
{
	struct tevent_req *subreq;

	subreq = read_rawpipe_send(npc, npc->ev, npc->tstream);
	if (!subreq) {
		DEBUG(0, ("Failed to start receving packets\n"));
		goto fail;
	}
	tevent_req_set_callback(subreq, rawpipe_process, npc);
fail:
	return subreq;
}

static struct tevent_req *start_common_rawpipe_loop(struct named_pipe_client *npc,
						void *private_data)
{
	struct common_rawpipe_ctx *ctx =
			talloc_get_type_abort(private_data,
					      struct common_rawpipe_ctx);
	struct common_rawpipe_loop_ctx *loop_ctx =
			talloc_zero(npc, struct common_rawpipe_loop_ctx);
	loop_ctx->reg_ctx = ctx;
	if (ctx->init) {
		loop_ctx->init_ctx = ctx->init(npc, ctx->private_data);
	}
	if (ctx->dtor) {
		npc->term_fn = common_destroy_pipe;
	}
	npc->private_data = loop_ctx;
	return common_rawpipe_loop(npc);
}

void common_rawpipe_register(const char* pipename,
			     uint16_t msg_mode,
			     rawpipe_init init,
			     rawpipe_close dtor,
			     rawpipe_fn handler,
			     void *private_data)
{
	struct common_rawpipe_ctx *ctx =
		talloc(NULL, struct common_rawpipe_ctx);
	ctx->init = init;
	ctx->dtor = dtor;
	ctx->handler = handler;
	ctx->private_data = private_data;
	add_pipe_server_details(pipename,
				msg_mode,
				start_common_rawpipe_loop,
				ctx);
}

#ifdef DEVELOPER

struct dummy_rawpipe_state
{
};

/*
 * Very simple test harness for raw pipes
 * + If we recieve message 'large' we return a large message
 *   that we know breaks the max response with a named pipe trans msg
 *   (Max Ioctl is hard coded to 4280) (this should generate a BUFFER_OVERFLOW)
 * + Any other message we recieve we just echo back
 *
 * Note: we can easily extend the test harness by defining some proper
 * 	 message structures to exchange more complex instruction + payload
 *	 combinations.
 */
static struct tevent_req *do_echo_send(TALLOC_CTX *ctx,
				       struct named_pipe_client *npc,
				       void *init_ctx)
{
	struct tevent_req *req;
	struct pipes_struct *p = npc->p;
	struct dummy_rawpipe_state *state;
	const char* large = "large";
	req = tevent_req_create(ctx, &state,
				struct dummy_rawpipe_state);
	DEBUG(10,("received %lu bytes mem_ctx = %p\n",
	      p->in_data.pdu.length,
	      npc->p->mem_ctx));

	if ((p->in_data.pdu.length == strlen(large) + 1)
	   && (memcmp(p->in_data.pdu.data, large, strlen(large) + 1) == 0)) {
		uint32_t large_size = 6500;
		p->out_data.rdata.data = talloc_zero_array(npc->p->mem_ctx,
					       uint8_t,
					       large_size);
		p->out_data.rdata.length = large_size;
		DEBUG(10,("LARGE message test sending back %d bytes\n",
			large_size));
	} else {
		/* simple echo */
		p->out_data.rdata.data = talloc_array(npc->p->mem_ctx,
					       uint8_t,
					       p->in_data.pdu.length);
		p->out_data.rdata.length = p->in_data.pdu.length;
	}

	memcpy(p->out_data.rdata.data,
		p->in_data.pdu.data,
		p->in_data.pdu.length);

	tevent_req_done(req);
	return tevent_req_post(req, npc->ev);
}

void init_rawipe_echo(struct tevent_context *ev_ctx,
		      struct messaging_context *msg_ctx)
{
	common_rawpipe_register("rawpipe", FILE_TYPE_MESSAGE_MODE_PIPE,
				NULL, NULL, do_echo_send, NULL);
	if (rpc_rawd_daemon()) {
		pid_t pid = fork();
		bool ok;
		if (pid == -1) {
			DEBUG(0, ("failed to fork rawd daemon [%s], "
			      "aborting ...\n", strerror(errno)));
			exit(1);
		}

		if (pid) {
			/* parent */
			return;
		}
		ok = setup_named_pipe_socket("rawpipe", ev_ctx, msg_ctx);
		if (!ok) {
			DEBUG(0, ("Failed to open rawpipe named pipe!\n"));
			exit(1);
		}
		DEBUG(10,("rawd daemon started\n"));
	}
	DEBUG(10,("raw pipe echo loop started\n"));
}
#endif
