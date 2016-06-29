#include "includes.h"
#include "system/filesys.h"
#include "librpc/rpc/dcerpc_raw.h"
#include "lib/events/events.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "param/param.h"
#include "lib/util/tevent_ntstatus.h"
#include "librpc/rpc/rpc_common.h"
#include "lib/tsocket/tsocket.h"

struct rawpipe_bh_state {
	struct dcerpc_pipe *p;
};

static bool rawpipe_bh_ref_alloc(struct dcerpc_binding_handle *h)
{
	return true;
}

static bool rawpipe_bh_is_connected(struct dcerpc_binding_handle *h)
{
	struct rawpipe_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rawpipe_bh_state);

	if (!hs->p) {
		return false;
	}

	if (!hs->p->conn) {
		return false;
	}

	if (hs->p->conn->dead) {
		return false;
	}

	return true;
}

static uint32_t rawpipe_bh_set_timeout(struct dcerpc_binding_handle *h,
				      uint32_t timeout)
{
	struct rawpipe_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rawpipe_bh_state);
	uint32_t old;

	if (!hs->p) {
		return DCERPC_REQUEST_TIMEOUT;
	}

	old = hs->p->request_timeout;
	hs->p->request_timeout = timeout;

	return old;
}

static void rawpipe_bh_auth_info(struct dcerpc_binding_handle *h,
				enum dcerpc_AuthType *auth_type,
				enum dcerpc_AuthLevel *auth_level)
{
	struct rawpipe_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rawpipe_bh_state);
	if (hs->p == NULL) {
		return;
	}

	if (hs->p->conn == NULL) {
		return;
	}

	*auth_type = hs->p->conn->security_state.auth_type;
	*auth_level = hs->p->conn->security_state.auth_level;
}

struct rawpipe_bh_disconnect_state {
	uint8_t _dummy;
};

static struct tevent_req *rawpipe_bh_disconnect_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct dcerpc_binding_handle *h)
{
	struct rawpipe_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rawpipe_bh_state);
	struct tevent_req *req;
	struct dcerpc_bh_disconnect_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct rawpipe_bh_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	ok = rawpipe_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return tevent_req_post(req, ev);
	}

	/* TODO: do a real disconnect ... */
	hs->p = NULL;

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS rawpipe_bh_disconnect_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct rawpipe_bh_raw_call_state {
	DATA_BLOB out_data;
	struct iovec req;
	struct iovec resp;
	struct tevent_context *ev;
	struct dcecli_connection  *conn;
};

struct rpc_write_state {
	struct tevent_context *ev;
	DATA_BLOB buffer;
	struct dcecli_connection *conn;
	struct iovec in;
	struct iovec out;
};

static void raw_tstream_trans_writev(struct tevent_req *subreq);
static void raw_tstream_trans_readv_done(struct tevent_req *subreq);

static struct tevent_req *raw_pipe_req_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct dcerpc_pipe *p,
					 struct  iovec *req_data)
{
	struct tevent_req *req, *subreq;
	struct rpc_write_state *state;
	struct timeval endtime;

	req = tevent_req_create(mem_ctx, &state, struct rpc_write_state);
	if (req == NULL) {
		return NULL;
	}

	/*
	 * #TODO check if stream is connected
	 */

	state->ev = ev;
	state->conn = p->conn;
	state->in = *req_data;

	endtime = timeval_current_ofs_msec(p->request_timeout);

	subreq = tstream_writev_queue_send(state,
				     ev,
				     state->conn->transport.stream,
				     state->conn->transport.write_queue,
				     &state->in,
				     1);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	if (!tevent_req_set_endtime(subreq, ev, endtime)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, raw_tstream_trans_writev, req);
	state->buffer.data = talloc_array(state, uint8_t, 1);
	state->buffer.length = talloc_array_length(state->buffer.data);
	state->out.iov_base = state->buffer.data;
	state->out.iov_len = state->buffer.length;
	subreq = tstream_readv_send(state, ev,
				      p->conn->transport.stream,
				      &state->out,
				      1);

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	if (!tevent_req_set_endtime(subreq, ev, endtime)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, raw_tstream_trans_readv_done, req);

	return req;
}

static void raw_tstream_trans_readv_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);

	struct rpc_write_state *state =
		tevent_req_data(req,
		struct rpc_write_state);

	int ret;
	int err = 0;
	int to_read;
	ssize_t ofs = 0;

	ret = tstream_readv_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix_common(err));
		return;
	}

	to_read = tstream_pending_bytes(state->conn->transport.stream);
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
	state->out.iov_base = (void *) (state->buffer.data + ofs);
	state->out.iov_len = state->buffer.length - ofs;
	subreq = tstream_readv_send(state,
				    state->ev,
				    state->conn->transport.stream,
				    &state->out,
				    1);
	if (tevent_req_nomem(subreq, req)) {
		tevent_req_post(req, state->ev);
		return;
	}

	tevent_req_set_callback(subreq, raw_tstream_trans_readv_done, req);
}

static void raw_tstream_trans_writev(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	int ret;
	int err;
	ret = tstream_writev_queue_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix_common(err));
		return;
	}
}

static void rawpipe_bh_call_send_done(struct tevent_req *subreq);
static struct tevent_req *rawpipe_bh_call_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct dcerpc_binding_handle *h,
					  const struct GUID *object,
					  uint32_t opnum,
					  uint32_t in_flags,
					  const uint8_t *in_data,
					  size_t in_length)
{
	struct rawpipe_bh_state *hs = dcerpc_binding_handle_data(h,
				     struct rawpipe_bh_state);
	struct tevent_req *req;
	bool ok;
	struct tevent_req *subreq;
	struct rawpipe_bh_raw_call_state* state;

	req = tevent_req_create(mem_ctx, &state,
				struct rawpipe_bh_raw_call_state);
	if (req == NULL) {
		return NULL;
	}
	state->req.iov_len = in_length;
	state->req.iov_base = discard_const_p(uint8_t, in_data);

	state->out_data = data_blob_null;
	state->conn = hs->p->conn;
	state->ev = ev;

	ok = rawpipe_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return tevent_req_post(req, ev);
	}
	subreq = raw_pipe_req_send(state, ev, hs->p,
				   &state->req);

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, rawpipe_bh_call_send_done, req);
	return req;
}

static void rawpipe_bh_call_send_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct rawpipe_bh_raw_call_state *state =
		tevent_req_data(req,
		struct rawpipe_bh_raw_call_state);
	struct rpc_write_state *write_state =
		tevent_req_data(subreq,
		struct rpc_write_state);
	NTSTATUS status;
	if (tevent_req_is_nterror(subreq, &status)) {
		tevent_req_nterror(req, status);
		return;
	}
	state->out_data.data = talloc_move(state, &write_state->buffer.data);
	state->out_data.length = write_state->buffer.length;
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static NTSTATUS rawpipe_bh_call_recv(struct tevent_req *req,
					TALLOC_CTX *mem_ctx,
					uint8_t **out_data,
					size_t *out_length,
					uint32_t *out_flags)
{
	NTSTATUS status;
	struct rawpipe_bh_raw_call_state *state =
		tevent_req_data(req,
		struct rawpipe_bh_raw_call_state);

	*out_data = talloc_move(mem_ctx, &state->out_data.data);
	*out_length = state->out_data.length;
	status = NT_STATUS_OK;
	if (tevent_req_is_nterror(req, &status)) {
	}
	tevent_req_received(req);

	return status;
}

static const struct dcerpc_binding_handle_ops raw_pipe_ccli_bh_ops = {
	.name			= "raw_pipe_ccli",
	.is_connected		= rawpipe_bh_is_connected,
	.set_timeout		= rawpipe_bh_set_timeout,
	.auth_info		= rawpipe_bh_auth_info,
	.raw_call_send		= rawpipe_bh_call_send,
	.raw_call_recv		= rawpipe_bh_call_recv,
	.disconnect_send	= rawpipe_bh_disconnect_send,
	.disconnect_recv	= rawpipe_bh_disconnect_recv,

	.ref_alloc		= rawpipe_bh_ref_alloc,
};

struct dcerpc_binding_handle *create_rawpipe_handle(struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *h = NULL;

	struct rawpipe_bh_state *hs;
	h = dcerpc_binding_handle_create(p,
					 &raw_pipe_ccli_bh_ops,
					 NULL,
					 NULL,
					 &hs,
					 struct rawpipe_bh_state,
					 __location__);
	if (h == NULL) {
		return NULL;
	}
	hs->p = p;
	return h;
}
