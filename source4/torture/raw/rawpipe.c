/*
   Unix SMB/CIFS implementation.

   test suite for Raw pipe implementation

   Copyright (C) Noel Power 2016

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "rpc_server/rawpipe.h"
#include "libcli/smb2/smb2.h"
#include "libcli/resolve/resolve.h"
#include "libcli/smb/tstream_smbXcli_np.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/libcli.h"
#include "librpc/rpc/dcerpc_raw.h"
#include "lib/cmdline/popt_common.h"
#include "auth/credentials/credentials.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"
#include "torture/rpc/torture_rpc.h"
#include "torture/raw/proto.h"
#include "torture/util.h"
#include "util/tevent_ntstatus.h"
#include "param/param.h"


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

static struct dcerpc_binding_handle *create_rawpipe_handle(struct dcerpc_pipe *p)
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

struct rawpipe_test_data
{
	struct dcerpc_pipe *p;
	struct dcerpc_binding_handle *h;
};

static NTSTATUS write_something(TALLOC_CTX* ctx,
				struct dcerpc_binding_handle *handle,
				DATA_BLOB *blob_in,
				DATA_BLOB *blob_out)
{
	uint32_t outflags;
	NTSTATUS status = dcerpc_binding_handle_raw_call(handle,
						NULL,
						0,
						0,
						blob_in->data,
						blob_in->length,
						ctx,
						&blob_out->data,
						&blob_out->length,
						&outflags);
	return status;
}

static NTSTATUS connect_server_smb2(TALLOC_CTX *mem_ctx,
			struct torture_context *tctx,
			struct smb2_tree **tree)
{
	NTSTATUS status;
	struct cli_credentials *credentials = cmdline_credentials;
	struct smbcli_options options;
	struct smbcli_session_options session_options;
	const char *host = torture_setting_string(tctx, "host", NULL);

	lpcfg_smbcli_options(tctx->lp_ctx, &options);

	lpcfg_smbcli_session_options(tctx->lp_ctx, &session_options);

	status = smb2_connect(mem_ctx,
			      host,
			      lpcfg_smb_ports(tctx->lp_ctx),
			      "IPC$",
			      lpcfg_resolve_context(tctx->lp_ctx),
			      credentials,
			      tree,
			      tctx->ev,
			      &options,
			      lpcfg_socket_options(tctx->lp_ctx),
			      lpcfg_gensec_settings(tctx, tctx->lp_ctx)
			      );
	return status;
}

static NTSTATUS connect_server_smb(TALLOC_CTX *mem_ctx,
			struct torture_context *tctx,
			struct smbcli_state **cli)
{
	NTSTATUS status;
	struct cli_credentials *credentials = cmdline_credentials;
	struct smbcli_options options;
	struct smbcli_session_options session_options;
	const char *host = torture_setting_string(tctx, "host", NULL);

	lpcfg_smbcli_options(tctx->lp_ctx, &options);

	lpcfg_smbcli_session_options(tctx->lp_ctx, &session_options);

	status = smbcli_full_connection(mem_ctx,
					cli,
					host,
					lpcfg_smb_ports(tctx->lp_ctx),
					"IPC$", NULL,
					lpcfg_socket_options(tctx->lp_ctx),
					credentials,
					lpcfg_resolve_context(tctx->lp_ctx),
					tctx->ev, &options, &session_options,
					lpcfg_gensec_settings(tctx,
							      tctx->lp_ctx));
	return status;
}

static bool test_rawpipe_simple_echo(struct torture_context *tctx,
				     const void *data)
{
	NTSTATUS status;
	bool ret = true;
	DATA_BLOB out;
	DATA_BLOB in;
	const char *test_message = "hello";
	struct rawpipe_test_data *test_data =
			talloc_get_type(data,
					struct rawpipe_test_data);
	TALLOC_CTX *mem_ctx = talloc_init("test_rawpipe_simple_echo");

	in.data = talloc_array(mem_ctx, uint8_t, strlen(test_message) + 1);
	in.length = talloc_array_length(in.data);
	memcpy(in.data, test_message, in.length);
	status = write_something(mem_ctx, test_data->h, &in, &out);
	torture_assert_ntstatus_ok(tctx, status, "failed to write to pipe\n");
	torture_assert(tctx,
		       in.length == out.length,
		       "message sizes are different");
	ret = memcmp(in.data, out.data, in.length) == 0;
	torture_assert(tctx, ret, "messages differ");
	TALLOC_FREE(mem_ctx);
	return ret;
}

/*
 * The idea here is to send a large message size that exceeds the normal
 * hardcoded Max Ioctl hard coded limit of 4280 bytes, this will generate
 * will result in a BUFFER_OVERFLOW error at the SMB layer in the response
 * from the server [1].
 *
 * [1] It seems we don't see the SMB BUFFER_OVERFLOW status at this layer
 *     however we can detect that the message is clipped to the current
 *     limit of 4280 bytes.
 */
static bool test_rawpipe_large_message(struct torture_context *tctx,
				     const void *data)
{
	NTSTATUS status;
	bool ret = true;
	const char * test_message = "large";
	uint32_t limit = 4280;
	uint32_t expected = 6500;
	DATA_BLOB out;
	DATA_BLOB in;
	struct rawpipe_test_data *test_data =
			talloc_get_type(data,
					struct rawpipe_test_data);

	TALLOC_CTX *mem_ctx = talloc_init("test_rawpipe_large_message");
	in.data = talloc_array(mem_ctx, uint8_t, strlen(test_message) + 1);
	in.length = talloc_array_length(in.data);
	memcpy(in.data, test_message, in.length);

	status = write_something(tctx, test_data->h, &in, &out);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "failed to write to pipe\n");
	ret = (out.length != expected) && (out.length == limit);
	torture_comment(tctx, "test_rawpipe_large_message test was %s (received %d bytes expected %d)\n", ret ? "successful" : "unsuccsessful", (uint32_t)out.length, limit);
done:
	return ret;
}

static bool raw_smb1_setup(struct torture_context *tctx,
			  void **ppdata)
{
	struct rawpipe_test_data *data;
	NTSTATUS status;
	struct dcerpc_pipe *p;
	struct smbcli_state *cli = NULL;
	struct dcerpc_binding_handle *h;

	data = talloc(NULL, struct rawpipe_test_data);
	status = connect_server_smb(data, tctx, &cli);
	torture_assert_ntstatus_ok(tctx, status, "failed to connect to server");

	p = dcerpc_pipe_init(tctx, tctx->ev);

	status = dcerpc_pipe_open_smb(p, cli->tree, "rawpipe");
	torture_assert_ntstatus_ok(tctx, status, "could not open pipe\n");

	h = create_rawpipe_handle(p);
	torture_assert(tctx, h != NULL, "failed to create handle\n");

	status = tstream_smbXcli_np_use_trans(p->conn->transport.stream);
	torture_assert_ntstatus_ok(tctx,
				   status,
				   "failed to set trans mode on pipe\n");

	data->p = p;
	data->h = h;

	*ppdata = data;
	return true;
}

static bool raw_smb2_setup(struct torture_context *tctx,
			  void **ppdata)
{
	struct rawpipe_test_data *data;
	NTSTATUS status;
	struct dcerpc_pipe *p;
	struct smb2_tree *tree = NULL;
	struct dcerpc_binding_handle *h;

	data = talloc(NULL, struct rawpipe_test_data);

	status = connect_server_smb2(data, tctx, &tree);
	torture_assert_ntstatus_ok(tctx, status, "failed to connect to server");

	p = dcerpc_pipe_init(tctx, tctx->ev);

	status = dcerpc_pipe_open_smb2(p, tree, "rawpipe");
	torture_assert_ntstatus_ok(tctx, status, "could not open pipe\n");

	h = create_rawpipe_handle(p);
	torture_assert(tctx, h != NULL, "failed to create handle\n");

	status = tstream_smbXcli_np_use_trans(p->conn->transport.stream);
	torture_assert_ntstatus_ok(tctx,
				   status,
				   "failed to set trans mode on pipe\n");

	data->p = p;
	data->h = h;

	*ppdata = data;
	return true;
}


static bool raw_smb1_teardown(struct torture_context *tctx,
			  void *data)
{
	return true;
}

static bool raw_smb2_teardown(struct torture_context *tctx,
			  void *data)
{
	return true;
}

static void add_raw_test(struct torture_suite *suite,
			const char *name,
			bool (*run) (struct torture_context *test,
					const void *tcase_data),
			bool use_smb2)
{
	struct torture_tcase *tcase = torture_suite_add_tcase(suite,
							      name);
	if (use_smb2) {
		torture_tcase_set_fixture(tcase,
					  raw_smb2_setup,
					  raw_smb1_teardown);
	} else {
		torture_tcase_set_fixture(tcase,
					  raw_smb1_setup,
					  raw_smb2_teardown);
	}
	torture_tcase_add_simple_test_const(tcase, name, run);
}

struct torture_suite *torture_raw_rawpipe(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "rawpipe");
	/* SMB1 tests */
	add_raw_test(suite, "smb1_simple_echo", test_rawpipe_simple_echo, false);
	add_raw_test(suite, "smb1_echo_large_message", test_rawpipe_large_message, false);
	/* SMB2 tests */
	add_raw_test(suite, "smb2_simple_echo", test_rawpipe_simple_echo, true);
	add_raw_test(suite, "smb2_echo_large_message", test_rawpipe_large_message, true);
	return suite;
}
