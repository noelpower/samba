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

static bool test_rawpipe_large_message_impl(struct torture_context *tctx,
					    const void *data,
					    bool increase_max_ioctl)
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
	struct tstream_context *stream = NULL;

	TALLOC_CTX *mem_ctx = talloc_init("test_rawpipe_large_message");
	in.data = talloc_array(mem_ctx, uint8_t, strlen(test_message) + 1);
	in.length = talloc_array_length(in.data);
	memcpy(in.data, test_message, in.length);

	if (increase_max_ioctl) {
		stream = test_data->p->conn->transport.stream;
		tstream_smbXcli_np_set_max_data(stream, expected);
	}
	status = write_something(tctx, test_data->h, &in, &out);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "failed to write to pipe\n");
	if (increase_max_ioctl) {
		ret = out.length == expected;
	} else {
		ret = (out.length != expected) && (out.length == limit);
	}
	torture_comment(tctx, "test_rawpipe_large_message test was %s (received %d bytes expected %d)\n", ret ? "successful" : "unsuccsessful", (uint32_t)out.length, increase_max_ioctl ? expected : limit);
done:
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
static bool test_rawpipe_large_message_clipped(struct torture_context *tctx,
					       const void *data)
{
	return test_rawpipe_large_message_impl(tctx, data, false);
}

/*
 * The idea here is to send a large message size that exceeds the normal
 * hardcoded Max Ioctl hard coded limit of 4280 bytes, this would normally
 * result in a BUFFER_OVERFLOW error at the SMB layer in the response
 * from the server. However, now we test 'tstream_smbXcli_np_set_max_data'
 * a new function which allows us to adjust the size limit so the message
 * should no longer be clipped.
 *
 * [1] It seems we don't see the SMB BUFFER_OVERFLOW status at this layer
 *     however we can detect that the message is clipped to the current
 *     limit of 4280 bytes.
 */

static bool test_rawpipe_large_message_newmax(struct torture_context *tctx,
					      const void *data)
{
	return test_rawpipe_large_message_impl(tctx, data, true);
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
#ifdef DEVELOPER
	/* SMB1 tests */
	add_raw_test(suite, "smb1_simple_echo", test_rawpipe_simple_echo, false);
	add_raw_test(suite, "smb1_echo_large_message_clipped", test_rawpipe_large_message_clipped, false);
	add_raw_test(suite, "smb1_echo_large_message_newmax", test_rawpipe_large_message_newmax, false);
	/* SMB2 tests */
	add_raw_test(suite, "smb2_simple_echo", test_rawpipe_simple_echo, true);
	add_raw_test(suite, "smb2_echo_large_message_clipped", test_rawpipe_large_message_clipped, true);
	add_raw_test(suite, "smb2_echo_large_message_newmax", test_rawpipe_large_message_newmax, true);
#endif
	return suite;
}
