/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
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
#include "bin/default/librpc/gen_ndr/ndr_wsp.h"
#include "bin/default/librpc/gen_ndr/ndr_wsp_data.h"
#include "librpc/rpc/wsp_helper.h"
#include "libcli/wsp/wsp_cli.h"
#include "lib/cmdline/popt_common.h"
#include "lib/events/events.h"
#include "auth/gensec/gensec.h"
#include "util/tevent_ntstatus.h"
#include "util/debug.h"
#include "dcerpc.h"
#include "credentials.h"
#include "param/param.h"

/* send connectin message */
static NTSTATUS connect(TALLOC_CTX *ctx,
			struct wsp_client_ctx *wsp_ctx,
			const char* clientmachine,
			const char* clientuser,
			const char* server)
{
	struct wsp_request *request;
	struct wsp_response *response;
	DATA_BLOB unread;
	NTSTATUS status;
	TALLOC_CTX *local_ctx = talloc_new(ctx);

	ZERO_STRUCT(unread);

	request = talloc_zero(local_ctx, struct wsp_request);
	response = talloc_zero(local_ctx, struct wsp_response);

	init_connectin_request(local_ctx, request,
			       clientmachine, clientuser, server);

	status =  wsp_request_response(local_ctx, wsp_ctx, request, response, &unread);
	data_blob_free(&unread);
	TALLOC_FREE(local_ctx);
	return status;
}

static NTSTATUS create_query(TALLOC_CTX *ctx,
			     struct wsp_client_ctx *wsp_ctx,
			     const char* location,
			     const char* phrase,
			     const char* kind,
			     uint32_t *single_cursor)
{
	struct wsp_request *request;
	struct wsp_response *response;
	NTSTATUS status;
	DATA_BLOB unread;
	TALLOC_CTX *local_ctx = talloc_new(ctx);

	ZERO_STRUCT(unread);
	request = talloc_zero(local_ctx, struct wsp_request);
	response = talloc_zero(local_ctx, struct wsp_response);

	create_querysearch_request(local_ctx, request, location, phrase, kind);
	status = wsp_request_response(local_ctx, wsp_ctx, request, response, &unread);
	if (NT_STATUS_IS_OK(status)) {
		if (unread.length == 4) {
			*single_cursor = IVAL(unread.data, 0);
		}
	}
	data_blob_free(&unread);
	TALLOC_FREE(local_ctx);
	return status;
}

static NTSTATUS create_bindings(TALLOC_CTX *ctx,
				struct wsp_client_ctx *wsp_ctx,
				uint32_t cursor,
				struct wsp_cpmsetbindingsin *bindings_out)
{
	struct wsp_request *request;
	struct wsp_response *response;
	NTSTATUS status;
	DATA_BLOB unread;

	ZERO_STRUCT(unread);

	request = talloc_zero(ctx, struct wsp_request);
	response = talloc_zero(ctx, struct wsp_response);
	create_setbindings_request(ctx, request, cursor);
	status = wsp_request_response(ctx, wsp_ctx, request, response, &unread);
	if (NT_STATUS_IS_OK(status)) {
		*bindings_out = request->message.cpmsetbindings;
	}
	data_blob_free(&unread);
	return status;
}

static NTSTATUS create_querystatusex(TALLOC_CTX *ctx,
				struct wsp_client_ctx *wsp_ctx,
				uint32_t cursor,
				uint32_t *nrows)
{
	struct wsp_request *request;
	struct wsp_response *response;
	NTSTATUS status;
	DATA_BLOB unread;
	TALLOC_CTX *local_ctx = talloc_new(ctx);

	ZERO_STRUCT(unread);

	request = talloc_zero(local_ctx, struct wsp_request);
	response = talloc_zero(local_ctx, struct wsp_response);
	request->header.msg = CPMGETQUERYSTATUSEX;
	request->message.cpmgetquerystatusex.hcursor = cursor;
	request->message.cpmgetquerystatusex.bmk = 0xfffffffc;
	status = wsp_request_response(local_ctx, wsp_ctx, request, response, &unread);
	if (NT_STATUS_IS_OK(status)) {
		*nrows = response->message.cpmgetquerystatusex.resultsfound;;
	}
	data_blob_free(&unread);
	TALLOC_FREE(local_ctx);
	return status;
}

static NTSTATUS create_getrows(TALLOC_CTX *ctx,
			       struct wsp_client_ctx *wsp_ctx,
			       struct wsp_cpmsetbindingsin *bindings,
			       uint32_t cursor,
			       uint32_t nrows)
{
	struct wsp_request *request;
	struct wsp_response *response;
	NTSTATUS status;
	DATA_BLOB unread;
	struct wsp_cbasestoragevariant **rowsarray = NULL;
	enum ndr_err_code err;
	TALLOC_CTX *local_ctx = talloc_new(ctx);
	uint32_t bmk = 0;
	uint32_t skip = 0;
	uint32_t requested_rows = 0;
	uint32_t total_rows = 0;
	uint32_t INITIAL_ROWS = 32;
	uint32_t row;
	uint32_t current_row = 0;
	ZERO_STRUCT(unread);

	while (total_rows != nrows) {
		request = talloc_zero(local_ctx, struct wsp_request);
		response = talloc_zero(local_ctx, struct wsp_response);

		if (requested_rows == 0) {
			uint32_t remaining_rows = nrows - total_rows;
			if ( remaining_rows < INITIAL_ROWS) {
				requested_rows = remaining_rows;
			} else {
				requested_rows = INITIAL_ROWS;
			}
			bmk = 0xfffffffc;
			skip = total_rows;
		}

		create_seekat_getrows_request(local_ctx,
					request,
					cursor,
					bmk,
					skip,
					requested_rows,
					40,
					0xDEAbd860,
					bindings->brow,
					0);

		status = wsp_request_response(local_ctx, wsp_ctx, request, response, &unread);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		total_rows += response->message.cpmgetrows.rowsreturned;
		if (response->message.cpmgetrows.rowsreturned
		   != requested_rows) {
			if (response->message.cpmgetrows.etype == EROWSEEKAT) {
				struct wsp_cpmgetrowsout *resp;
				struct wsp_crowseekat *seekat;
				resp = &response->message.cpmgetrows;
				seekat =
					&resp->seekdescription.crowseekat;
				bmk = seekat->bmkoffset;
				skip = seekat->cskip;
				requested_rows =
					requested_rows - response->message.cpmgetrows.rowsreturned;
			}
		} else {
			requested_rows = 0;
		}
		rowsarray =
			talloc_zero_array(local_ctx,
				struct wsp_cbasestoragevariant*,
				response->message.cpmgetrows.rowsreturned);
		err = extract_rowsarray(rowsarray,
				&unread,
				bindings,
				40,
				0xDEAbd860,
				response->message.cpmgetrows.rowsreturned,
				rowsarray);
		if (err) {
			DBG_ERR("failed to extract rows from getrows response\n");
		}
		data_blob_free(&unread);
		for(row = 0;
		    row < response->message.cpmgetrows.rowsreturned; row++, current_row++) {
			if (rowsarray[row][0].vtype != VT_EMPTY) {
				printf("%s\n", rowsarray[row][0].vvalue.vt_lpwstr.value );
			} else {
				printf("problem with row[%d]\n", current_row);
			}
		}
	}
out:
	TALLOC_FREE(rowsarray);
	TALLOC_FREE(local_ctx);
	return status;
}

int main(int argc, const char *argv[])
{
	int opt;
	int result = 0;
	NTSTATUS status = NT_STATUS_OK;
	poptContext pc;
	char* server = NULL;
	char* share = NULL;
	char* path = NULL;
	char* location = NULL;
	const char* phrase = NULL;
	const char* kind = NULL;
	uint32_t nrows = 0;
	struct wsp_cpmsetbindingsin bindings_used;
	struct poptOption long_options[] = {
                POPT_AUTOHELP
		{ "search", 0, POPT_ARG_STRING, &phrase, 0, "Search phrase", "phrase" },
		{ "kind", 0, POPT_ARG_STRING, &kind, 0, "Kind of thing to search for [Calendar|Communication|Contact|Document|Email|Feed|Folder|Game|InstantMessage|Journal|Link|Movie|Music|Note|Picture|Program|RecordedTV|SearchFolder|Task|Video|WebHistory]", "kind" },
                POPT_COMMON_SAMBA
                POPT_COMMON_CONNECTION
                POPT_COMMON_CREDENTIALS
                POPT_TABLEEND
	};
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev_ctx
		=  s4_event_context_init(talloc_tos());
	struct dcerpc_pipe *p;
	uint32_t cursor;
	struct wsp_client_ctx *wsp_ctx;

	gensec_init();

	pc = poptGetContext("wspsearch", argc, argv, long_options, 0);
	poptSetOtherOptionHelp(pc, "//server1/share1");
	while ((opt = poptGetNextOpt(pc)) != -1) ;

	if(!poptPeekArg(pc)) {
		poptPrintUsage(pc, stderr, 0);
		result = -1;
		goto out;
	}

	path = talloc_strdup(talloc_tos(), poptGetArg(pc));
	if (!path) {
		DBG_ERR("Invalid argument\n");
		result = -1;
		goto out;
	}

	string_replace(path,'/','\\');

        server = talloc_strdup(talloc_tos(), path+2);
        if (!server) {
		DBG_ERR("Invalid argument\n");
                return -1;
        }

	share = strchr_m(server,'\\');
	if (!share) {
		DBG_ERR("Invalid argument\n");
                return -1;
	}

	*share = 0;
	share++;

	DBG_INFO("server name is %s\n", server);
	DBG_INFO("share name is %s\n", share);
	DBG_INFO("search phrase is %s\n", phrase);
	DBG_INFO("search kind is %s\n", kind);

	if (kind == NULL && phrase == NULL) {
		poptPrintUsage(pc, stderr, 0);
		result = -1;
		goto out;
	}
	status = wsp_server_connect(talloc_tos(),
				    server,
				    ev_ctx,
				    cmdline_credentials,
				    &wsp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to connect to wsp service status: %s\n",
		      nt_errstr(status));
		result = -1;
		goto out;
	}

	p = get_wsp_pipe(wsp_ctx);
	dcerpc_binding_handle_set_timeout(p->binding_handle,
					  DCERPC_REQUEST_TIMEOUT * 1000);

	/* connect */
	DBG_INFO("sending connect\n");
	status = connect(talloc_tos(),
			 wsp_ctx,
			 lpcfg_netbios_name(cmdline_lp_ctx),
			 cli_credentials_get_username(cmdline_credentials),
			 server);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to connect to wsp: %s\n",
		      nt_errstr(status));
		result = -1;
		goto out;
	}

	DBG_INFO("sending query\n");

	location = talloc_asprintf(talloc_tos(), "FILE://%s/%s", server, share);
	status = create_query(talloc_tos(), wsp_ctx, location, phrase, kind, &cursor);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to send query: %s)\n",
		      nt_errstr(status));
		result = -1;
		goto out;
	}

	DBG_INFO("sending createbindings\n");
	/* set bindings */
	status = create_bindings(talloc_tos(), wsp_ctx, cursor, &bindings_used);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to setbindings: %s)\n",
		      nt_errstr(status));
		result = -1;
		goto out;
	}

	status = create_querystatusex(talloc_tos(),
				      wsp_ctx,
				      bindings_used.hcursor,
				      &nrows);
	if (!nrows) {
		result = 0;
		printf("no results found\n");
		goto out;
	}

	printf("found %d results\n", nrows);
	status = create_getrows(talloc_tos(),
				wsp_ctx,
				&bindings_used,
				bindings_used.hcursor,
				nrows);
	result = 0;
out:
	TALLOC_FREE(frame);
	return result;
}
