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
#include "librpc/wsp/wsp_helper.h"
#include "libcli/wsp/wsp_cli.h"
#include "lib/cmdline/popt_common.h"
#include "lib/events/events.h"
#include "auth/gensec/gensec.h"
#include "util/tevent_ntstatus.h"
#include "util/debug.h"
#include "dcerpc.h"
#include "credentials.h"
#include "param/param.h"
#include "libcli/wsp/wsp_aqs.h"

#if DEVELOPER

static bool is_operator_node(t_query *node)
{
	if (node->type == eVALUE) {
		return false;
	}
	return true;
}

static const char *nodetype_as_string(t_nodetype node)
{
	const char *result = NULL;
	switch (node) {
		case eNOT:
			result = "NOT";
			break;
		case eAND:
			result = "AND";
			break;
		case eOR:
			result = "OR";
			break;
		case eVALUE:
		default:
			break;
	}
	return result;
}

static const char *restriction_as_string(TALLOC_CTX *ctx,
				    struct wsp_crestriction *crestriction )
{
	const char *result = NULL;
	if (crestriction->ultype == RTPROPERTY) {
		struct wsp_cpropertyrestriction *prop_restr =
			&crestriction->restriction.cpropertyrestriction;
		struct wsp_cbasestoragevariant *value = &prop_restr->prval;
		result = variant_as_string(ctx, value, true);
	} else {
		struct wsp_ccontentrestriction *cont_restr = NULL;
		cont_restr = &crestriction->restriction.ccontentrestriction;
		result = talloc_strdup(ctx, cont_restr->pwcsphrase);
	}
	return result;
}

static const char* prop_name_from_restriction(
		TALLOC_CTX *ctx,
		struct wsp_crestriction *restriction)
{
	const char* result;
	struct wsp_cfullpropspec *prop;
	if (restriction->ultype == RTCONTENT) {
		prop = &restriction->restriction.ccontentrestriction.property;
	} else {
		prop = &restriction->restriction.cpropertyrestriction.property;
	}
	result = prop_from_fullprop(ctx, prop);
	return result;
}

static void print_basic_query(struct wsp_crestriction *restriction)
{
	TALLOC_CTX *ctx = talloc_init("print_basic_query");
	const char *op_str = op_as_string(restriction);
	const char *val_str = restriction_as_string(ctx, restriction);
	const char *prop_name = prop_name_from_restriction(ctx, restriction);
	printf("%s %s %s", prop_name, op_str ? op_str : "", val_str);
	TALLOC_FREE(ctx);
}

static void print_node(t_query *node, bool is_rpn)
{
	switch(node->type) {
		case eAND:
		case eOR:
		case eNOT:
			printf(" %s ", nodetype_as_string(node->type));
			break;
		case eVALUE:
		default:
			print_basic_query(node->restriction);
			break;
	}
}

/*
 * Algorithm infix (tree)
 * Print the infix expression for an expression tree.
 *  Pre : tree is a pointer to an expression tree
 *  Post: the infix expression has been printed
 * if (tree not empty)
 *    if (tree token is operator)
 *       print (open parenthesis)
 *    end if
 *    infix (tree left subtree)
 *    print (tree token)
 *    infix (tree right subtree)
 *    if (tree token is operator)
 *       print (close parenthesis)
 *    end if
 * end if
 *end infix
 */

static void infix(t_query *tree)
{
	if (tree == NULL) {
		return;
	}
	if (is_operator_node(tree)) {
		printf("(");
	}
	infix(tree->left);
	print_node(tree, false);
	infix(tree->right);
	if (is_operator_node(tree)) {
		printf(")");
	}
}

static void dump_cols(t_select_stmt *select)
{
	t_col_list *cols = select->cols;
	if (cols) {
		int i;
		for (i = 0; i < cols->num_cols; i++) {
			if (i == 0) {
				printf("%s", cols->cols[i]);
			} else {
				printf(", %s", cols->cols[i]);
			}
		}
	}
}

static void dump_sql(t_select_stmt *select)
{
	if (!select) {
		return;
	}
	printf("selecting the following columns\n");
	dump_cols(select);
	printf("\n");
	printf("parsed query:\n");
	infix(select->where);
	printf("\n");
}

static int test_query(TALLOC_CTX *ctx, t_select_stmt *select)
{
	struct wsp_request request;
	struct wsp_crestrictionarray *restrictionset = NULL;
	const char *restrictionset_expr = NULL;
	NTSTATUS status;
	ZERO_STRUCT(request);
	dump_sql(select);
	create_querysearch_request(ctx, &request, select);

	restrictionset =
		&request.message.cpmcreatequery.restrictionarray.restrictionarray;

	restrictionset_expr =
		raw_restriction_to_string(ctx,
				    &restrictionset->restrictions[0]);
	if (restrictionset_expr == NULL) {
		status = NT_STATUS_UNSUCCESSFUL;
	} else {
		status = NT_STATUS_OK;
	}
	if (NT_STATUS_IS_OK(status)) {
		printf("restriction expression =>%s<=\n", restrictionset_expr);
	} else {
		printf("error status %s\n",
			nt_errstr(status));
	}
	return 0;
}
#endif

/* send connectin message */
static NTSTATUS connect(TALLOC_CTX *ctx,
			struct wsp_client_ctx *wsp_ctx,
			const char* clientmachine,
			const char* clientuser,
			const char* server,
			bool *is_64bit)
{
	struct wsp_request *request;
	struct wsp_response *response;
	uint32_t client_ver;
	uint32_t server_ver;
	DATA_BLOB unread;
	NTSTATUS status;
	TALLOC_CTX *local_ctx = talloc_new(ctx);

	ZERO_STRUCT(unread);

	request = talloc_zero(local_ctx, struct wsp_request);
	response = talloc_zero(local_ctx, struct wsp_response);

	init_connectin_request(local_ctx, request,
			       clientmachine, clientuser, server);

	status =  wsp_request_response(local_ctx, wsp_ctx, request, response, &unread);
	if (NT_STATUS_IS_OK(status)) {
		client_ver = request->message.cpmconnect.iclientversion;
		server_ver = response->message.cpmconnect.server_version;
		*is_64bit = (server_ver & 0xffff0000) && (client_ver & 0xffff0000);
	}
	data_blob_free(&unread);
	TALLOC_FREE(local_ctx);
	return status;
}

static NTSTATUS create_query(TALLOC_CTX *ctx,
			     struct wsp_client_ctx *wsp_ctx,
			     t_select_stmt *select,
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

	create_querysearch_request(ctx, request, select);
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
				t_select_stmt *select,
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
	create_setbindings_request(ctx, request, select, cursor);
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



static NTSTATUS print_rowsreturned(
				TALLOC_CTX *ctx,
				DATA_BLOB *buffer,
				bool is_64bit,
				bool disp_all_cols,
				struct wsp_cpmsetbindingsin *bindings,
				uint32_t cbreserved,
				uint64_t address,
				uint32_t rowsreturned,
				uint32_t *rows_processed)
{
	NTSTATUS status;
	int row = 0;
	TALLOC_CTX *local_ctx = talloc_init("results");
	struct wsp_cbasestoragevariant **rowsarray =
		talloc_zero_array(local_ctx,
			struct wsp_cbasestoragevariant*,
			rowsreturned);

	enum ndr_err_code err = extract_rowsarray(rowsarray,
			buffer,
			is_64bit,
			bindings,
			cbreserved,
			address,
			rowsreturned,
			rowsarray);

	if (err) {
		DBG_ERR("failed to extract rows from getrows response\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	for(; row < rowsreturned; row++) {
		TALLOC_CTX *row_ctx = talloc_init("row");
		const char *col_str = NULL;
		if (disp_all_cols) {
			int i;
			for (i = 0; i < bindings->ccolumns; i++){
				col_str =
					variant_as_string(
						row_ctx,
						&rowsarray[row][i],
						true);
				if (col_str) {
					printf("%s%s",
						i ? ", " : "", col_str);
				} else {
					printf("%sN/A",
						i ? ", " : "");
				}
			}
		} else {
			col_str = variant_as_string(
					row_ctx,
					&rowsarray[row][0],
					true);
			printf("%s", col_str);
		}
		printf("\n");
		TALLOC_FREE(row_ctx);
	}
	TALLOC_FREE(local_ctx);
	status = NT_STATUS_OK;
out:
	*rows_processed = row;
	return status;
}

static NTSTATUS create_getrows(TALLOC_CTX *ctx,
			       struct wsp_client_ctx *wsp_ctx,
			       struct wsp_cpmsetbindingsin *bindings,
			       uint32_t cursor,
			       uint32_t nrows,
			       bool disp_all_cols,
			       bool is_64bit)
{
	struct wsp_request *request;
	struct wsp_response *response;
	NTSTATUS status;
	DATA_BLOB unread;
	uint32_t bmk = 0;
	uint32_t skip = 0;
	uint32_t requested_rows = 0;
	uint32_t total_rows = 0;
	uint32_t INITIAL_ROWS = 32;
	uint32_t rows_printed;
	uint32_t current_row = 0;
	TALLOC_CTX *row_ctx;
	ZERO_STRUCT(unread);

	while (total_rows != nrows) {
		row_ctx = talloc_new(ctx);
		if (!row_ctx) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
		request = talloc_zero(row_ctx, struct wsp_request);
		response = talloc_zero(request, struct wsp_response);
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

		create_seekat_getrows_request(request,
					request,
					cursor,
					bmk,
					skip,
					requested_rows,
					40,
					0xDEAbd860,
					bindings->brow,
					0);

		status = wsp_request_response(request, wsp_ctx, request, response, &unread);
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
		status = print_rowsreturned(request, &unread,
				is_64bit,
				disp_all_cols,
				bindings, 40,
				0xDEAbd860,
				response->message.cpmgetrows.rowsreturned,
				&rows_printed);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
		current_row += rows_printed;
		data_blob_free(&unread);
		TALLOC_FREE(row_ctx);
	}
out:
	TALLOC_FREE(row_ctx);
	return status;
}


const char *default_column = "System.ItemUrl";

static bool is_valid_kind(const char *kind)
{
	const char* kinds[] = {"calendar",
		"communication",
		"contact",
		"document",
		"email",
		"feed",
		"folder",
		"game",
		"instantMessage",
		"journal",
		"link",
		"movie",
		"music",
		"note",
		"picture",
		"program",
		"recordedtv",
		"searchfolder",
		"task",
		"video",
		"webhistory"};
	char* search_kind = NULL;
	int i;
	bool found = false;
	search_kind = strlower_talloc(NULL, kind);
	if (search_kind == NULL) {
		DBG_ERR("couldn't convert %s to lower case\n",
				search_kind);
		return NULL;
	}
	for (i=0; i<ARRAY_SIZE(kinds); i++) {
		if (strequal(search_kind, kinds[i])) {
			found = true;
			break;
		}
	}
	if (found == false) {
		DBG_ERR("Invalid kind %s\n", kind);
	}
	TALLOC_FREE(search_kind);
	return found;
}
static char * build_default_sql(TALLOC_CTX *ctx,
				const char *kind,
				const char *phrase,
				const char *location)
{
	char *sql = NULL;

	sql = talloc_asprintf(ctx,
		"Scope:\"%s\"  AND NOT System.Shell.SFGAOFlagsStrings:hidden"
		"  AND NOT System.Shell.OmitFromView:true", location);

	if (kind) {
		if (!is_valid_kind(kind)) {
			return NULL;
		}
		sql = talloc_asprintf(ctx, "System.Kind:%s AND %s",
					kind, sql);
	}

	if (phrase) {
		sql = talloc_asprintf(ctx,
				"All:$=\"%s\" OR All:$<\"%s\""
				" AND %s", phrase, phrase, sql);
	}
	sql =  talloc_asprintf(ctx, "SELECT %s"
				" WHERE %s", default_column, sql);
	return sql;
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
	char* query = NULL;
	bool custom_query = false;
	const char* phrase = NULL;
	const char* kind = NULL;
	uint32_t limit = 500;
	uint32_t nrows = 0;
	struct wsp_cpmsetbindingsin bindings_used;
	bool is_64bit = false;
	struct poptOption long_options[] = {
                POPT_AUTOHELP
		{ "limit", 0, POPT_ARG_INT, &limit, 0, "limit results", "default is 500, specifying 0 means unlimited" },
		{ "search", 0, POPT_ARG_STRING, &phrase, 0, "Search phrase", "phrase" },
		{ "kind", 0, POPT_ARG_STRING, &kind, 0, "Kind of thing to search for [Calendar|Communication|Contact|Document|Email|Feed|Folder|Game|InstantMessage|Journal|Link|Movie|Music|Note|Picture|Program|RecordedTV|SearchFolder|Task|Video|WebHistory]", "kind" },
		{ "query", 0, POPT_ARG_STRING, &query, 0, "specify a more complex query", "query" },
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
	t_select_stmt *select_stmt;

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
	if (!path || limit < 0) {
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

	if (server) {
		/*
		 * if we specify --query then we don't need actually need the
		 * share part, if it is specified then we don't care as we
		 * expect the scope to be part of the query (and if it isn't
		 * then it will probably fail anyway)
		 */
		share = strchr_m(server,'\\');
		if (!query && !share) {
			DBG_ERR("Invalid argument\n");
			return -1;
		}
		if (share) {
			*share = 0;
			share++;
		}
	}


	DBG_INFO("server name is %s\n", server ? server : "N/A");
	DBG_INFO("share name is %s\n", share ? share : "N/A");
	DBG_INFO("search phrase is %s\n", phrase ? phrase : "N/A");
	DBG_INFO("search kind is %s\n", kind ? kind : "N/A");

	if (!query && (kind == NULL && phrase == NULL)) {
		poptPrintUsage(pc, stderr, 0);
		result = -1;
		goto out;
	}

	if (!query) {
		location = talloc_asprintf(talloc_tos(),
				"FILE://%s/%s", server, share);
		query = build_default_sql(talloc_tos(), kind, phrase, location);
		if (!query) {
			result = -1;
			goto out;
		}
	} else {
		custom_query = true;
	}

	select_stmt = get_wsp_sql_tree(query);

	poptFreeContext(pc);

	if (select_stmt == NULL) {
		printf("query failed\n");
		result = -1;
		goto out;
	}

	if (select_stmt->cols == NULL) {
		select_stmt->cols = talloc_zero(select_stmt, t_col_list);
		select_stmt->cols->num_cols = 1;
		select_stmt->cols->cols =
			talloc_zero_array(select_stmt->cols, char*, 1);
		select_stmt->cols->cols[0] =
			talloc_strdup(select_stmt->cols, default_column);
	}

#if DEVELOPER
	if (query) {
		result = test_query(talloc_tos(), select_stmt);
	}
#endif
	status = wsp_server_connect(talloc_tos(),
				    server,
				    ev_ctx,
				    popt_get_cmdline_credentials(),
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
			 cli_credentials_get_username(popt_get_cmdline_credentials()),
			 server,
			 &is_64bit);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to connect to wsp: %s\n",
		      nt_errstr(status));
		result = -1;
		goto out;
	}

	DBG_INFO("sending query\n");

	status = create_query(talloc_tos(), wsp_ctx, select_stmt, &cursor);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to send query: %s)\n",
		      nt_errstr(status));
		result = -1;
		goto out;
	}

	DBG_INFO("sending createbindings\n");
	/* set bindings */
	status = create_bindings(talloc_tos(), wsp_ctx, select_stmt, cursor, &bindings_used);
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

	printf("found %d results, returning %d \n", nrows, limit ? MIN(nrows, limit) : nrows);
	status = create_getrows(talloc_tos(),
				wsp_ctx,
				&bindings_used,
				bindings_used.hcursor,
				limit ? MIN(nrows, limit) : nrows,
				custom_query,
				is_64bit);
	result = 0;
out:
	TALLOC_FREE(frame);
	return result;
}
