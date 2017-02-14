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

#include <includes.h>
#include "wsp_srv_tracker_abs_if.h"
#include "wsp_gss.h"
#include "bin/default/librpc/gen_ndr/ndr_wsp.h"
#include "wsp_sparql_conv.h"
#include "serverid.h"
#include "messages.h"
#include "rpc_server/rpc_pipes.h"
#include "rpc_server/rpc_server.h"
#include "wsp_srv_tracker-sparql.h"
#include "smbd/proto.h"
#include "util/tevent_ntstatus.h"
#include "libcli/security/security.h"

struct dummy_async_state
{
	uint32_t dummy;
};

struct client_info {
	struct client_info *prev, *next;
	struct wsp_cpmconnectin *connectin;
	uint32_t query_id;
	uint32_t handle;
};

struct query_list {
	int nqueries;
	struct query_data *items;
};

struct wsp_abstract_state {
	struct client_info *client_info_map;
	struct query_list queries;
	uint64_t current_request_id;
	struct tevent_context *ev;
	struct sparql_ctx *sparql_ctx;
};

struct binding_data
{
	struct binding_data *prev, *next;
	struct wsp_ctablecolumn *columns;
	struct binding_result_mapper *result_converter;
	uint32_t ncols;
	uint32_t cursor_hndl;
};

struct binding_list {
	int nbindings;
	struct binding_data *items;
};

struct next_cursor_data {
	struct next_cursor_data *prev, *next;
	uint32_t cursor;
	uint32_t chapter;
	uint32_t index;
};

struct next_cursor_list {
	struct next_cursor_data *items;
};

struct query_data
{
	struct query_data *prev, *next;
	struct tracker_query_info *tracker_ctx;
	struct wsp_abstract_state *glob_data;
	int query_id;
	struct wsp_crestrictionarray restrictionset;
	enum sparql_server_query_state state;
	struct tracker_selected_cols cols_to_convert;
	struct binding_list bindings;
	struct next_cursor_list next_cursors;
	struct wsp_crowsetproperties rowsetproperties;
	struct connection_struct *vfs_conn;
	const char* where_filter;
	const char* share;
	bool no_index;
	bool wsp_enabled;
	/*
	 * current index set from index passed from last call to
	 * SetNextGetRowsPosition. (maybe we should just store the
	 * last chapter...)
	 */
	uint32_t current_index;
	uint32_t ncursors;
	uint32_t nrows; /* only set when query is finished */
	/*
	 * #FIXME current_url & current workid should be replaced by
	 * some sort of cache/hash of workid -> url
	 */
	const char* current_url;
	uint32_t  workid;
};

static struct client_info* find_client_info(
					uint32_t handle,
					struct wsp_abstract_state *glob_data)
{
	struct client_info *item = NULL;
	for (item = glob_data->client_info_map; item; item = item->next) {
		if (item->handle == handle) {
			break;
		}
	}
	return item;
}

static struct next_cursor_data *find_next_cursor_index(
						struct query_data *query_info,
						uint32_t cursor,
						uint32_t chapter)
{
	struct next_cursor_data *item = query_info->next_cursors.items;
	for (; item; item = item->next) {
		if (item->chapter == chapter && item->cursor == cursor) {
			return item;
		}
	}
	return NULL;
}

static struct query_data *find_query_info(uint32_t query_id,
					  struct wsp_abstract_state *globals)
{
	struct query_data *item;
	for (item = globals->queries.items; item; item = item->next) {
		if (item->query_id == query_id) {
			return item;
		}
	}
	return NULL;
}

static struct binding_data *find_bindings(uint32_t QueryIdentifier,
					  uint32_t CursorHandle,
					  struct wsp_abstract_state *globals)
{
	struct binding_data *item = NULL;
	struct query_data *query_data = find_query_info(QueryIdentifier,
							globals);
	if (query_data) {
		for (item = query_data->bindings.items; item;
						item = item->next) {
			if (item->cursor_hndl == CursorHandle) {
				return item;
			}
		}
	}
	return NULL;
}

/* release all data associated with query_info */
static int destroy_query_data(struct query_data *query_info)
{
	struct client_info* cli_item =
		query_info->glob_data->client_info_map;
	struct wsp_abstract_state *glob_data = query_info->glob_data;

	TALLOC_FREE(query_info->cols_to_convert.tracker_ids);
	DLIST_REMOVE(glob_data->queries.items, query_info);
	glob_data->queries.nqueries--;
	if (query_info->tracker_ctx) {
		TALLOC_FREE(query_info->tracker_ctx);
	} else {
		DBG_ERR("failed to retrieve tracker_ctx for handle %d\n",
		      query_info->query_id);
	}
	while(cli_item) {
		struct client_info *next_cli = cli_item->next;
		if (cli_item->handle == query_info->query_id) {
			DLIST_REMOVE(glob_data->client_info_map,
				     cli_item);
			TALLOC_FREE(cli_item);
		}
		cli_item = next_cli;
	}
	return 0;
}

const char * get_where_restriction_string(struct wsp_abstract_state *glob_data,
					  uint32_t id)
{
	/* search all open queries for where id */
	struct query_data *item = NULL;
	if (glob_data) {
		item = glob_data->queries.items;
	}
	for (;item;item = item->next) {
		if (item->query_id == id && item->where_filter) {
			return item->where_filter;
		}
	}
	return NULL;
}

static bool is_catalog_available(struct wspd_client_state *client_data,
				 const char *CatalogName)
{
	return strequal(CatalogName, "Windows\\SYSTEMINDEX");
}

static void store_client_information(struct wspd_client_state *client_state,
				     uint32_t QueryIdentifier,
				     struct wsp_cpmconnectin *ConnectMessage,
				     uint32_t NamedPipeHandle)
{
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct client_info *client_info = talloc_zero(glob_data,
						      struct client_info);
	client_info->handle = NamedPipeHandle;
	client_info->query_id = QueryIdentifier;
	client_info->connectin = ConnectMessage;
	DLIST_ADD_END(glob_data->client_info_map, client_info);
}

static void get_server_versions(struct wspd_client_state *client_state,
				uint32_t *dwWinVerMajor,
				uint32_t *dwWinVerMinor,
				uint32_t *dwNLSVerMajor,
				uint32_t *dwNLSVerMinor,
				uint32_t *serverVersion,
				bool *supportsVersioningInfo)
{
	*supportsVersioningInfo = false;
	/* 32 bit win7 */
	*serverVersion = 0x00000700;
}

struct run_new_query_state
{
	uint32_t *QueryParametersError;
	bool *CanQueryNow;
};

static void run_new_query_done(struct tevent_req *subreq);
static struct tevent_req *run_new_query_send(TALLOC_CTX *ctx,
			  struct wspd_client_state *client_state,
			  uint32_t QueryIdentifier,
			  struct wsp_ccolumnset *ProjectionColumnsOffsets,
			  struct wsp_crestrictionarray *RestrictionSet,
			  struct wsp_csortset *SortOrders,
			  struct wsp_ccategorizationset *Groupings,
			  struct wsp_crowsetproperties *RowSetProperties,
			  struct wsp_cpidmapper *PidMapper,
			  struct wsp_ccolumngrouparray *GroupArray,
			  uint32_t Lcid, uint32_t *QueryParametersError,
			  uint32_t **CursorHandlesList,
			  bool *fTrueSequential, bool *fWorkidUnique,
			  bool *CanQueryNow)
{
	struct query_data *query_info;
	const char *sparql_query;
	bool can_query_now = true;
	int i;
	const char *restriction_expr;
	const char *share = NULL;
	bool no_index = false;
	struct tevent_req *req, *subreq = NULL;
	struct run_new_query_state *state = NULL;
	uint32_t where_id;
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct pipes_struct *p = get_pipe(client_state);
	NTSTATUS status;
	*QueryParametersError = 0;

	req = tevent_req_create(ctx, &state, struct run_new_query_state);
	if (!req)
	{
		DBG_ERR("out of memory\n");
		return NULL;
	}

	state->QueryParametersError = QueryParametersError;
	state->CanQueryNow = CanQueryNow;
	if (!RestrictionSet) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto err_out;
	}

	query_info = talloc_zero(glob_data, struct query_data);
	if (!query_info) {
		DBG_ERR("out of memory\n");
		return NULL;
	}

	query_info->state = QUERY_IN_PROGRESS;
	query_info->query_id = QueryIdentifier;
	query_info->ncursors = Groupings ? Groupings->size +1 : 1;
	query_info->glob_data = glob_data;

	talloc_set_destructor(query_info, destroy_query_data);

	DLIST_ADD_END(glob_data->queries.items, query_info);
	glob_data->queries.nqueries++;

	/* might need to keep these for later use (e.g. whereid processing) */
	status = build_restriction_expression(query_info,
					glob_data,
					RestrictionSet,
					true,
					&restriction_expr,
					&share,
					&where_id);
	if (NT_STATUS_IS_OK(status)) {
		query_info->where_filter = restriction_expr;
	} else {
		DBG_ERR("error %s when creating filter string\n",
			nt_errstr(status));
		/*
		 * let this special error through, just don't
		 * actually run the query
		 */
		if (NT_STATUS_EQUAL(status,NT_STATUS(WIN_UPDATE_ERR))) {
			no_index = true;
			query_info->no_index = true;
		} else {
			*QueryParametersError = NT_STATUS_V(status);
			can_query_now = false;
			goto err_out;
		}
	}

	if (!share) {
		if (where_id) {
			struct query_data *tmp_data =
				find_query_info(where_id,
						glob_data);
			if (tmp_data) {
				share = tmp_data->share;
			}
		}
	}

	*CursorHandlesList = talloc_zero_array(query_info, uint32_t,
					       query_info->ncursors);
	/* allocate cursor id(s) */
	for (i = 0; i < query_info->ncursors; i++) {
		struct next_cursor_data *item = talloc_zero(query_info,
					struct next_cursor_data);
		*CursorHandlesList[i] = i + 1;

		/* initial index (with unchaptered chapter) */
		item->chapter = 0;
		item->cursor = *CursorHandlesList[i];
		item->index = 0;

		DLIST_ADD_END(query_info->next_cursors.items, item);
	}

	if (!share) {
		DBG_ERR("No share passed in the RestrictionSet\n");
		status = NT_STATUS_INVALID_PARAMETER;
		can_query_now = false;
		goto err_out;
	} else {
		char *service;
		int snum = find_service(query_info, share, &service);
		struct conn_struct_tos *c = NULL;
		const struct loadparm_substitution *lp_sub =
			loadparm_s3_global_substitution();
		DBG_INFO("SHARE %s has indexing = %s\n", share,
			lp_wsp(snum) ? "enabled" : "disabled");
		query_info->share = talloc_strdup(query_info,share);
		query_info->wsp_enabled = lp_wsp(snum);
		if (query_info->wsp_enabled == false) {
			status = NT_STATUS_OK;
			goto err_out;
		}
		if ((snum == -1) || (service == NULL)) {
			DBG_ERR("share %s not found\n", share);
			status = NT_STATUS_INVALID_PARAMETER;
			can_query_now = false;
			goto err_out;
		}

		/*
		 * due to changes in create_conn_struct_tos this
		 * may no longer work (or be in scope) as
		 * expected (maybe we need a hacky talloc_steal)
		 */
		status = create_conn_struct_tos(p->msg_ctx,
					    snum,
					    lp_path(query_info, lp_sub, snum),
					    p->session_info,
					    &c);

		if (NT_STATUS_IS_OK(status)) {
			query_info->vfs_conn = c->conn;
			talloc_steal(query_info, c);
		}
		DBG_INFO("CONNECTION status = %s\n", nt_errstr(status));
	}

	talloc_steal(query_info, RestrictionSet->restrictions);

	status = build_tracker_query(query_info,
				     ProjectionColumnsOffsets,
				     restriction_expr,
				     PidMapper,
				     &query_info->cols_to_convert,
				     SortOrders,
				     true,
				     &sparql_query);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("error %s when creating tracker query\n",
		        nt_errstr(status));
		can_query_now = false;
		goto err_out;
	}

	query_info->rowsetproperties = *RowSetProperties;
	query_info->restrictionset = *RestrictionSet;

	*fWorkidUnique = false;
	if (!no_index && can_query_now) {
		uint32_t bool_opts =
			query_info->rowsetproperties.ubooleanoptions;
		bool cache_results =
			!(bool_opts & EDONOTCOMPUTEEXPENSIVEPROPS);
		subreq = glib_tracker_new_query(state,
						glob_data->sparql_ctx,
						QueryIdentifier,
						sparql_query,
						cache_results,
						lp_wsp_result_limit(),
						query_info->vfs_conn,
						p->session_info,
						&query_info->tracker_ctx);
		if (!subreq) {
			DBG_ERR("failed to create tracker subquery\n");
			can_query_now = false;
			status = NT_STATUS_UNSUCCESSFUL;
			goto err_out;
		}
		/* kick off query */
		DBG_INFO("tracker-sparql query is \"%s\"\n", sparql_query);
		tevent_req_set_callback(subreq, run_new_query_done, req);
	}
	/*
	 * we don't keep the unique ids around, if we wanted to we would
	 * need to somehow map the tracker internal uuid to a 32 bit
	 * identifier, that seems a bit heavyweight
	 */
	status = NT_STATUS_OK;
	return req;
err_out:
	*CanQueryNow = can_query_now;
	*QueryParametersError = NT_STATUS_V(status);
	if (!tevent_req_nterror(req, status)) {
		tevent_req_done(req);
	}
	return tevent_req_post(req, glob_data->ev);
}

static void run_new_query_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	NTSTATUS status = NT_STATUS_OK;
	struct run_new_query_state *state =
		tevent_req_data(req, struct run_new_query_state);
	if (tevent_req_is_nterror(subreq, &status)) {
		*state->CanQueryNow = false;
		*state->QueryParametersError = NT_STATUS_V(status);
	} else {
		*state->CanQueryNow = true;
		*state->QueryParametersError = NT_STATUS_V(NT_STATUS_OK);
	}
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static void set_bindings(struct wspd_client_state *client_state,
			 uint32_t QueryIdentifier,
			 uint32_t CursorHandle,
			 struct wsp_ctablecolumn *Columns,
			 uint32_t nColumns)
{
	struct query_data * query_data;
	struct binding_data *binding;
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	query_data = find_query_info(QueryIdentifier,
				     glob_data);
	DBG_INFO("got bindings for %d columns %p\n", nColumns, Columns);
	binding = talloc_zero(query_data, struct binding_data);
	binding->columns = Columns;
	binding->ncols = nColumns;
	binding->cursor_hndl = CursorHandle;
	/*
	 * need to create a mapping between the tracker cols returned
	 * and the binding columns requested
	 */
	binding->result_converter = talloc_zero(binding,
						struct binding_result_mapper);

	build_mapper(binding, Columns, nColumns,
		     &query_data->cols_to_convert, binding->result_converter);
	DLIST_ADD_END(query_data->bindings.items, binding);
	query_data->bindings.nbindings++;
}

static bool has_bindings(struct wspd_client_state *client_state,
			 uint32_t QueryIdentifier,
			 uint32_t CursorHandle)
{
	struct binding_data *item = NULL;
	struct wsp_abstract_state *glob_data =
					client_state->wsp_abstract_state;
	item = find_bindings(QueryIdentifier, CursorHandle, glob_data);
	if (item) {
		return true;
	}
	return false;
}

struct get_tracker_query_state
{
	uint32_t *status;
	uint32_t *nrows;
};

static void get_tracker_query_done(struct tevent_req *subreq);
static struct tevent_req *get_tracker_query_status(TALLOC_CTX *ctx,
				     struct wsp_abstract_state *glob_data,
				     uint32_t QueryIdentifier,
				     uint32_t *status,
				     uint32_t *nrows)
{
	bool no_index;
	struct get_tracker_query_state *state = NULL;
	struct query_data *query_info = find_query_info(QueryIdentifier,
							glob_data);
	struct tevent_req *req, *subreq;
	NTSTATUS ntstatus = NT_STATUS_OK;
	if (!query_info) {
		return NULL;
	}

	req = tevent_req_create(ctx, &state,
		struct get_tracker_query_state);

	if (!req) {
		return NULL;
	}

	state->status = status;
	state->nrows = nrows;

	no_index = query_info->no_index;


	if (!no_index) {
		subreq = glib_tracker_query_status(state,
						   query_info->tracker_ctx,
						   state->status,
						   state->nrows);
		if (!subreq) {
			DBG_ERR("communication with tracker server failed\n");
			ntstatus = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
		tevent_req_set_callback(subreq, get_tracker_query_done, req);
	} else {
		*status = QUERY_COMPLETE;
		*nrows = 0;
		goto out;
	}
	return req;
out:
	if (!tevent_req_nterror(req, ntstatus)) {
		tevent_req_done(req);
	}
	return tevent_req_post(req, glob_data->ev);
}

static void get_tracker_query_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
			tevent_req_callback_data(subreq, struct tevent_req);
	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	TALLOC_FREE(subreq);
	if (has_error) {
		tevent_req_nterror(req, status);
	} else {
		tevent_req_done(req);
	}
}

struct get_query_status_state
{
	uint32_t *QueryStatus;
	uint32_t nrows;
	struct query_data *query_data;
};


static void get_query_status_done(struct tevent_req *subreq);
static struct tevent_req *get_query_status_send(
					TALLOC_CTX *ctx,
					struct wspd_client_state *client_state,
					uint32_t QueryIdentifier,
					uint32_t *QueryStatus)
{
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct query_data *query_data = find_query_info(QueryIdentifier,
							glob_data);
	struct tevent_req *req, *subreq = NULL;
	struct get_query_status_state *state = NULL;

	req = tevent_req_create(ctx, &state,
				struct get_query_status_state);
	if (!req) {
		return NULL;
	}
	state->QueryStatus = QueryStatus;
	state->query_data = query_data;

	if (query_data->wsp_enabled == false) {
		*QueryStatus = 2;
		tevent_req_nterror(req, NT_STATUS_OK);
		tevent_req_done(req);
		return tevent_req_post(req, glob_data->ev);
	}
	subreq = get_tracker_query_status(state, glob_data, QueryIdentifier,
					  &query_data->state, &state->nrows);
	if (!subreq) {
		tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
		return tevent_req_post(req, glob_data->ev);
	}
	tevent_req_set_callback(subreq, get_query_status_done, req);
	return req;
}

static void get_query_status_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
					struct tevent_req);
	struct get_query_status_state *state =  tevent_req_data(req,
					struct get_query_status_state);
	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	TALLOC_FREE(subreq);
	if (has_error) {
		tevent_req_nterror(req, status);
		return;
	}
	switch(state->query_data->state) {
		case QUERY_IN_PROGRESS:
			*state->QueryStatus = STAT_BUSY;
			break;
		case QUERY_COMPLETE:
			*state->QueryStatus = STAT_DONE;
			state->query_data->nrows = state->nrows;
			break;
		case QUERY_ERROR:
		case IDLE:
		default:
			*state->QueryStatus = STAT_ERROR;
			break;
	}
	tevent_req_done(req);
}

struct get_ratiofinished_state
{
	struct query_data *query_data;
	uint32_t *rdwRatioFinishedDenominator;
	uint32_t *rdwRatioFinishedNumerator;
	uint32_t *cRows;
	uint32_t *fNewRows;
	uint32_t rows;
};

static void get_ratiofinished_params_done(struct tevent_req *subreq);
static struct tevent_req *get_ratiofinished_params_send(TALLOC_CTX *ctx,
				     struct wspd_client_state *client_state,
				     uint32_t QueryIdentifier,
				     uint32_t CursorHandle,
				     uint32_t *rdwRatioFinishedDenominator,
				     uint32_t *rdwRatioFinishedNumerator,
				     uint32_t *cRows,
				     uint32_t *fNewRows)
{
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct query_data *query_data = find_query_info(QueryIdentifier,
							glob_data);
	int rows = 0;
	struct tevent_req *req, *subreq = NULL;
	struct get_ratiofinished_state *state = NULL;
	NTSTATUS status;
	req = tevent_req_create(ctx, &state,
				struct get_ratiofinished_state);

	state->query_data = query_data;
	state->rdwRatioFinishedDenominator = rdwRatioFinishedDenominator;
	state->rdwRatioFinishedNumerator = rdwRatioFinishedNumerator;
	state->cRows = cRows;
	state->fNewRows = fNewRows;
	if (query_data) {
		if (query_data->wsp_enabled == false) {
			status = NT_STATUS_OK;
			goto early_out;
		}
		if (query_data->state == QUERY_COMPLETE) {
			rows = query_data->nrows;
			status = NT_STATUS_OK;
		} else {
			subreq = get_tracker_query_status(state,
							  glob_data,
							  QueryIdentifier,
							  &query_data->state,
							  &state->rows);
			if (!subreq) {
				status = NT_STATUS_UNSUCCESSFUL;
				goto out;
			}
			tevent_req_set_callback(req,
						get_ratiofinished_params_done,
						req);
			return req;
		}
	}
early_out:
	*rdwRatioFinishedDenominator = 0;
	*rdwRatioFinishedDenominator = rows;
	*cRows = rows; /* MS-WSP says client dont use it */
	*fNewRows = (rows > 0) ? 1 : 0;
out:
	if (!tevent_req_nterror(req, status)) {

		tevent_req_done(req);
	}
	return tevent_req_post(req, glob_data->ev);
}

static void get_ratiofinished_params_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct get_ratiofinished_state *state =
			tevent_req_data(req, struct get_ratiofinished_state);

	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	TALLOC_FREE(subreq);

	if (has_error) {
		tevent_req_nterror(req, status);
		return;
	}

	if (state->query_data->state == QUERY_COMPLETE) {
		state->query_data->nrows = state->rows;
	}
	if (state->query_data->wsp_enabled == false) {
		tevent_req_done(req);
		return;
	}
	*state->rdwRatioFinishedDenominator = 0;
	*state->rdwRatioFinishedDenominator = state->rows;
	*state->cRows = state->rows; /* MS-WSP says client dont use it */
	*state->fNewRows = (state->rows > 0) ? 1 : 0;;
	tevent_req_done(req);
}

static uint32_t get_approximate_position(struct wspd_client_state *client_state,
				     uint32_t QueryIdentifier,
				     uint32_t CursorHandle,
				     uint32_t Bmk)
{
	/*
	 * not sure how to handle this yet, somehow it seems bookmarks
	 * must be exposed to the client from the row results, but...
	 * I am not sure how yet.
	 */
	return 0;
}

static uint32_t get_whereid(struct wspd_client_state *client_state,
			    uint32_t QueryIdentifier)
{
	return QueryIdentifier;
}

struct get_expensive_properties_state
{
	struct query_data *query_data;
	uint32_t *rcRowsTotal;
	uint32_t *rdwResultCount;
	uint32_t *Maxrank;
	uint32_t num_rows;
};

static void get_expensive_properties_done(struct tevent_req *subreq);
static struct tevent_req *get_expensive_properties_send(TALLOC_CTX *ctx,
					struct wspd_client_state *client_state,
					uint32_t QueryIdentifier,
					uint32_t CursorHandle,
					uint32_t *rcRowsTotal,
					uint32_t *rdwResultCount,
					uint32_t *Maxrank)
{
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct query_data *query_data = find_query_info(QueryIdentifier,
							glob_data);
	uint32_t boolean_options;
	uint32_t num_rows = 0;
	struct tevent_req *req, *subreq = NULL;
	struct get_expensive_properties_state *state = NULL;
	NTSTATUS status;
	*rcRowsTotal = 0;
	*rdwResultCount = 0;
	*Maxrank = 0;

	req = tevent_req_create(ctx, &state,
				struct get_expensive_properties_state);
	if (!req) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (query_data->wsp_enabled == false) {
		status = NT_STATUS_OK;
		goto out;
	}
	state->query_data = query_data;
	state->rcRowsTotal = rcRowsTotal;
	state->rdwResultCount = rdwResultCount;
	state->Maxrank = Maxrank;

	if (!query_data) {
		DBG_ERR("failed to find query for %d\n", QueryIdentifier);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}
	if (query_data->state == QUERY_COMPLETE) {
		num_rows = query_data->nrows;
		status = NT_STATUS_OK;
	} else {
		subreq = get_tracker_query_status(state, glob_data,
						  QueryIdentifier,
						  &query_data->state,
					 	  &state->num_rows);
		if (!subreq) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
		tevent_req_set_callback(subreq, get_expensive_properties_done,
					req);
		return req;
	}
out:
	if (!tevent_req_nterror(req, status)) {
		boolean_options = query_data->rowsetproperties.ubooleanoptions;
		if (!(boolean_options & EDONOTCOMPUTEEXPENSIVEPROPS)) {
			*rdwResultCount = num_rows;
			*rcRowsTotal = num_rows;
			/* how does one fake the makrank ? */
		}
		tevent_req_done(req);
	}
	return tevent_req_post(req, glob_data->ev);
}

static void get_expensive_properties_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
					struct tevent_req);
	struct get_expensive_properties_state *state =
		tevent_req_data(req, struct get_expensive_properties_state);
	bool boolean_options;
	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	TALLOC_FREE(subreq);

	if (has_error) {
		tevent_req_nterror(req, status);
		return;
	}

	if (state->query_data->state == QUERY_COMPLETE) {
		state->query_data->nrows = state->num_rows;
	}
	boolean_options = state->query_data->rowsetproperties.ubooleanoptions;
	if (!(boolean_options & EDONOTCOMPUTEEXPENSIVEPROPS)) {
		*state->rdwResultCount = state->num_rows;
		*state->rcRowsTotal = state->num_rows;
		/* how does one fake the makrank ? */
	}
	tevent_req_done(req);
}

struct get_state_state
{
	struct wsp_cpmcistateinout *out;
};

static void get_state_done(struct tevent_req *subreq);
static struct tevent_req *get_state_send(TALLOC_CTX *ctx,
				    struct wspd_client_state *client_state,
				    struct wsp_cpmcistateinout *out)
{
	struct tevent_req *req, *subreq = NULL;
	struct get_state_state *state = NULL;
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;

	req = tevent_req_create(ctx, &state, struct get_state_state);
	if (!req) {
		return NULL;
	}

	state->out = out;

	subreq = glib_tracker_getstate(state, glob_data->sparql_ctx, out);
	if (!subreq) {
		tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
		return tevent_req_post(req, glob_data->ev);
	}
	tevent_req_set_callback(subreq, get_state_done, req);
	return req;
}

static void get_state_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
				tevent_req_callback_data(subreq,
							struct tevent_req);
	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	TALLOC_FREE(subreq);
	if (has_error) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

struct get_rows_data_state
{
	TALLOC_CTX *ctx;
	struct tracker_getrowsout *rows;
	uint32_t *rows_left;
};

static void get_rows_data_done(struct tevent_req *subreq);
static struct tevent_req *get_rows_data_send(TALLOC_CTX *ctx,
			  struct wspd_client_state *client_state,
			  struct tracker_query_info *tracker_ctx,
			  struct tracker_getrowsout *rows, uint32_t index,
			  uint32_t rows_to_get, uint32_t fbwdfetch, uint32_t *rows_left)
{
	struct tevent_req *req, *subreq = NULL;
	struct get_rows_data_state *state = NULL;
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	bool reverse_fetch = (fbwdfetch == 1);
	req = tevent_req_create(ctx, &state, struct get_rows_data_state);
	if (!req) {
		return NULL;
	}

	state->rows_left = rows_left;
	state->rows = rows;
	state->ctx = ctx;

	subreq = glib_tracker_getrows(state, glob_data->sparql_ctx,
				      tracker_ctx, index, rows_to_get, reverse_fetch, rows);

	if (!subreq) {
		tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
		req = tevent_req_post(req, glob_data->ev);
		return req;
	}

	tevent_req_set_callback(subreq, get_rows_data_done, req);
	return req;
}

void get_rows_data_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
					struct tevent_req);
	struct get_rows_data_state *state =
			tevent_req_data(req, struct get_rows_data_state);
	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	TALLOC_FREE(subreq);

	if (has_error) {
		tevent_req_nterror(req, status);
		return;
	}
	*state->rows_left = state->rows->nrows_remaining;
	talloc_steal(state->ctx, state->rows->rows);
	tevent_req_done(req);
}

static void *get_value(int i, int j, struct tracker_col_data *col_val)
{
	void *value = NULL;
	switch (col_val->tracker_type) {
		case TRACKER_STRING:
			value = discard_const_p(void, col_val->type.string);
			DBG_DEBUG("String value[%d][%d] is %s\n",
				  i, j, col_val->type.string);
			break;
		case TRACKER_INTEGER:
			value = (void*)&col_val->type.integer;
			DBG_DEBUG("Integer value[%d][%d] is %lu\n",
				  i, j, col_val->type.integer);
			break;
		case TRACKER_BOOLEAN:
			value = (void*)&col_val->type.boolean;
			DBG_DEBUG("Boolean value[%d][%d] is %d(bool)\n",
				  i, j, col_val->type.boolean);
			break;
		case TRACKER_DOUBLE:
			value = (void*)&col_val->type.double_val;
			DBG_DEBUG("Double value[%d][%d] is %f(float)\n",
				  i, j, (float)col_val->type.double_val);
			break;
	}
	return value;
}

struct get_rows_state
{
	struct wsp_cbasestoragevariant **RowsArray;
	struct tracker_getrowsout *rows;
	struct auth_session_info *session_info;
	struct connection_struct *conn;
	struct wspd_client_state *client_state;
	uint32_t queryid;
	bool *NoMoreRowsToReturn;
	uint32_t *NumRowsReturned;
	uint32_t *Error;
	uint32_t cmaxresults;
	uint32_t remaining_rows;
	struct binding_data *binding;
	uint32_t nbinding_cols;
	struct map_data *map_data;
	uint32_t index;
};

static void get_rows_done(struct tevent_req *subreq);
static struct tevent_req *get_rows_send(TALLOC_CTX *ctx,
		     struct wspd_client_state *client_state,
		     uint32_t QueryIdentifier,
		     uint32_t CursorHandle,
		     uint32_t NumRowsRequested,
		     uint32_t FetchForward,
		     /* out */
		     struct wsp_cbasestoragevariant **RowsArray,
		     bool *NoMoreRowsToReturn,
		     uint32_t *NumRowsReturned,
		     uint32_t *Error)
{
	struct query_data *query_data;
	struct tevent_req *req = NULL, *subreq = NULL;
	struct get_rows_state *state;
	struct wsp_abstract_state *glob_data =
					client_state->wsp_abstract_state;
	struct pipes_struct *p = get_pipe(client_state);
	*NoMoreRowsToReturn = false;
	*NumRowsReturned = 0;
	*Error = 0;

	req = tevent_req_create(ctx, &state, struct get_rows_state);
	if (!req) {
		return NULL;
	}

	/* find the bindings associated with this query */
	state->client_state = client_state;
	state->queryid = QueryIdentifier;
	state->binding = find_bindings(QueryIdentifier,
				       CursorHandle,
				       glob_data);

	if (!state->binding) {
		*Error = E_UNEXPECTED;
		tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
		return tevent_req_post(req, glob_data->ev);
	}


	state->RowsArray = RowsArray;
	state->NoMoreRowsToReturn = NoMoreRowsToReturn;
	state->NumRowsReturned = NumRowsReturned;
	state->Error = Error;
	state->cmaxresults = 0;
	state->map_data = state->binding->result_converter->map_data;
	state->nbinding_cols = state->binding->ncols;

	query_data = find_query_info(QueryIdentifier, glob_data);
	if (query_data->state == QUERY_ERROR) {
		*Error = E_UNEXPECTED;
		tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
		return tevent_req_post(req, glob_data->ev);
	}

	if (query_data->wsp_enabled == false) {
		*NoMoreRowsToReturn = true;
		tevent_req_nterror(req, NT_STATUS_OK);
		tevent_req_done(req);
		return tevent_req_post(req, glob_data->ev);
	}

	state->conn = query_data->vfs_conn;
	state->cmaxresults = query_data->rowsetproperties.cmaxresults;
	state->session_info = p->session_info;
	if (state->cmaxresults &&
		NumRowsRequested > query_data->rowsetproperties.cmaxresults) {
		NumRowsRequested = query_data->rowsetproperties.cmaxresults;
	}

	/* current index was set from last call to SetNextGetRowsPosition */
	state->index = query_data->current_index;
	state->rows = talloc_zero(state, struct tracker_getrowsout);
	subreq = get_rows_data_send(state, client_state,
			       query_data->tracker_ctx,
			       state->rows,
			       state->index, NumRowsRequested,
			       FetchForward,
			       &state->remaining_rows);
	if (!subreq) {
		DBG_ERR("unexpected failure trying to return row data\n");
		*Error = E_UNEXPECTED;
		tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
		return tevent_req_post(req, glob_data->ev);
	}

	tevent_req_set_callback(subreq, get_rows_done, req);
	return req;
}

static bool has_access_toworkid(struct wspd_client_state *client_state,
				uint32_t QueryIdentifier,
				uint32_t Workid)
{
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct query_data *query_data = find_query_info(QueryIdentifier,
							glob_data);
	return can_access_workid(query_data->tracker_ctx, Workid);
}

static void get_rows_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct get_rows_state *state =
			tevent_req_data(req, struct get_rows_state);
	uint32_t rows_to_try = state->rows->nrows; /* this is how many rows we got */
	int i;
	int j;

	struct wsp_cbasestoragevariant **RowsArray = state->RowsArray;
	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	TALLOC_CTX *frame;
	if (has_error) {
		TALLOC_FREE(subreq);
		tevent_req_nterror(req, status);
		return;
	}

	frame = talloc_stackframe();
	/* try retrieve next 'rows_to_try' rows */
	for (i = 0; i < rows_to_try; i++) {
		/*
		 * try and convert the colums of stuff returned from tracker
		 * to the columns required for the bindings
		 */
		struct tracker_row *row_item = &state->rows->rows[i];
		struct row_conv_data *row_private_data =
			talloc_zero(subreq, struct row_conv_data);
		struct wsp_cbasestoragevariant *row;
		/*
		 * Here we deviate from the spec, we *don't* acl filter
		 * results before passing back to the client as we have
		 * already acl checked the results returned (and cached) from
		 * the query. Note: MS-WSP documentation is very ambiguous
		 * about how this filtering should work, the description to
		 * me seems to contradict itself and is very unclear.
		 * Also in practise with win8 at least it seems that the
		 * filtering is already done when the query returns
		 * (reflected in the num results contained in
		 * CPMGETQUERYSTATUSEX _cResultsFound response field.
		 */
		row = RowsArray[i];
		row_private_data->conn = state->conn;
		row = talloc_zero_array(state->RowsArray,
					struct wsp_cbasestoragevariant,
					state->nbinding_cols);

		RowsArray[i] = row;
		for (j = 0; j < state->nbinding_cols; j++) {
			struct wsp_ctablecolumn *bind_desc =
				&state->binding->columns[j];
			struct wsp_cbasestoragevariant *col_val =
				&row[j];
			DBG_DEBUG("about to process row[%d]col[%d] by using "
				   "tracker_col %d with result_converter %p\n",
				   i, j, state->map_data[j].col_with_value,
				   state->map_data[j].convert_fn);
			if (state->map_data[j].vtype != VT_NULL) {
				NTSTATUS conv_status;
				uint32_t val_col =
					state->map_data[j].col_with_value;
				struct tracker_col_data *trker_col;
				void *val;
				trker_col = &row_item->columns[val_col];
				val = get_value(i, j, trker_col);
				conv_status = state->map_data[j].convert_fn(
							RowsArray, col_val,
							bind_desc->vtype,
							trker_col->tracker_type,
							val,
							row_private_data);
				if (!NT_STATUS_IS_OK(conv_status)) {
					/* mark column as unprocessable */
					DBG_DEBUG("failed to process row "
						 "%d col %d, error: %s\n",
						 i, j,
						 nt_errstr(conv_status));
					col_val->vtype = VT_NULL;
				}
			} else {
				/* mark column as unprocessable or missing... */
				col_val->vtype = VT_NULL;
			}
		}
		(*state->NumRowsReturned)++;
	}

	/*
	 * if we returned the maxresults for a query, then say no-more
	 * available
	 */
	if (!state->remaining_rows
	   || (state->cmaxresults
	   && (state->index + *state->NumRowsReturned) >= state->cmaxresults)) {
		*state->NoMoreRowsToReturn = true;
	}
	TALLOC_FREE(frame);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static void set_nextgetrowsposition(struct wspd_client_state *client_state,
				    uint32_t QueryIdentifier,
				    uint32_t CursorHandle,
				    uint32_t Chapter,
				    uint32_t Index)
{
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct query_data *query_data = find_query_info(QueryIdentifier,
							glob_data);

	/*
	 * we store 0 based indices ala array indices but the GSS descriptions
	 * are 1 based.
	 */
	Index--;
	if (query_data) {
		struct next_cursor_data *next_cursor =
			find_next_cursor_index(query_data,
					       CursorHandle,
					       Chapter);
		if (next_cursor) {
			next_cursor->index = Index;
		}
		query_data->current_index = Index;
	}
}

static uint32_t get_nextgetrowsposition(struct wspd_client_state *client_state,
					uint32_t QueryIdentifier,
					uint32_t CursorHandle,
					uint32_t Chapter)
{
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct query_data *query_data = find_query_info(QueryIdentifier,
							glob_data);
	uint32_t index = 0;
	if (query_data) {
		struct next_cursor_data *next_cursor =
			find_next_cursor_index(query_data,
					       CursorHandle,
					       Chapter);
		if (next_cursor) {
			index = next_cursor->index;
			index--;
		}
		return index;
	}
	DBG_ERR("couldn't get index for queryid 0x%x cursor "
		 "handle 0x%x chapter 0x%x\n",
		  QueryIdentifier, CursorHandle, Chapter);
	/* shouldn't get here */
	return 0;
}

static uint32_t get_bookmarkpos(struct wspd_client_state *client_state,
				uint32_t QueryIdentifier,
				uint32_t CursorHandle,
				uint32_t bmkHandle)
{
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	uint32_t result = 0;
	if (bmkHandle == DBBMK_FIRST) {
		result = 1;
	} else if (bmkHandle == DBBMK_LAST) {
		struct query_data *query_data =
			find_query_info(QueryIdentifier, glob_data);
		if (!query_data) {
			DBG_ERR("no query_data for query id, something "
				 "pretty major wrong :/\n");
			/* #TODO perhaps we should abort */
			result = bmkHandle;
		} else {
			result = query_data->nrows;
		}
	} else {
		DBG_INFO("bmkHandle 0x%x\n", bmkHandle);
		result = bmkHandle;
	}
	return result;
}

static bool clientquery_has_cursorhandle(struct wspd_client_state *client_state,
					 uint32_t QueryIdentifier,
					 uint32_t CursorHandle)
{
	bool result;
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct query_data *query_data = find_query_info(QueryIdentifier,
							glob_data);
	struct next_cursor_data *item;
	if (!query_data) {
		DBG_ERR("no query_data for query id, something "
			 "pretty major wrong :/\n");
		result = false;
		goto out;
	}

	item = query_data->next_cursors.items;
	for (; item; item = item->next) {
		if (item->cursor == CursorHandle) {
			result = true;
			goto out;
		}
	}
	result = false;
out:
	return result;
}

static NTSTATUS set_scope_prio(struct wspd_client_state *client_state,
			       uint32_t QueryIdentifier,
			       uint32_t Priority)
{
	NTSTATUS status;
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct query_data * query_info = find_query_info(QueryIdentifier,
							 glob_data);
	if (!query_info) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	} else if (query_info->no_index){
		status = NT_STATUS(WIN_UPDATE_ERR);
		goto done;
	}
	status = NT_STATUS_OK;
done:
	return status;
}

static NTSTATUS get_query_stats(struct wspd_client_state *client_state,
				uint32_t QueryIdentifier,
				uint32_t *NumIndexedItems,
				uint32_t *NumOutstandingAdds,
				uint32_t *NumOutstandingModifies)
{
	NTSTATUS status;
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct query_data * query_info = find_query_info(QueryIdentifier,
							 glob_data);
	/* don't believe we can handle this, just init all to 0 */
	*NumIndexedItems = 0;
	*NumOutstandingAdds = 0;
	*NumOutstandingModifies = 0;
	if (!query_info) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	} else if (query_info->wsp_enabled == false) {
		DBG_ERR("indexing not available for share %s\n",
			 query_info->share);
		/*
		 * On windows we see that an indexed share that has
		 * indexing turned off seems to return zero results
		 * until such time as the client requests scope statistics
		 * if we sent the error below then the client will fall back
		 * to searching via smb.
		 */
		status = NT_STATUS(0x80070003);
		goto done;
	} else if (query_info->no_index){
		status = NT_STATUS(WIN_UPDATE_ERR);
		goto done;
	}
	status = NT_STATUS_OK;
done:
	return status;
}

static void get_last_unretrieved_evt(struct wspd_client_state *client_state,
				     uint32_t QueryIdentifier,
				     /* out */
				     uint32_t *Wid,
				     uint8_t *EventType,
				     bool *MoreEvents,
				     uint8_t *RowsetItemState,
				     uint8_t *ChangedItemState,
				     uint8_t *RowsetEvent,
				     uint64_t *RowsetEventData1,
				     uint64_t *RowsetEventData2)
{
	/* can't handle this */
	*Wid = 0;
	*EventType = 0;
	*MoreEvents = false;
	*RowsetItemState = 0;
	*ChangedItemState = 0;
	*RowsetEvent = 0;
	*RowsetEventData1 = 0;
	*RowsetEventData2 = 0;
}

static void remove_cursors_data(uint32_t cursor_handle,
				struct query_data *query_info)
{
	struct next_cursor_data *item = query_info->next_cursors.items;
	while (item) {
		struct next_cursor_data *tmp = item->next;
		if (item->cursor == cursor_handle) {
			DLIST_REMOVE(query_info->next_cursors.items, item);
			TALLOC_FREE(item);
			query_info->ncursors--;
			item = tmp;
		} else {
			item = item->next;
		}
	}
}

static uint32_t release_cursor(struct wspd_client_state *client_state,
			       uint32_t QueryIdentifier,
			       uint32_t CursorHandle)
{
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct query_data *query_info = find_query_info(QueryIdentifier,
							glob_data);
	struct binding_data *binding = find_bindings(QueryIdentifier,
						     CursorHandle,
						     glob_data);
	uint32_t ncursors = 0;
	if (binding && query_info) {
		DLIST_REMOVE(query_info->bindings.items, binding);
		TALLOC_FREE(binding);
		query_info->bindings.nbindings--;
		remove_cursors_data(CursorHandle, query_info);
	}
	return ncursors;
}

static struct tevent_req *release_query_send(TALLOC_CTX *ctx,
					struct wspd_client_state *client_state,
					uint32_t QueryIdentifier)
{
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct query_data *query_info = find_query_info(QueryIdentifier,
							glob_data);
	struct dummy_async_state *state;
	struct tevent_req *req = tevent_req_create(ctx, &state,
				struct dummy_async_state);
	if (!req) {
		return NULL;
	}

	if (query_info) {
		TALLOC_FREE(query_info);
	} else {
		DBG_ERR("failed to retrieve query associated with handle %d\n",			 QueryIdentifier);

	}
	return tevent_req_post(req, glob_data->ev);

}

static int destroy_wsp_abstract_state(struct wsp_abstract_state *glob_data)
{
	struct query_data *item = NULL;
	for (item = glob_data->queries.items; item;){
		struct query_data *next = item->next;
		TALLOC_FREE(item);
		item = next;
	}
	TALLOC_FREE(glob_data->sparql_ctx);
	return 0;
}

static struct wsp_abstract_state *initialise(struct tevent_context *event_ctx,
				  struct messaging_context *msg_ctx)
{
	struct wsp_abstract_state *wsp_abstract_state =
				talloc_zero(NULL, struct wsp_abstract_state);
	if (!wsp_abstract_state) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}

	talloc_set_destructor(wsp_abstract_state, destroy_wsp_abstract_state);

	wsp_abstract_state->client_info_map = talloc_zero(wsp_abstract_state,
							  struct client_info);
	if (!wsp_abstract_state->client_info_map) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}
	wsp_abstract_state->ev = event_ctx;
	wsp_abstract_state->sparql_ctx = init_sparql(event_ctx);
	if (!wsp_abstract_state->sparql_ctx) {
		DBG_ERR("failed to initialise tracker\n");
		return NULL;
	}
	return wsp_abstract_state;
}

static struct wsp_cpmconnectin *get_client_information(
					struct wspd_client_state *client_state,
					uint32_t QueryIdentifier)
{
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct client_info* client_info = find_client_info(QueryIdentifier,
							   glob_data);
	if (client_info) {
		return client_info->connectin;
	}
	return NULL;
}

static struct wsp_ctablecolumn* get_binding(
					struct wspd_client_state *client_state,
					uint32_t QueryIdentifier,
					uint32_t CursorHandle,
					uint32_t *ncols)
{
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct binding_data *binding_info = find_bindings(QueryIdentifier,
							  CursorHandle,
							  glob_data);

	if (binding_info) {
		*ncols  = binding_info->ncols;
		return binding_info->columns;
	}
	return NULL;
}

static struct wsp_abstract_interface concrete_impl = {
	.Initialise = initialise,
	.IsCatalogAvailable = is_catalog_available,
	.StoreClientInformation = store_client_information,
	.GetClientInformation = get_client_information,
	.GetServerVersions = get_server_versions,
	.GetState_send = get_state_send,
	.RunNewQuery_send = run_new_query_send,
	.ClientQueryHasCursorHandle = clientquery_has_cursorhandle,
	.GetQueryStatus_send = get_query_status_send,
	.GetRatioFinishedParams_send = get_ratiofinished_params_send,
	.GetApproximatePosition = get_approximate_position,
	.GetWhereid = get_whereid,
	.GetExpensiveProperties_send = get_expensive_properties_send,
	.HasBindings = has_bindings,
	.GetBookmarkPosition = get_bookmarkpos,
	.SetNextGetRowsPosition = set_nextgetrowsposition,
	.GetNextGetRowsPosition = get_nextgetrowsposition,
	.GetRows_send = get_rows_send,
	.HasAccessToWorkid = has_access_toworkid,
	.HasAccessToProperty = NULL,
	.GetPropertyValueForWorkid = NULL,
	.GetQueryStatusChanges = NULL,
	.SetBindings = set_bindings,
	.GetBindings = get_binding,
	.ReleaseCursor = release_cursor,
	.ReleaseQuery_send = release_query_send,
	.FindNextOccurrenceIndex = NULL,
	.GetLastUnretrievedEvent = get_last_unretrieved_evt,
	.GetQueryStatistics = get_query_stats,
	.SetScopePriority = set_scope_prio,
	.FilterOutScopeStatisticsMessages = NULL,
	.Inflect = NULL,
	.GenerateScopeStatisticsEvent = NULL,
};

struct wsp_abstract_interface *tracker_wsp_abs_interace(void)
{
	return &concrete_impl;
}
