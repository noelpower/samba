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
#include <tevent.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include "wsp_gss.h"
#include "bin/default/librpc/gen_ndr/ndr_wsp.h"
#include "wsp_sparql_conv.h"
#include "serverid.h"
#include "messages.h"
#include "rpc_server/rpc_pipes.h"
#include "rpc_server/rpc_server.h"
#include "wsp_srv_tracker_abs_if.h"
#include "util/tevent_ntstatus.h"

#define MSG_HEADER_SIZE 16

static struct client_info *find_client_info(uint32_t handle,
					    struct gss_state *gss_state);

struct dummy_async_state
{
};

enum wsp_server_state {
	NOT_INITIALISED,
	RUNNING,
};

struct uint32_list
{
	struct uint32_list *prev, *next;
	uint32_t number;
};

struct client_version_map {
	struct client_version_map *prev, *next;
	uint32_t fid_handle;
	uint32_t version;
};

struct client_info {
	struct client_info *prev, *next;
	uint32_t handle;
	uint32_t rowstart_index; /* index where 'rows' starts */
	uint32_t total_rows;     /* num rows stored*/
	bool nomorerowstoreturn; /* num rows stored*/
	/*includes those processed already*/
	struct wsp_cbasestoragevariant **rows;
};

struct wsp_client_data
{
	struct gss_state *gss_state;
	struct named_pipe_client *npc;
	uint32_t fid;
};

struct gss_state {

	struct uint32_list *ConnectedClientsIdentifiers;
	struct client_version_map *ConnectedClientVersions;
	struct client_info *client_info_map;
	enum wsp_server_state wsp_server_state;
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	struct wsp_abstract_state *wsp_abstract_state;
};

/* fake some indirection for future backend support */
static struct wsp_abstract_interface *get_impl(void)
{
	return tracker_wsp_abs_interace();
}

static struct uint32_list *get_connected_client_entry(uint32_t handle,
						struct gss_state *gss_state)
{
	struct uint32_list *item = gss_state->ConnectedClientsIdentifiers;
	for (; item; item = item->next) {
		DBG_INFO("compare 0x%x with 0x%x\n", (uint32_t)handle, (uint32_t)item->number);
		if (handle == item->number) {
			return item;
		}
	}
	return NULL;
}
static bool has_connected_client(uint32_t handle, struct gss_state *state)
{
	return get_connected_client_entry(handle, state) != NULL;
}

static bool extract_connectin_propsets(TALLOC_CTX *ctx,
				       struct wsp_request *request,
				       struct connectin_propsets *propset)
{
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	bool result = false;
	DATA_BLOB blob;
	blob.length = request->message.cpmconnect.cbblob1;
	blob.data = request->message.cpmconnect.propsets;
	ndr = ndr_pull_init_blob(&blob, ctx);
	err = ndr_pull_connectin_propsets(ndr, ndr_flags, propset);
	if (err) {
		DBG_ERR("Failed to pull propset from propset blob, error %d\n",	 err);
		goto out;
	}
	result = true;

out:
	return result;
}

static bool get_property(uint32_t propid, struct wsp_cdbpropset *props,
			 struct wsp_cdbprop **prop_result)
{
	bool result = false;
	int i;
	for (i = 0; i < props->cproperties; i++) {
		if (props->aprops[i].dbpropid == propid) {
			*prop_result = &props->aprops[i];
			result = true;
			break;
		}
	}
	return result;
}

/* stub for getting lcid */
static uint32_t get_lcid(void)
{
	/* en-us */
	return 0x00000409;
}

static uint32_t calculate_checksum(DATA_BLOB *blob, struct wsp_header *hdr)
{
	uint32_t i;
	/* point at payload */
	uint8_t *buffer = blob->data + MSG_HEADER_SIZE;
	uint32_t buf_size = blob->length - MSG_HEADER_SIZE;
	uint32_t nwords = buf_size/4;
	uint32_t offset = 0;
	uint32_t checksum = 0;

	for(i = 0; i < nwords; i++) {
		checksum += IVAL(buffer, offset);
		offset += 4;
	}

	checksum ^= XOR_CONST;
	checksum -= hdr->msg;
	return checksum;
}

static bool verify_checksum(DATA_BLOB *blob, struct wsp_header *hdr)
{
	return calculate_checksum(blob, hdr) == hdr->checksum;
}

/* MS-WSP 2.2.3.2, MS-WSP 3.1.5.2.1 */
static struct tevent_req *handle_connect(TALLOC_CTX *ctx,
				struct wspd_client_state *client,
				struct wsp_request *request,
				struct wsp_response *response,
				DATA_BLOB *in_data,
				DATA_BLOB *extra_out_blob,
				struct wsp_abstract_interface *abs_interface)
{
	NTSTATUS  status;
	uint32_t handle = client->client_data->fid;
	struct connectin_propsets propsets;
	struct wsp_cpmconnectin *client_info;
	struct wsp_cdbprop *catalog_name;
	struct uint32_list *item;
	struct client_version_map *version_info;
	uint32_t dwwinvermajor = 0;
	uint32_t dwwinverminor = 0;
	uint32_t dwnlsvermajor = 0;
	uint32_t dwnlsverminor = 0;
	uint32_t serverversion = 0;
	bool supportsversioninginfo = false;
	struct wsp_cpmconnectout *msg_out = &response->message.cpmconnect;
	struct dummy_async_state *state;
	struct tevent_req *req = tevent_req_create(
						ctx,
						&state,
						struct dummy_async_state);
	struct gss_state *gss_state = client->client_data->gss_state;
	ZERO_STRUCT(propsets);
	if (has_connected_client(handle, gss_state)) {
		DBG_ERR("error client %d is already connected\n", handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (!extract_connectin_propsets(state, request, &propsets)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (!get_property(DBPROP_CI_CATALOG_NAME, &propsets.propertyset1,
			  &catalog_name)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (catalog_name->vvalue.vtype != VT_LPWSTR) {
		DBG_ERR("incorrect type %d for DBPROP_CI_CATALOG_NAME \n",
		      catalog_name->vvalue.vtype);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (!abs_interface->IsCatalogAvailable(client,
				catalog_name->vvalue.vvalue.vt_lpwstr.value)){
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (request->message.cpmconnect.iclientversion > 0x00000109) {
		if (!verify_checksum(in_data, &request->header)) {
			DBG_ERR("invalid checksum 0x%x\n",
			      request->header.checksum);
			status = NT_STATUS_INVALID_PARAMETER;
			goto out;
		}
	}
	item = talloc_zero(gss_state,
			   struct uint32_list);
	item->number = handle;
	DLIST_ADD_END(gss_state->ConnectedClientsIdentifiers, item);

	/*
	 * TODO not quite sure about the queryidentifier, documentation
	 * is not clear to me, for the moment I use the handle as the
	 * query identifier (e.g. only one query is possible per client)
	 */
	abs_interface->StoreClientInformation(client,
					      (uint32_t)handle,
					      &request->message.cpmconnect,
					      handle);
	client_info = abs_interface->GetClientInformation(client,
							  handle);

	if (!client_info) {
		DBG_ERR("error, no client info for handle %d available\n",
		handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	version_info = talloc_zero(gss_state,
				   struct client_version_map);
	version_info->fid_handle = handle;
	version_info->version = request->message.cpmconnect.iclientversion;

	DLIST_ADD_END(gss_state->ConnectedClientVersions, version_info);
	/* we need to hold onto the cpmconnect message */
	talloc_steal(get_connected_client_entry(handle, gss_state),
						request);

	abs_interface->GetServerVersions(client,
					 &dwwinvermajor, &dwwinverminor,
					 &dwnlsvermajor,
					 &dwnlsverminor,
					 &serverversion,
					 &supportsversioninginfo);

	msg_out->server_version = serverversion;
	if (supportsversioninginfo) {
		msg_out->version_dependant.version_info.dwwinvermajor =
			dwwinvermajor;
		msg_out->version_dependant.version_info.dwwinverminor =
			dwwinverminor;
		msg_out->version_dependant.version_info.dwnlsvermajor =
			dwnlsvermajor;
		msg_out->version_dependant.version_info.dwnlsverminor =
			dwnlsverminor;
	}

	status = NT_STATUS_OK;
out:
	if (!tevent_req_nterror(req, status)) {
		tevent_req_done(req);
	}
	return tevent_req_post(req, gss_state->ev);
}

struct create_query_state
{
	uint32_t query_params_error;
	uint32_t num_cursor_handles;
	uint32_t *cursor_handles;
	bool ftrueseq;
	bool fworkid_unique;
	bool can_query_now;
	struct wsp_response *response;
	DATA_BLOB *extra_blob;
};

static void handle_createquery_done(struct tevent_req *subreq);

/* MS-WSP 2.2.3.4, MS-WSP 3.1.5.2.2 */
static struct tevent_req *handle_createquery(TALLOC_CTX *ctx,
			       struct wspd_client_state *client,
			       struct wsp_request *request,
			       struct wsp_response *response,
			       DATA_BLOB *in_data,
			       DATA_BLOB *extra_out_blob,
			       struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct gss_state *gss_state = client->client_data->gss_state;
	struct wsp_cpmcreatequeryin *query = &request->message.cpmcreatequery;
	struct wsp_ccolumnset *projected_col_offsets = NULL;
	struct wsp_crestrictionarray *restrictionset = NULL;
	struct wsp_csortset *sort_orders = NULL;
	struct wsp_ccategorizationset *groupings = NULL;
	struct wsp_crowsetproperties *rowsetproperties =
					&query->rowsetproperties;
	struct wsp_cpidmapper *pidmapper = &query->pidmapper;
	struct wsp_ccolumngrouparray *grouparray = &query->grouparray;

	struct client_info *info = find_client_info(handle, gss_state);
	struct tevent_req *req, *subreq = NULL;
	struct create_query_state *state = NULL;
	NTSTATUS status;

	if (!info) {
		info = talloc_zero(gss_state, struct client_info);
		info->handle = handle;
		DLIST_ADD_END(gss_state->client_info_map, info);
	}

	req = tevent_req_create(gss_state, &state, struct create_query_state);
	if (!req) {
		return NULL;
	}

	if (!verify_checksum(in_data, &request->header)) {
		DBG_ERR("invalid checksum 0x%x\n",
		      request->header.checksum);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error_out;
	}
	state->extra_blob = extra_out_blob;
	state->response = response;
	if (!has_connected_client(handle, gss_state)) {
		DBG_ERR("no record of connected client for handle %d\n",
		      handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error_out;
	}

	if (query->ccolumnsetpresent) {
		projected_col_offsets = &query->columnset.columnset;
	}
	if (query->crestrictionpresent) {
		restrictionset = &query->restrictionarray.restrictionarray;
	}
	if (query->csortsetpresent) {
		if (query->sortset.groupsortaggregsets.ccount) {
			struct wsp_cingroupsortaggregset* aggregset;
			aggregset =
				&query->sortset.groupsortaggregsets.sortsets[0];
			sort_orders = &aggregset->sortaggregset;
		}
	}
	if (query->ccategorizationsetpresent) {
		groupings = &query->ccategorizationset.ccategorizationset;
		if (groupings->size > 1) {
			DBG_WARNING("can't yet handle multiple categories\n");
			status = NT_STATUS_INVALID_PARAMETER;
			goto error_out;
		}
	}

	state->num_cursor_handles = groupings ? groupings->size + 1 : 1;
	subreq = abs_interface->RunNewQuery_send(ctx,
					    client,
					    handle,
					    projected_col_offsets,
					    restrictionset,
					    sort_orders,
					    groupings,
					    rowsetproperties,
					    pidmapper,
					    grouparray,
					    get_lcid(),
					    /* out */
					    &state->query_params_error,
					    &state->cursor_handles,
					    &state->ftrueseq,
					    &state->fworkid_unique,
					    &state->can_query_now);
	if (!subreq) {
		goto error_out;
	}

	tevent_req_set_callback(subreq, handle_createquery_done, req);
	return req;
error_out:
	if (!tevent_req_nterror(req, status)) {
		tevent_req_done(req);
	}
	return tevent_req_post(req, gss_state->ev);
}

static void handle_createquery_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
					struct tevent_req);
	struct create_query_state *state =  tevent_req_data(req,
					struct create_query_state);
	struct wsp_response *response =  state->response;
	uint32_t *pcursors = state->cursor_handles;
	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	int i;
	int pos = 0;
	talloc_free(subreq);

	if (has_error || !state->can_query_now || state->query_params_error) {
		if (has_error == false) {
			if(state->query_params_error) {
				status = NT_STATUS(state->query_params_error);
				DBG_DEBUG("copy error %s 0x%x from subrequest %p\n",
					  nt_errstr(status), NT_STATUS_V(status), subreq);
			} else {
				DBG_DEBUG("can_query_now=false, returning"
					  "NT_STATUS_INVALID_PARAMETER\n");
				status = NT_STATUS_INVALID_PARAMETER;
			}
		}
		tevent_req_nterror(req, status);
		return;
	}
	/*
	 * extra_blob is for tacking on typically dynamic content at the
	 * end of the message buffer that isn't easily (or at all)
	 * expressible in idl
	 */
	state->extra_blob->length =
				sizeof(uint32_t) * state->num_cursor_handles;
	state->extra_blob->data = talloc_zero_array(state,
						   uint8_t,
						   state->extra_blob->length);
	for (i = 0; i < state->num_cursor_handles; i++) {
		SIVAL(state->extra_blob->data, pos, pcursors[i]);
		pos += sizeof(uint32_t);
	}

	status = NT_STATUS_OK;
	response->header.status = NT_STATUS_V(status);
	tevent_req_done(req);
}

struct query_status_state
{
	uint32_t status;
	struct wsp_response *response;
};

static void handle_querystatus_done(struct tevent_req *subreq);


/* MS-WSP 2.2.3.6, MS-WSP 3.1.5.2.3 */
static struct tevent_req *handle_querystatus(TALLOC_CTX *ctx,
			       struct wspd_client_state *client,
			       struct wsp_request *request,
			       struct wsp_response *response,
			       DATA_BLOB *in_data,
			       DATA_BLOB *extra_out_blob,
			       struct wsp_abstract_interface *abs_interface)
{
	NTSTATUS  status;
	uint32_t handle = client->client_data->fid;
	uint32_t hcursor = request->message.cpmgetquerystatus.hcursor;
	struct tevent_req *req, *subreq = NULL;
	struct query_status_state *state;
	struct gss_state *gss_state = client->client_data->gss_state;
	req = tevent_req_create(gss_state, &state, struct query_status_state);
	if (!req) {
		return NULL;
	}
	state->status = NT_STATUS_V(NT_STATUS_OK);
	state->response = response;
	if (!has_connected_client(handle, gss_state)) {
		DBG_ERR("no record of connected client for handle %d\n",
		      handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (!abs_interface->ClientQueryHasCursorHandle(client,
						       handle, hcursor)) {
		DBG_ERR("no cursor %d for handle %d\n", hcursor, handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	subreq = abs_interface->GetQueryStatus_send(state,
						    client,
						    handle,
						    &state->status);
	tevent_req_set_callback(subreq, handle_querystatus_done, req);
	return req;
out:
	if (!tevent_req_nterror(req, status)) {
		tevent_req_done(req);
	}
	return tevent_req_post(req, gss_state->ev);
}

static void handle_querystatus_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct query_status_state *state =
			tevent_req_data(req, struct query_status_state);
	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	TALLOC_FREE(subreq);
	if (has_error) {
		tevent_req_nterror(req, status);
		return;
	}
	state->response->message.cpmgetquerystatus.qstatus = state->status;
	tevent_req_done(req);
}

struct handle_querystatusex_state
{
	struct wspd_client_state *client;
	struct wsp_response *response;
	struct wsp_cpmcistateinout cistate;
	struct wsp_abstract_interface *abs_interface;
	uint32_t rows;
	uint32_t handle;
	uint32_t has_newrows;
	uint32_t hcursor;
	uint32_t bmk;
};

static void handle_querystatusex_done(struct tevent_req *subreq);

/* MS-WSP 2.2.3.7, MS-WSP 3.1.5.2.4 */
static struct tevent_req *handle_querystatusex(TALLOC_CTX *ctx,
				 struct wspd_client_state *client,
				 struct wsp_request *request,
				 struct wsp_response *response,
				 DATA_BLOB *in_data,
				 DATA_BLOB *extra_out_blob,
				 struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	uint32_t hcursor = request->message.cpmgetquerystatusex.hcursor;
	uint32_t bmk = request->message.cpmgetquerystatusex.bmk;
	NTSTATUS status;
	struct tevent_req *req, *subreq = NULL;
	struct handle_querystatusex_state *state;
	struct gss_state *gss_state = client->client_data->gss_state;

	req = tevent_req_create(gss_state, &state,
				struct handle_querystatusex_state);
	ZERO_STRUCTP(state);
	state->client = client;
	state->response = response;
	state->abs_interface = abs_interface;
	state->handle = handle;
	state->hcursor = hcursor;
	state->bmk = bmk;
	if (!has_connected_client(handle, gss_state)) {
		DBG_ERR("no record of connected client for handle %d\n",
		      handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (!abs_interface->ClientQueryHasCursorHandle(client,
						       handle, hcursor)) {
		DBG_ERR("no cursor %d for handle %d\n", hcursor, handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}


	subreq = abs_interface->GetState_send(state, client,
					      &state->cistate);
	if (!subreq) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}
	tevent_req_set_callback(subreq, handle_querystatusex_done, req);
	return req;
out:
	if (!tevent_req_nterror(req, status)) {
		tevent_req_done(req);
	}
	return tevent_req_post(req, gss_state->ev);
}

static void getquerystatus_done(struct tevent_req *subreq);
static void handle_querystatusex_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct handle_querystatusex_state *state =
			tevent_req_data(req, struct handle_querystatusex_state);

	struct wsp_cpmgetquerystatusexout *out =
			&state->response->message.cpmgetquerystatusex;
	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	TALLOC_FREE(subreq);

	if (has_error) {
		tevent_req_nterror(req, status);
		return;
	}
	TALLOC_FREE(subreq);
	out->cfiltereddocuments = state->cistate.cfiltereddocuments;
	out->cdocumentstofilter = state->cistate.ctotaldocuments;

	subreq = state->abs_interface->GetQueryStatus_send(state,
						      state->client,
						      state->handle,
						      &out->qstatus);
	if (!subreq) {
		status = NT_STATUS_INVALID_PARAMETER;
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_set_callback(subreq, getquerystatus_done, req);
}

static void getratiofinished_done(struct tevent_req *subreq);
static void getquerystatus_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct handle_querystatusex_state *state =
			tevent_req_data(req, struct handle_querystatusex_state);

	struct wsp_cpmgetquerystatusexout *out =
			&state->response->message.cpmgetquerystatusex;
	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	TALLOC_FREE(subreq);
	if (has_error) {
		tevent_req_nterror(req, status);
		return;
	}
	subreq = state->abs_interface->GetRatioFinishedParams_send(state,
					      state->client,
					      state->handle,
					      state->hcursor,
					      &out->dwratiofinisheddenominator,
					      &out->dwratiofinishednumerator,
					      &state->rows,
					      &state->has_newrows);
	if (!subreq) {
		status = NT_STATUS_INVALID_PARAMETER;
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_set_callback(subreq, getratiofinished_done, req);
}

static void getexpensiveprops_done(struct tevent_req *subreq);
static void getratiofinished_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct handle_querystatusex_state *state =
			tevent_req_data(req, struct handle_querystatusex_state);

	struct wsp_cpmgetquerystatusexout *out =
			&state->response->message.cpmgetquerystatusex;
	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	TALLOC_FREE(subreq);
	if (has_error) {
		tevent_req_nterror(req, status);
		return;
	}
	out->irowbmk =
		state->abs_interface->GetApproximatePosition(state->client,
							     state->handle,
							     state->hcursor,
							     state->bmk);
	out->whereid = state->abs_interface->GetWhereid(state->client,
							state->handle);

	subreq = state->abs_interface->GetExpensiveProperties_send(
					      state,
					      state->client,
					      state->handle,
					      state->hcursor,
					      &out->crowstotal,
					      &out->resultsfound,
					      &out->maxrank);

	if (!subreq) {
		status = NT_STATUS_INVALID_PARAMETER;
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_set_callback(subreq, getexpensiveprops_done, req);
}

static void getexpensiveprops_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
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

/* MS-WSP 2.2.3.13, MS-WSP 3.1.5.2.5 */
static struct tevent_req *handle_getratiofinishedin(TALLOC_CTX *ctx,
				 struct wspd_client_state *client,
				 struct wsp_request *request,
				 struct wsp_response *response,
				 DATA_BLOB *in_data,
				 DATA_BLOB *extra_out_blob,
				 struct wsp_abstract_interface *abs_interface)
{
	NTSTATUS status;
	uint32_t handle = client->client_data->fid;
	struct gss_state *gss_state = client->client_data->gss_state;
	struct tevent_req *req = NULL;
	struct wsp_cpmratiofinishedin *ratio_in =
		&request->message.wsp_cpmratiofinished;
	struct wsp_cpmratiofinishedout *ratio_out =
		&response->message.wsp_cpmratiofinished;
	if (!has_connected_client(handle, gss_state)) {
		DBG_ERR("no record of connected client for handle %d\n",
		      handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}
	status = NT_STATUS_OK;
	req = abs_interface->GetRatioFinishedParams_send(ctx,
					      client,
					      handle,
					      ratio_in->hcursor,
					      &ratio_out->uldenominator,
					      &ratio_out->ulnumerator,
					      &ratio_out->crows,
					      &ratio_out->fnewrows);
	return req;
out:
	if (req) {
		if (!tevent_req_nterror(req, status)) {
			tevent_req_done(req);
		}
		req = tevent_req_post(req, gss_state->ev);
	}
	return req;
}

static bool push_column_value(TALLOC_CTX *ctx,
			       struct  wsp_cbasestoragevariant *col_val,
			       uint8_t *buf_start,
			       uint8_t *value_buf, uint8_t *row_buf,
			       uint32_t *cur_rowbuf_end_pos,
			       uint32_t *value_length,
			       uint32_t address_adjustment,
			       uint32_t row_boundry)
{
	switch (col_val->vtype) {
		case VT_BOOL:
		case VT_I2:
		case VT_UI2:
			SSVAL(value_buf, 8, col_val->vvalue.vt_ui2);
			break;
		case VT_UI4:
		case VT_I4:
		case VT_INT:
		case VT_UINT:
			SIVAL(value_buf, 8, col_val->vvalue.vt_ui4);
			break;
		case VT_FILETIME:
		case VT_UI8:
		case VT_I8:
		case VT_R8: {
			uint64_t hyper_val;
			struct wsp_hyper *phyper = &col_val->vvalue.vt_ui8;
			wsp_hyper_to_uint64(phyper, &hyper_val);
			SBVAL(value_buf, 8, hyper_val);
			break;
		}
		case VT_VECTOR | VT_LPWSTR:
		case VT_LPWSTR: {
			uint32_t address = 0;
			uint32_t offset = 8;
			bool is_vector = (col_val->vtype & VT_VECTOR);
			const char *str_val;
			*value_length = 0;
			/*
			 * if vector for testing at the moment just assume 1
			 * entry
			 */
			if (is_vector) {
				*value_length = 4; /* for 1 X 32bit address*/
				str_val = col_val->vvalue.vt_lpwstr_v.vvector_data[0].value;
			} else {
				str_val = col_val->vvalue.vt_lpwstr.value;
			}
			DBG_DEBUG("string value (vector = %s) is %s\n",
				is_vector ? "true" : "false", str_val);
			/* lenght is num bytes (including null term) */
			*value_length +=
				((strlen(str_val) + 1) * 2);
			*cur_rowbuf_end_pos =
				*cur_rowbuf_end_pos - *value_length;
			if (row_boundry >= *cur_rowbuf_end_pos) {
				/*
				 * col variant value about to corrupt
				 * fixed buffer
				*/
				DBG_NOTICE("col value overlapping fixed buffer "
					  "area\n");
				return false;
			}
			push_string(buf_start + *cur_rowbuf_end_pos,
				    str_val, ((strlen(str_val) + 1) * 2),
				    STR_UNICODE | STR_TERMINATE);

			address = *cur_rowbuf_end_pos + address_adjustment;
			if (is_vector) {
				/* #FIXME this is FSCK-ugly */
				/* store item1 address */
				SIVAL(buf_start,
				      *cur_rowbuf_end_pos + *value_length - 4,
				      address); /* 1 item */
				/*
				 * address where address of string vector item
				 * is stored
				 */
				address += *value_length - 4;
			}

			*value_length += 0x10; /* variant */

			if (is_vector) {
				SIVAL(value_buf, offset, 1); /* 1 item */
				offset += 4;
			}
			/* for 32 bit addressing */
			SIVAL(value_buf, offset, address);
			break;
		}
	}
	return true;
}

static bool push_column(TALLOC_CTX *ctx, struct wsp_ctablecolumn *tab_col,
			struct wsp_cbasestoragevariant *col_val,
			DATA_BLOB *blob, uint32_t *cur_rowbuf_end_pos,
			int row, uint32_t address_adjustment,
			uint32_t row_width, bool is_64bit)
{
	uint8_t *row_buff = blob->data + (row * row_width);
	uint32_t row_boundry = (row * row_width) + row_width;
	if (row_boundry >= *cur_rowbuf_end_pos) {
		/*
		 * abandon row processing, variant and fixed portions about
		 * to collide
		 */
		DBG_NOTICE("row too big to fit...\n");
		return false;
	}
	SSVAL(row_buff, 0, 0xdead);
	if (tab_col->statusused) {
		if (col_val->vtype == VT_NULL) {
			*(row_buff + tab_col->statusoffset.value) =
				STORESTATUSNULL;
		} else {
			*(row_buff + tab_col->statusoffset.value) =
				STORESTATUSOK;
		}
	}
	/* default value.. adjusted below if necessary when processing values */
	if (tab_col->lengthused) {
		SIVAL(row_buff, tab_col->lengthoffset.value, 0x10);
	}

	if (tab_col->valueused) {
		uint32_t new_length = 0;
		uint8_t *value_buf = row_buff + tab_col->valueoffset.value;
		SSVAL(value_buf, 0, col_val->vtype); /* vtype */
		if (col_val->vtype != VT_NULL) {
			bool ok;
			SSVAL(value_buf, 2, 0);  /* reserved1 */
			SIVAL(value_buf, 4, 0); /* reserved2 */
			ok = push_column_value(ctx, col_val, blob->data,
					       value_buf, row_buff,
					       cur_rowbuf_end_pos,
					       &new_length, address_adjustment,
					       row_boundry);
			if (!ok) {
				return false;
			}
			if (tab_col->lengthused && new_length) {
				SIVAL(row_buff,
				      tab_col->lengthoffset.value, new_length);
			}

		} else {
			SSVAL(value_buf, 0, VT_EMPTY); /* vtype */
		}
	}
	return true;
}

struct seekratio_data
{
	uint32_t crowstotal;
	uint32_t resultsfound;
	uint32_t maxrank;
};

struct getrows_state
{
	struct client_info *info;
	struct wspd_client_state *client;
	DATA_BLOB *extra_out_blob;
	struct wsp_cpmgetrowsin *rowsin;
	struct wsp_cpmgetrowsout *rowsout;
	struct wsp_abstract_interface *abs_interface;
	struct gss_state *gss_state;

	uint32_t pad_adjust;
	uint8_t* row_buff;
	uint32_t buf_size;
	uint32_t error;
	uint32_t ncols;
	uint32_t rowsreturned;
	uint32_t rows_requested;
	uint32_t cur_rowbuf_end_pos;
	uint32_t address_adjustment;
	uint32_t index;
	uint32_t handle;
	struct wsp_ctablecolumn *binding;
	bool nomorerowstoreturn;
	bool is_64bit; /* #TODO need to also check 64k mode */
	uint32_t *resp_status;
	struct seekratio_data *seekratio;
};

static void handle_getrows_done(struct tevent_req *subreq);

static void fill_rows_buffer(struct getrows_state *state,
			     struct gss_state *gss_state,
			     struct wsp_cbasestoragevariant **rowsarray)
{
	int i, j;
	uint32_t nrows = 0;
	uint32_t hcursor;
	uint32_t chapter;
	struct wsp_cbasestoragevariant *row;

	DATA_BLOB rows_blob;

	rows_blob.data = state->row_buff;
	rows_blob.length = state->buf_size;

	hcursor = state->rowsin->hcursor;
	chapter = state->rowsin->chapt;
	if (state->error) {
		*state->resp_status = NT_STATUS_V(NT_STATUS_INVALID_PARAMETER);
		return;
	}

	for (i = 0, nrows = 0; i < state->rowsreturned; i++) {
		row = rowsarray[i];
		for (j = 0; j < state->ncols; j++) {
			bool ok;
			struct wsp_cbasestoragevariant *col_val =
				&row[j];
			DBG_INFO("processing col[%d]\n", j);
			ok = push_column(state, &state->binding[j],
					 col_val, &rows_blob,
					 &state->cur_rowbuf_end_pos, i,
					 state->address_adjustment,
					 state->rowsin->cbrowWidth,
					 state->is_64bit);
			if (!ok) {
				DBG_NOTICE("readjusting rows returned from %d "
					 "to %d\n", state->rowsreturned, nrows);
				state->rowsreturned = nrows;
				/*
				 * reset nomorerowstoreturn if it's already set
				 * as we no longer are returning all rows
				 */
				if (state->nomorerowstoreturn) {
					state->nomorerowstoreturn = false;
				}
				break;
			}
		}
		nrows++;
	}

	state->abs_interface->SetNextGetRowsPosition(
					state->client,
					state->handle,
					hcursor, chapter,
					state->index + i);
	state->rowsout->rowsreturned = state->rowsreturned;
	state->rowsout->etype = 0;
	state->rowsout->chapt = state->rowsin->chapt;

	if (!state->nomorerowstoreturn
	    && (state->rows_requested != state->rowsreturned)) {
		if (state->rowsin->etype == EROWSEEKAT) {
			/* follow what windows seems to do, use a skip of 1 */
			uint32_t skip = 1;
			/*
	 		 * 3.1.5.2.6 Receiving a CPMGetRowsIn Request
			 * (bullet 5 - 10)
			 * MS-WSP is confusing here again, but.. at least by
			 * observation with SeekDescription etype EROWSEEKAT
			 * we set the response eType to be the eType from
			 * GetRowsIn *BUT* not copy it, instead we populate the
			 * bookmark offset with the index and skip values to
			 * allow the client restart the search.
			 * Note: we only seem to need to do this when we
			 *       haven't been able to fill the buffer with the
			 *       requested number of rows
			 * #FIXME not sure how we hande the other types
			 */
			state->rowsout->etype = state->rowsin->etype;
			state->rowsout->seekdescription.crowseekat.cskip = skip;

			state->rowsout->seekdescription.crowseekat.bmkoffset =
					state->index + i - 1 - skip;
		}
	}
	/*
	 * assuming no seekdescription we rewind row_buf back the max padding
	 */
	if (!state->rowsout->etype) {
		state->row_buff -= state->pad_adjust;
		state->buf_size += state->pad_adjust;
	}

	rows_blob.data = state->row_buff;
	rows_blob.length = state->buf_size;

	/* set up out param */
	*state->extra_out_blob = rows_blob;

	if (state->nomorerowstoreturn) {
		*state->resp_status = DB_S_ENDOFROWSET;
	}
}

static struct tevent_req *process_rows_for_index(TALLOC_CTX *ctx,
				   struct tevent_req *req,
				   struct getrows_state *state)
{
	uint32_t hcursor;
	uint32_t chapter;
	uint32_t handle;
	uint32_t fetchforward;
	struct wsp_abstract_interface *abs_interface = state->abs_interface;
	struct client_info *info = state->info;
	struct wsp_cpmgetrowsin *rowsin = state->rowsin;
	struct tevent_req* subreq;

	hcursor = state->rowsin->hcursor;
	chapter = state->rowsin->chapt;
	handle = state->handle;
	fetchforward = rowsin->fbwdfetch;
	if (state->index < 1) {
		/* something odd gone wrong */
		DBG_ERR("illegal value for index %d\n", state->index);
		goto error_out;
	}

	abs_interface->SetNextGetRowsPosition(state->client,
					      handle, hcursor,
					      chapter, state->index);
	state->binding = abs_interface->GetBindings(state->client,
						    handle, hcursor,
						    &state->ncols);
	/*
	 * allocate the full amount of possible padding (rowsin->cbreserved)
	 * note: cbreserved includes the header size (16) plus size of
	 * message (not including seekdescription) (12) + any possible
	 * seekdescription ( variable 0 - 12 bytes )
	 * e.g. if cbreserved is 40 then we increase the size of the
	 * buffer by 12 (thats the max padding), if the response message
	 * contains a seek description we need discard the seek description
	 * bytes from the start of the buffer.
	 *
	 */
	state->pad_adjust = (rowsin->cbreserved - (MSG_HEADER_SIZE + 12));

	state->buf_size =
		rowsin->cbreadbuffer - rowsin->cbreserved + state->pad_adjust;
	state->row_buff = talloc_zero_array(ctx, uint8_t, state->buf_size);

	/* position buffer to write into after max padding */
	state->row_buff = state->row_buff + state->pad_adjust;
	/* similary adjust size */
	state->buf_size = state->buf_size - state->pad_adjust;
	state->cur_rowbuf_end_pos = state->buf_size;
	state->address_adjustment = rowsin->ulclientbase + rowsin->cbreserved;

	info->rows = talloc_zero_array(info, struct wsp_cbasestoragevariant*,
				       rowsin->crowstotransfer);
	subreq = abs_interface->GetRows_send(state, state->client,
					     handle, hcursor,
					     rowsin->crowstotransfer,
					     fetchforward, info->rows,
					     &info->nomorerowstoreturn,
					     &info->total_rows, &state->error);
	if (!subreq) {
		goto error_out;
	}
	tevent_req_set_callback(subreq, handle_getrows_done, req);
	return req;
error_out:
	if (!tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER)) {
		tevent_req_done(req);
	}
	return tevent_req_post(req, state->gss_state->ev);
}

static void get_expensive_props_done(struct tevent_req *subreq);

/* MS-WSP 2.2.3.2, MS-WSP 3.1.5.2.6 */
static struct tevent_req *handle_getrows(TALLOC_CTX *ctx,
			   struct wspd_client_state *client,
			   struct wsp_request *request,
			   struct wsp_response *response,
			   DATA_BLOB *in_data,
			   DATA_BLOB *extra_out_blob,
			   struct wsp_abstract_interface *abs_interface)
{
	NTSTATUS status;
	uint32_t handle = client->client_data->fid;
	struct gss_state *gss_state = client->client_data->gss_state;
	struct wsp_cpmgetrowsin *rowsin = &request->message.cpmgetrows;
	struct wsp_cpmgetrowsout *rowsout = &response->message.cpmgetrows;
	uint32_t hcursor;
	uint32_t chapter;
	uint32_t oldindex;

	struct client_info *info = find_client_info(handle, gss_state);
	struct tevent_req *req = NULL, *subreq = NULL;
	struct getrows_state *state = NULL;

	if (!info) {
		DBG_ERR("no cached data for query with handle %d\n", handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	req = tevent_req_create(gss_state, &state, struct getrows_state);

	if (!req) {
		return NULL;
	}

	ZERO_STRUCTP(state);
	state->client = client;
	state->gss_state = client->client_data->gss_state;
	state->extra_out_blob = extra_out_blob;
	state->nomorerowstoreturn = true;
	state->resp_status = &response->header.status;
	state->is_64bit = false; /* #TODO need to also check 64k mode */
	state->abs_interface = abs_interface;
	state->rowsout = rowsout;
	state->handle = handle;
	state->info = info;
	state->rowsin = rowsin;
	state->rowsout = rowsout;

	hcursor = rowsin->hcursor;
	chapter = rowsin->chapt;
	state->rows_requested = rowsin->crowstotransfer;

	if (!has_connected_client(handle, gss_state)) {
		DBG_ERR("no record of connected client for handle %d\n",
		      handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (!verify_checksum(in_data, &request->header)) {
		DBG_ERR("invalid checksum 0x%x\n",
		      request->header.checksum);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (!abs_interface->ClientQueryHasCursorHandle(client,
						       handle, hcursor)) {
		DBG_ERR("no cursor %d for handle %d\n", hcursor, handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (!abs_interface->HasBindings(client, handle, hcursor)) {
		DBG_ERR("no bindings for handle %d and cursor %d\n",
			 handle, hcursor);
		status = NT_STATUS(E_UNEXPECTED);
		goto out;
	}

	oldindex = abs_interface->GetNextGetRowsPosition(client,
							 handle, hcursor,
							 chapter);
	switch (rowsin->etype) {
		case EROWSEEKNONE:
			state->index = oldindex;
			break;
		case EROWSEEKNEXT:
			state->index =
				oldindex + rowsin->seekdescription.crowseeknext.cskip;
			break;
		case EROWSEEKAT: {
			uint32_t cskip =
				rowsin->seekdescription.crowseekat.cskip;
			uint32_t bmkoffset =
				rowsin->seekdescription.crowseekat.bmkoffset;
			state->index = abs_interface->GetBookmarkPosition(
								client,
								handle,
								hcursor,
								bmkoffset);
			state->index += cskip;
			break;
		}
		case EROWSEEKATRATIO: {
			uint32_t ulnumerator =
				rowsin->seekdescription.crowseekatratio.ulnumerator;
			uint32_t uldenominator =
				rowsin->seekdescription.crowseekatratio.uldenominator;
			state->seekratio = talloc_zero(state,
						       struct seekratio_data);
			if (!uldenominator || uldenominator > ulnumerator) {
				/* DB_E_BADRATIO */
				response->header.status  = 0x80040E12;
				goto out;
			}


			subreq = abs_interface->GetExpensiveProperties_send(
					state,
					client,
					handle,
					hcursor,
					&state->seekratio->crowstotal,
					&state->seekratio->resultsfound,
					&state->seekratio->maxrank);

			if (!subreq) {
				goto out;
			}
			tevent_req_set_callback(subreq,
						get_expensive_props_done,
						req);
			return req;
			break;
		}
		case EROWSEEKBYBOOKMARK:

			DBG_ERR("etype EROWSEEKBYBOOKMARK is unsupported for "
				 "GetRowsIn message");
			status = NT_STATUS_INVALID_PARAMETER;
			goto out;
			break;
		default:
			DBG_ERR("illegal value for etype %d\n",
				 rowsin->etype);
			status = NT_STATUS_INVALID_PARAMETER;
			goto out;
			break;
	}

	return process_rows_for_index(state, req, state);
out:
	if (!tevent_req_nterror(req, status)) {
		tevent_req_done(req);
	}
	return tevent_req_post(req, gss_state->ev);
}

static void get_expensive_props_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct getrows_state *state =
			tevent_req_data(req, struct getrows_state);
	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	if (state->seekratio) {
		struct wsp_cpmgetrowsin *rowsin = state->rowsin;
		uint32_t ulnumerator =
			rowsin->seekdescription.crowseekatratio.ulnumerator;
		uint32_t uldenominator =
			rowsin->seekdescription.crowseekatratio.uldenominator;
		uint32_t crowstotal = state->seekratio->crowstotal;
		state->index = (ulnumerator/uldenominator) * crowstotal;
	}
	TALLOC_FREE(subreq);

	if (has_error) {
		tevent_req_nterror(req, status);
		return;
	}
	process_rows_for_index(state, req, state);
}

static void handle_getrows_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct getrows_state *state =
				tevent_req_data(req, struct getrows_state);
	struct wsp_cbasestoragevariant **rows;
	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	TALLOC_FREE(subreq);
	if (has_error) {
		tevent_req_nterror(req, status);
		return;
	}
	rows = state->info->rows;
	state->info->rowstart_index = state->index;

	state->nomorerowstoreturn = state->info->nomorerowstoreturn;
	if (state->info->total_rows >= state->rows_requested) {
		/*
		 * if total_rows we got is what we asked for it's
		 * possible that there are no more rows to get
		 */
		if (state->info->total_rows != state->rows_requested) {
			state->nomorerowstoreturn = false;
		}
		state->rowsreturned = state->rows_requested;
	} else {
		state->rowsreturned = state->info->total_rows;
	}
	fill_rows_buffer(state, state->gss_state, rows);
	tevent_req_done(req);
}


/* MS-WSP 2.2.3.10, MS-WSP 3.1.5.2.8 */
static struct tevent_req *handle_setbindings(TALLOC_CTX *ctx,
			       struct wspd_client_state *client,
			       struct wsp_request *request,
			       struct wsp_response *response,
			       DATA_BLOB *in_data,
			       DATA_BLOB *extra_out_blob,
			       struct wsp_abstract_interface *abs_interface)
{
	struct wsp_cpmsetbindingsin *bindings =
					&request->message.cpmsetbindings;
	uint32_t handle = client->client_data->fid;
	NTSTATUS status;
	struct dummy_async_state *state;
	struct tevent_req *req = tevent_req_create(ctx, &state,
					struct dummy_async_state);
	struct gss_state *gss_state = client->client_data->gss_state;
	if (!has_connected_client(handle, gss_state)) {
		DBG_ERR("no record of connected client for handle %d\n",
		      handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (!verify_checksum(in_data, &request->header)) {
		DBG_ERR("invalid checksum 0x%x\n",
		      request->header.checksum);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	/*
	 * #FIXME we should ideally be checking the integrity of
	 * bindings->acolumns.
	 */
	abs_interface->SetBindings(client,
				   handle, bindings->hcursor,
				   bindings->acolumns,
				   bindings->ccolumns);
	/* keep the binding columns info */
	talloc_steal(get_connected_client_entry(handle, gss_state),
		     bindings->acolumns);
	status = NT_STATUS_OK;
out:
	if (!tevent_req_nterror(req, status)) {
		tevent_req_done(req);
	}
	return tevent_req_post(req, gss_state->ev);
}

static struct client_info *find_client_info(uint32_t handle,
					    struct gss_state *gss_state)
{
	struct client_info *item;
	for (item = gss_state->client_info_map; item; item = item->next){
		if (item->handle == handle) {
			return item;
		}
	}
	return NULL;
}

static struct tevent_req *handle_getscopestats(TALLOC_CTX *ctx,
				 struct wspd_client_state *client,
				 struct wsp_request *request,
				 struct wsp_response *response,
				 DATA_BLOB *in_data,
				 DATA_BLOB *extra_out_blob,
				 struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct gss_state *gss_state = client->client_data->gss_state;
	NTSTATUS status;
	struct wsp_cpmgetscopestatisticsout *statsout =
				&response->message.cpmgetscopestatistics;
	struct dummy_async_state *state;
	struct tevent_req *req = tevent_req_create(ctx, &state,
					struct dummy_async_state);

	if (!has_connected_client(handle, gss_state)) {
		DBG_ERR("no record of connected client for handle %d\n",
		      handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}
	status = abs_interface->GetQueryStatistics(
					client,
					handle,
					&statsout->dwindexeditems,
					&statsout->dwoutstandingadds,
					&statsout->dwoustandingmodifies);
out:
	if (!tevent_req_nterror(req, status)) {
		tevent_req_done(req);
	}
	return tevent_req_post(req, gss_state->ev);
}


static struct tevent_req *handle_rowsetnotify(TALLOC_CTX *ctx,
				struct wspd_client_state *client,
				struct wsp_request *request,
				struct wsp_response *response,
				DATA_BLOB *in_data,
				DATA_BLOB *extra_out_blob,
				struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct gss_state *gss_state = client->client_data->gss_state;
	NTSTATUS status;
	bool more_events;
	uint64_t data1;
	uint64_t data2;
	struct dummy_async_state *state;
	struct tevent_req *req = tevent_req_create(ctx, &state,
					struct dummy_async_state);

	struct wsp_cpmgetrowsetnotifyout *out =
				&response->message.cpmgetrowsetnotifyout;

	if (!has_connected_client(handle, gss_state)) {
		DBG_ERR("no record of connected client for handle %d\n",
		      handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	abs_interface->GetLastUnretrievedEvent(client,
					       handle, &out->wid,
					       &out->eventinfo,
					       &more_events,
					       &out->rowitemstate,
					       &out->changeditemstate,
					       &out->rowsetevent,
					       &data1,
					       &data2);
	out->eventinfo = (out->eventinfo << 1);
	if (more_events) {
		out->eventinfo = out->eventinfo | 0x1;
	} else {
		out->eventinfo = out->eventinfo & 0xFE;
	}
	memcpy(&out->rowseteventdata1, &data1, sizeof(data1));
	memcpy(&out->rowseteventdata2, &data2, sizeof(data2));
	status = NT_STATUS_OK;
out:
	if (!tevent_req_nterror(req, status)) {
		tevent_req_done(req);
	}
	return tevent_req_post(req, gss_state->ev);
}

static struct tevent_req *handle_freecursor(TALLOC_CTX *ctx,
			      struct wspd_client_state *client,
			      struct wsp_request *request,
			      struct wsp_response *response,
			      DATA_BLOB *in_data,
			      DATA_BLOB *extra_out_blob,
			      struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct gss_state *gss_state = client->client_data->gss_state;
	struct wsp_cpmfreecursorin *in = &request->message.cpmfreecursor;
	struct wsp_cpmfreecursorout *out = &response->message.cpmfreecursor;
	NTSTATUS status;
	struct dummy_async_state *state;
	struct tevent_req *req = tevent_req_create(ctx, &state,
					struct dummy_async_state);
	if (!has_connected_client(handle, gss_state)) {
		DBG_ERR("no record of connected client for handle %d\n",
		      handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (!abs_interface->ClientQueryHasCursorHandle(client,
						       handle, in->hcursor)) {
		DBG_ERR("no cursor %d for handle %d\n", in->hcursor, handle);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	out->ccursorsremaining = abs_interface->ReleaseCursor(client,
							      handle,
							      in->hcursor);

	if (!out->ccursorsremaining) {
		req = abs_interface->ReleaseQuery_send(state, client, handle);
	}
	status = NT_STATUS_OK;
out:
	if (!tevent_req_nterror(req, status)) {
		tevent_req_done(req);
	}
	return tevent_req_post(req, gss_state->ev);
}

static void release_client_resources(struct wspd_client_state *client)
{
	uint32_t handle = client->client_data->fid;
	struct gss_state *gss_state = client->client_data->gss_state;
	struct uint32_list *id_item = gss_state->ConnectedClientsIdentifiers;
	struct client_version_map *version_item =
		gss_state->ConnectedClientVersions;
	struct client_info *info = gss_state->client_info_map;
	while (id_item) {
		struct uint32_list *next_id = id_item->next;
		if (id_item->number == handle) {
			DLIST_REMOVE(gss_state->ConnectedClientsIdentifiers,
				     id_item);
			TALLOC_FREE(id_item);
		}
		id_item = next_id;
	}
	while(version_item) {
		struct client_version_map *next_version = version_item->next;
		if (version_item->fid_handle == handle) {
			DLIST_REMOVE(gss_state->ConnectedClientVersions,
				     version_item);
			TALLOC_FREE(version_item);
		}
		version_item = next_version;
	}
	while(info) {
		struct client_info *next_info = info->next;
		if (info->handle == handle) {
			DLIST_REMOVE(gss_state->client_info_map,
				     info);
			TALLOC_FREE(info);
		}
		info = next_info;
	}
}

static int destroy_client_state(struct wspd_client_state *client)
{
	release_client_resources(client);
	return 0;
}

static int destroy_gss_state(struct gss_state *gss_state)
{
	TALLOC_FREE(gss_state->wsp_abstract_state);
	return 0;
}

static struct tevent_req *handle_disconnect(TALLOC_CTX *ctx,
			      struct wspd_client_state *client,
			      struct wsp_request *request,
			      struct wsp_response *response,
			      DATA_BLOB *in_data,
			      DATA_BLOB *extra_out_blob,
			      struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	release_client_resources(client);
	return abs_interface->ReleaseQuery_send(ctx, client, handle);
}

static struct tevent_req *handle_setcope(TALLOC_CTX *ctx,
			     struct wspd_client_state *client,
			     struct wsp_request *request,
			     struct wsp_response *response,
			     DATA_BLOB *in_data,
			     DATA_BLOB *extra_out_blob,
			     struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct dummy_async_state *state;
	struct gss_state *gss_state = client->client_data->gss_state;
	struct tevent_req *req = tevent_req_create(ctx, &state,
					struct dummy_async_state);

	/* #FIXME '0' isn't correct */
	NTSTATUS status =
		abs_interface->SetScopePriority(client, handle,0);
	if (!tevent_req_nterror(req, status)) {
		tevent_req_done(req);
	}
	return tevent_req_post(req, gss_state->ev);
}

/*
 * dummy handler to just return a blank response message with 'success'
 * status.
 */
static struct tevent_req *handle_dummy_handler(TALLOC_CTX *ctx,
			     struct wspd_client_state *client,
			     struct wsp_request *request,
			     struct wsp_response *response,
			     DATA_BLOB *in_data,
			     DATA_BLOB *extra_out_blob,
			     struct wsp_abstract_interface *abs_interface)
{
	struct dummy_async_state *state;
	struct gss_state *gss_state = client->client_data->gss_state;
	struct tevent_req *req = tevent_req_create(ctx, &state,
					struct dummy_async_state);
	tevent_req_done(req);
	return tevent_req_post(req, gss_state->ev);
}

typedef struct tevent_req *(*msg_handler_fn)(TALLOC_CTX *ctx,
				struct wspd_client_state *client,
				struct wsp_request *request,
				struct wsp_response *response,
				DATA_BLOB *in_data,
				DATA_BLOB *extra_out_blob,
				struct wsp_abstract_interface *abs_interface);

static struct {
	uint32_t msgid;
	msg_handler_fn msg_handler;
} msg_handlers [] = {
	{CPMCONNECT, handle_connect},
	{CPMCREATEQUERY, handle_createquery},
	{CPMSETBINDINGSIN, handle_setbindings},
	{CPMGETQUERYSTATUS, handle_querystatus},
	{CPMGETQUERYSTATUSEX, handle_querystatusex},
	{CPMGETROWS, handle_getrows},
	{CPMGETSCOPESTATISTICS, handle_getscopestats},
	{CPMGETROWSETNOTIFY, handle_rowsetnotify},
	{CPMFREECURSOR, handle_freecursor},
	{CPMDISCONNECT, handle_disconnect},
	{CPMSETSCOPEPRIORITIZATION, handle_setcope},
	{CPMRESTARTPOSITIONIN, handle_dummy_handler},
	{CPMRATIOFINISHED, handle_getratiofinishedin},

	/* start unimplemented messages */
	{CPMCOMPAREBMK, NULL},
	{CPMGETAPPROXIMATEPOSITION, NULL},
	{CPMGETNOTIFY, NULL},
	{CPMSENDNOTIFYOUT, NULL},
	{CPMCISTATEOUT, NULL},
	{CPMFETCHVALUE, NULL},
	{CPMSETCATSTATEIN, NULL},
	{CPMFINDINDICES, NULL},
};

static struct {
	uint32_t msgid;
	const char *msg_name;
} msg_id_name_map [] = {
	{CPMCONNECT, "CPMCONNECT"},
	{CPMCREATEQUERY, "CPMCREATEQUERY"},
	{CPMSETBINDINGSIN, "CPMSETBINDINGSIN"},
	{CPMGETQUERYSTATUS, "CPMGETQUERYSTATUS"},
	{CPMGETQUERYSTATUSEX, "CPMGETQUERYSTATUSEX"},
	{CPMDISCONNECT, "CPMDISCONNECT"},
	{CPMFREECURSOR, "CPMFREECURSOR"},
	{CPMGETROWS, "CPMGETROWS"},
	{CPMRATIOFINISHED, "CPMRATIOFINISHED"},
	{CPMCOMPAREBMK, "CPMCOMPAR"},
	{CPMGETAPPROXIMATEPOSITION, "CPMGETAPPROXIMATEPOSITION"},
	{CPMGETNOTIFY, "CPMGETNOTIFY"},
	{CPMSENDNOTIFYOUT, "CPMSENDNOTIFYOUT"},
	{CPMCISTATEOUT, "CPMCISTATEOUT"},
	{CPMFETCHVALUE, "CPMFETCHVALUE"},
	{CPMRESTARTPOSITIONIN, "CPMRESTARTPOSITIONIN"},
	{CPMSETCATSTATEIN, "CPMSETCATSTATEIN"},
	{CPMGETROWSETNOTIFY, "CPMGETROWSETNOTIFY"},
	{CPMFINDINDICES, "CPMFINDINDICES"},
	{CPMSETSCOPEPRIORITIZATION, "CPMSETSCOPEPRIORITIZATION"},
	{CPMGETSCOPESTATISTICS, "CPMGETSCOPESTATISTICS"},
};

static const char *msgid_to_string(uint32_t msgid)
{
	int i;
	const char *result = "UNKNOWN";
	for (i = 0; i < ARRAY_SIZE(msg_id_name_map); i++) {
		if (msgid == msg_id_name_map[i].msgid ){
			result = msg_id_name_map[i].msg_name;
			break;
		}
	}
	return result;
};
static msg_handler_fn get_wsp_msg_handler(uint32_t msgid)
{
	int i;
	for(i = 0; i < ARRAY_SIZE(msg_handlers); i++) {
		if (msg_handlers[i].msgid == msgid) {
			if (!msg_handlers[i].msg_handler) {
				DBG_WARNING("unhandled msgid 0x%x\n", msgid);
				break;
			}
			return msg_handlers[i].msg_handler;
		}
	}
	DBG_ERR("no handler for unknown msgid 0x%x\n", msgid);
	return NULL;
}

static bool extract_wsp_request(TALLOC_CTX *ctx,
				DATA_BLOB *wsp_blob,
				struct wsp_request *wsp_request)
{
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;

	DBG_DEBUG("got wsp message blob of size %d\n", (int)wsp_blob->length);
	ndr = ndr_pull_init_blob(wsp_blob, ctx);
	err = ndr_pull_wsp_request(ndr, ndr_flags, wsp_request);
	if (err) {
		return false;
	}
	return true;
}

static void set_msg_checksum(DATA_BLOB *blob, struct wsp_header *hdr)
{
	uint32_t checksum = calculate_checksum(blob, hdr);
	hdr->checksum = checksum;
}

static enum ndr_err_code insert_checksum_into_msg_and_hdr(DATA_BLOB* blob,
				struct wsp_header *header)
{
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	TALLOC_CTX *ctx = talloc_init("insert");
	struct ndr_push *header_ndr = ndr_push_init_ctx(ctx);

	if ((blob->length > MSG_HEADER_SIZE) && (header->msg == CPMCONNECT
	|| header->msg == CPMCREATEQUERY
	|| header->msg == CPMSETBINDINGSIN
	|| header->msg == CPMFETCHVALUE)) {

		set_msg_checksum(blob, header);
	} else {
		DBG_DEBUG("Warning, trying to set checksum on message "
			  "that doesn't support a checksum\n");
		err = NDR_ERR_SUCCESS;
		goto out;
	}
	/*
	 * alternatively we could just shove in the checksum at the
	 * appropriate offset. Safer though I think to use the standard
	 * routines, also it's probably an advantage to be able to
	 * rewrite out the msg header (in case of late setting of some status)
	 */
	err = ndr_push_wsp_header(header_ndr, ndr_flags, header);
	if (err) {
		DBG_ERR("Failed to push header, error %d\n", err);
		goto out;
	}
	memcpy(blob->data, header_ndr->data, MSG_HEADER_SIZE);
out:
	TALLOC_FREE(ctx);
	return err;
}

static bool insert_wsp_response(TALLOC_CTX *ctx, struct wsp_response *response,
				DATA_BLOB *out_blob, DATA_BLOB *extra_out_blob)
{
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	struct ndr_push* push_ndr;
	enum ndr_err_code err;
	bool header_only = false;
	push_ndr = ndr_push_init_ctx(ctx);

	/*
	 * We don't send a response for CPMDISCONNECT
	 * When response->header.status == DB_S_ENDOFROWSET, this is a
	 * informational error and the rest of the message is expected to be
	 * filled out.
	 */
	if (response->header.msg != CPMDISCONNECT
	   &&( !response->header.status
	   || response->header.status == DB_S_ENDOFROWSET)) {
		err = ndr_push_wsp_response(push_ndr, ndr_flags,
				    response);
	} else {
		err = ndr_push_wsp_header(push_ndr, ndr_flags,
					  &response->header);
		header_only = true;
	}

	if (err) {
		DBG_ERR("failed to marshall response\n");
		return false;
	}
	*out_blob = ndr_push_blob(push_ndr);
	if (!header_only && extra_out_blob->length) {
		out_blob->data = talloc_realloc(
				ctx,
				out_blob->data,
				uint8_t,
				out_blob->length + extra_out_blob->length);
		memcpy(out_blob->data + out_blob->length,
		       extra_out_blob->data,
		       extra_out_blob->length);
		out_blob->length =  out_blob->length + extra_out_blob->length;
	}
	err = insert_checksum_into_msg_and_hdr(out_blob, &response->header);
	if (err) {
		DBG_ERR("failed to insert checksum\n");
		return false;
	}
	return true;
}

struct handle_wsp_state
{
	struct wsp_request *wsp_request;
	struct wsp_response *response;
	DATA_BLOB *out_blob;
	DATA_BLOB extra_out_blob;
	struct named_pipe_client  *npc;
};

static void handle_wsp_done(struct tevent_req *subreq);
static struct tevent_req *handle_wsp_send(TALLOC_CTX *ctx,
		struct wspd_client_state *client,
		struct named_pipe_client  *npc,
		DATA_BLOB *in_blob, DATA_BLOB *out_blob)
{
	struct wsp_request *wsp_request;
	struct wsp_response *response;
	struct tevent_req *req, *subreq = NULL;
	struct handle_wsp_state *state = NULL;
	struct gss_state *gss_state = client->client_data->gss_state;
	msg_handler_fn msg_handler;
	NTSTATUS status;

	req = tevent_req_create(ctx, &state, struct handle_wsp_state);
	if (!req) {
		return NULL;
	}

	response = talloc_zero(state, struct wsp_response);
	wsp_request = talloc_zero(state, struct wsp_request);
	ZERO_STRUCTP(out_blob);

	if (!extract_wsp_request(wsp_request, in_blob, wsp_request)) {
		DBG_ERR("error extracting WSP message\n");
		goto err_out;
	}

	state->wsp_request = wsp_request;
	state->response = response;
	state->out_blob = out_blob;
	ZERO_STRUCT(state->extra_out_blob);
	state->npc = npc;
	response->header.msg = wsp_request->header.msg;
	msg_handler = get_wsp_msg_handler(wsp_request->header.msg);
	DBG_NOTICE("received %s message from handle %d\n",
		  msgid_to_string(wsp_request->header.msg),
		  client->client_data->fid);
	if (msg_handler) {
		subreq = msg_handler(state, client, wsp_request,
				     response, in_blob, &state->extra_out_blob,
				     get_impl());
	} else {
		status = NT_STATUS_UNHANDLED_EXCEPTION;
		goto err_out;
	}
	if (!subreq) {
		/* better status ?? */
		status = NT_STATUS_UNHANDLED_EXCEPTION;
		goto err_out;
	}
	tevent_req_set_callback(subreq, handle_wsp_done, req);
	return req;
err_out:
	response->header.status = NT_STATUS_V(status);
	if (!insert_wsp_response(wsp_request, response, out_blob,
				 &state->extra_out_blob)) {
		DBG_ERR("error inserting WSP response for msg %s\n",
	      	      msgid_to_string(state->wsp_request->header.msg));
	}
	if (state->npc) {
		talloc_steal(state->npc->p->mem_ctx, state->out_blob->data);
	}
	tevent_req_done(req);
	return tevent_req_post(req, gss_state->ev);
}

static void handle_wsp_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct handle_wsp_state *state =
		tevent_req_data(req, struct handle_wsp_state);
	NTSTATUS status = NT_STATUS_OK;
	bool has_error = tevent_req_is_nterror(subreq, &status);
	if (has_error) {
		DBG_ERR("detected some async processing error %s 0x%x "
			 "for request %p\n", nt_errstr(status),
			 NT_STATUS_V(status), subreq);
		state->response->header.status = NT_STATUS_V(status);
	}
	if (state->wsp_request->header.msg != CPMDISCONNECT) {
		if (!insert_wsp_response(state->wsp_request, state->response,
				     state->out_blob, &state->extra_out_blob)) {
			DBG_ERR("error inserting WSP response for msg %s\n",
		      	      msgid_to_string(state->wsp_request->header.msg));
		}
	} else {
		DBG_INFO("no message payload set for CPMDISCONNECT\n");
	}
	if (state->npc) {
		DBG_DEBUG("stealing response blob %p state->out_blob->data "
			  "with %d bytes\n",
			  state->out_blob->data,
			  (int)state->out_blob->length);
		talloc_steal(state->npc->p->mem_ctx, state->out_blob->data);
	}
	TALLOC_FREE(state->wsp_request);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

struct gss_state *gss_state_create(struct tevent_context *event_ctx,
				   struct messaging_context *msg_ctx)

{
	struct gss_state *state = talloc_zero(NULL, struct gss_state);
	if (!state) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}
	DBG_NOTICE("wsp gss_start\n");
	state->ConnectedClientsIdentifiers = talloc_zero(state,
							struct uint32_list);
	state->ConnectedClientVersions = talloc_zero(state,
						     struct client_version_map);
	state->wsp_server_state = NOT_INITIALISED;

	state->ev = event_ctx;
	state->msg_ctx = msg_ctx;
	talloc_set_destructor(state, destroy_gss_state);
	return state;
}

bool gss_init(struct gss_state *state)
{
	struct wsp_abstract_interface *abs_if = get_impl();
	if (state->wsp_server_state != NOT_INITIALISED) {
		DBG_DEBUG("GSS_STATE is already initialised\n");
		return true;
	}
	state->wsp_abstract_state = abs_if->Initialise(state->ev,
						       state->msg_ctx);

	if (!state->wsp_abstract_state) {
		DBG_ERR("failure initialise abstract interface\n");
		return false;
	}
	state->wsp_server_state = RUNNING;
	return true;
}

struct handle_wsp_req_state
{
	DATA_BLOB *out_resp;
};

struct tevent_req *do_wsp_request_send(TALLOC_CTX *ctx,
				       struct wspd_client_state *client)
{
	struct named_pipe_client *npc = client->client_data->npc;
	struct pipes_struct *p = npc->p;

	return handle_wsp_send(ctx, client, npc, &p->in_data.pdu,
			       &p->out_data.rdata);

}

struct wspd_client_state * create_client_state(struct named_pipe_client *npc,
					       struct gss_state *gss_state)
{
	static int gen_id = 1;
	struct wspd_client_state *state = talloc_zero(NULL,
						      struct wspd_client_state);
	state->client_data = talloc_zero(state, struct wsp_client_data);
	state->client_data->fid = gen_id++;
	state->client_data->npc = npc;
	state->client_data->gss_state = gss_state;
	state->wsp_abstract_state = gss_state->wsp_abstract_state;
	talloc_set_destructor(state, destroy_client_state);
	return state;
}

struct client_disconnected_state
{
	struct wspd_client_state *client_state;
};

static void client_disconnected_done(struct tevent_req *subreq);

void client_disconnected(struct wspd_client_state *client_state)
{
	struct tevent_req *req, *subreq;
	struct client_disconnected_state *state;
	DBG_NOTICE("got disconnect for handle %d\n",
		 client_state->client_data->fid);
	req = tevent_req_create(client_state->client_data->gss_state, &state,
				struct client_disconnected_state);
	if (!req) {
		DBG_ERR("out of memory\n");
		goto error;
	}
	state->client_state = client_state;
	subreq = get_impl()->ReleaseQuery_send(state, client_state,
					       client_state->client_data->fid);
	if (!subreq) {
		DBG_ERR("failed to create subrequest to release query "
			 "for handle %d\n", client_state->client_data->fid);
		goto error;
	}
	tevent_req_set_callback(subreq, client_disconnected_done, req);
	return;
error:
	TALLOC_FREE(state->client_state);
}

static void client_disconnected_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct client_disconnected_state *state =
		tevent_req_data(req, struct client_disconnected_state);
	TALLOC_FREE(state->client_state);
	TALLOC_FREE(subreq);
	TALLOC_FREE(req);
}

struct pipes_struct *get_pipe(struct wspd_client_state *state)
{
	return state->client_data->npc->p;
}
