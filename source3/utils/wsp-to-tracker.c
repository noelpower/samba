#include "includes.h"
#include "popt_common.h"
#include "bin/default/librpc/gen_ndr/ndr_wsp.h"
#include "bin/default/librpc/gen_ndr/ndr_wsp_data.h"
#include "rpc_server/wsp/wsp_sparql_conv.h"
#include <unistd.h>

static const uint32_t BUFFER_SIZE = 20000;

static bool get_blob_from_file(TALLOC_CTX *ctx, const char *message_bytes_file,
			DATA_BLOB *blob)
{
	char *content = file_load(message_bytes_file, &blob->length, BUFFER_SIZE, ctx);
	blob->data = (uint8_t*)content;
	return content != NULL;
}

static enum ndr_err_code parse_blob(TALLOC_CTX *ctx, DATA_BLOB *blob,
		struct wsp_request *request, struct wsp_response *response,
		bool is_request)
{
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;

	ndr = ndr_pull_init_blob(blob, ctx);

	if (is_request) {
		err = ndr_pull_wsp_request(ndr, ndr_flags, request);
	}
	else {
		err = ndr_pull_wsp_response(ndr, ndr_flags, response);
	}
	return err;
}

static bool synthesize_bindings(TALLOC_CTX *ctx,
			       struct wsp_ccolumnset *columnset,
			       struct wsp_cpidmapper *pidmapper,
			       struct wsp_ctablecolumn **columns,
			       uint32_t *ncols)
{
	int i;
	struct wsp_ctablecolumn *tab_cols =
			talloc_zero_array(ctx,
					  struct wsp_ctablecolumn,
					  columnset->count);
	*ncols = columnset->count;
	for (i=0; i < columnset->count; i++) {
		int pid_index = columnset->indexes[i];
		struct wsp_cfullpropspec *prop_spec =
				&pidmapper->apropspec[pid_index];
		tab_cols[i].propspec = *prop_spec;
	}
	*columns = tab_cols;
	return true;
}

int main(int argc, const char *argv[])
{
	DATA_BLOB blob;
	int result;
	TALLOC_CTX *ctx = talloc_init(NULL);
	struct wsp_request *request;
	struct wsp_response *response;	
	enum ndr_err_code err;
	const char *query_str = NULL;
	const char *share = NULL;
	const char *restrictionset_expr = NULL;
	struct wsp_cpmcreatequeryin *query;
	struct wsp_ccolumnset *projected_col_offsets = NULL;
	struct wsp_crestrictionarray *restrictionset = NULL;
	struct wsp_cpidmapper *pidmapper = NULL;
	struct tracker_selected_cols tracker_cols;
	uint32_t where_id;
	int i = 0;
	int c = 0;
	bool raw = false;
	bool full = false;
	bool restriction = false;
	const char *infile;
	poptContext pc;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"full",	'f', POPT_ARG_NONE,	NULL, 'f', "prints out the full sparql query" },
		{"restriction",	'r', POPT_ARG_NONE, 	NULL, 'r', "prints out the restriction expression only" },
		{"verbose",	'v', POPT_ARG_NONE, 	NULL, 'v', "doesn't do any conversion to tracker properties, doesn't drop any part of the expression, just prints out what it can" },
		POPT_TABLEEND
	};
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	if (!frame) {
		DBG_ERR("failed to allocate stack frame\n");
		return -1;
	}

	setup_logging(argv[0], DEBUG_STDERR);
	smb_init_locale();

	if (!lp_load_client(get_dyn_CONFIGFILE())) {
		fprintf(stderr, "ERROR: Can't load %s - run testparm to debug it\n",
			get_dyn_CONFIGFILE());
		exit(1);
	}

	pc = poptGetContext("wsp-to-sparql", argc, argv, long_options,
			    0);

	poptSetOtherOptionHelp(pc, "binary msg file");
	while ((c = poptGetNextOpt(pc)) != -1) {
		switch (c)
		{
			case 'v':
				raw = true;
				break;
			case 'f':
				full = true;
				break;
			case 'r':
				restriction = true;
				break;
		}
	}

	if(!poptPeekArg(pc)) {
		poptPrintUsage(pc, stderr, 0);
		return -1;
	}

	infile = talloc_strdup(frame, poptGetArg(pc));
	if (!infile) {
		poptPrintUsage(pc, stderr, 0);
		return -1;
	}

	if (full && restriction) {
		poptPrintUsage(pc, stderr, 0);
		return -1;
	}

	if (!full && !restriction) {
		/* default to full */
		full = true;
	}
	if (!lp_load_with_shares(get_dyn_CONFIGFILE())) {
		DBG_ERR("failed to load %s\n",get_dyn_CONFIGFILE());
		return -1;
	}
	poptFreeContext(pc);

	request = talloc(ctx, struct wsp_request);
	response = talloc(ctx, struct wsp_response);
	ZERO_STRUCTP(request);
	ZERO_STRUCTP(response);
	ZERO_STRUCT(tracker_cols);


	if (!get_blob_from_file(ctx, infile, &blob)) {
		DBG_ERR("failed to process %s\n", infile);
		result = 1;
		goto out;
	}

	err = parse_blob(ctx, &blob, request, response, true);
	if (err) {
		DBG_ERR("failed to parse blob error %d\n", err);
		result = 1;
		goto out;
	}
	if (request->header.msg != CPMCREATEQUERY) {
		DBG_ERR("wrong msg request type was expecting CPMCREATEQUERY, got %d\n", request->header.msg);
	}

	query = &request->message.cpmcreatequery;
	pidmapper = &query->pidmapper;

	if (query->ccolumnsetpresent) {
		projected_col_offsets = &query->columnset.columnset;
	}
	if (query->crestrictionpresent) {
		restrictionset = &query->restrictionarray.restrictionarray;
	}

	status =
		build_restriction_expression(ctx,
					     NULL,
					     restrictionset,
					     !raw,
					     &restrictionset_expr,
					     &share,
					     &where_id);

	if (!restrictionset_expr || strlen(restrictionset_expr) == 0) {
		DBG_ERR("failed to generate restriction expression\n");
		goto out;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("status failure detected %s\n",
			nt_errstr(status));
		goto out;
	}

	if (full) {
		struct binding_result_mapper *result_converter;
		struct map_data *map_data;
		struct wsp_ctablecolumn *columns;
		uint32_t  ncolumns;
		struct wsp_csortset *sortset;
		if (query->csortsetpresent) {
			struct wsp_cingroupsortaggregset* aggregset;
			aggregset =
				&query->sortset.groupsortaggregsets.sortsets[0];
			sortset = &aggregset->sortaggregset;
		}
		result_converter = talloc_zero(ctx,
					       struct binding_result_mapper);
		if (!result_converter) {
			goto out;
		}
		/*
		 * currently the tool doesn't have access to the bindings so
		 * we synthesise them here from the columnset & pidmapper info
		 * from the query message.
		 * #TODO allow bindings be specified on the commandline also
		 * to be used here.
		 */
		if (!synthesize_bindings(ctx, projected_col_offsets, pidmapper,
					 &columns, &ncolumns)) {
			goto out;
		}

		status = build_tracker_query(ctx,
				     projected_col_offsets,
				     restrictionset_expr,
				     pidmapper,
				     &tracker_cols,
				     sortset,
				     !raw,
				     &query_str);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
		DBG_ERR("tracker-sparql query is:\n\"%s\"\n", query_str);
		DBG_ERR("selected columns:\n");
		if (!build_mapper(ctx, columns, ncolumns, &tracker_cols,
				  result_converter)) {
			goto out;
		}
		map_data = result_converter->map_data;
		for (i=0; i < result_converter->ncols; i++) {
			int pid_index = projected_col_offsets->indexes[i];
			struct wsp_cfullpropspec *prop_spec =
					&pidmapper->apropspec[pid_index];
			char *prop = prop_from_fullprop(ctx, prop_spec);
			if (map_data[i].convert_fn) {
				DBG_ERR("Col[%d] %s is mapped/converted from tracker col[%d] %s\n", i, prop, map_data[i].col_with_value, tracker_cols.tracker_ids[map_data[i].col_with_value]);
			} else {
				DBG_ERR("Col[%d] %s Will not return a value\n", i, prop);
			}
		}
	}
	if (restriction) {
		DBG_ERR("tracker-sparql restriction expression\n\"%s\"\n",
			restrictionset_expr);
	}
	result = 0;
	status = NT_STATUS_OK;
out:
	return result;
}
