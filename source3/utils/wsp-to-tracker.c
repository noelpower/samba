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
	bool result = true;
	FILE *f=NULL;
	int i = 0;

	uint8_t *buffer = talloc_array(ctx, uint8_t, BUFFER_SIZE);
	/* cheap and nasty read */
	f = fopen(message_bytes_file,"rb");

	if (!f) {
		DBG_ERR("Failed to open %s for reading\n", message_bytes_file);
		result = false;
		goto out;
	}
	while (!feof(f)) {
		if (i > BUFFER_SIZE) {
			DBG_ERR("buffer too small read %d bytes from %s\n", i, message_bytes_file);
		}
		fread(buffer+i,1,1,f);
		i++;

	}
	i--;
	DBG_ERR("%d bytes from %s\n", i, message_bytes_file);
out:
	fclose(f);
	blob->data = buffer;
	blob->length = i;
	return result;
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

static void print_help(void)
{
	DBG_ERR("wsp-to-tracker [-f|-r] -v\n");
	DBG_ERR("\t-f full prints out the full sparql query\n");
	DBG_ERR("\t-r restriction, prints out the restriction expression\n");
	DBG_ERR("\t-o uses old infix expression generator\n");
	DBG_ERR("\t-v don't do any conversion to tracker properties from wsp properties\n");
	DBG_ERR("\t   don't drop any part of the expression, just print it out as you can\n");
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

int main(int argc, char *argv[])
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
	int errflg = 0;
	bool raw = false;
	bool full = false;
	bool restriction = false;
	bool new_generator = true;

	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	if (!frame) {
		DBG_ERR("failed to allocate stack frame\n");
		return -1;
	}
	while ((c = getopt (argc, argv, "vfrho")) != -1) {
		switch (c)
		{
			case 'v':
				raw = true;
				break;
			case 'f':
				full = true;
				break;
			case 'h':
				print_help();
				exit(0);
				break;
			case 'r':
				restriction = true;
				break;
			case 'o':
				new_generator = false;
				break;
			case ':':       /* -f or -o without operand */
				DBG_ERR("Option -%c requires an operand\n",
					optopt);
				errflg++;
				break;
			case '?':
				DBG_ERR("Unrecognized option: '-%c'\n", optopt);
				errflg++;
				break;
			default:
				break;
		}
	}
	if ( optind >= argc || errflg || ( full && restriction )) {
		DBG_ERR("USAGE: wsp-to-tracker [-f|-r] -v -h message.bytes\n");
		exit(2);
	}

	if (!full && !restriction) {
		/* default to full */
		full = true;
	}
	/* #TODO #FIXME do we really need this ? */
	if (!lp_load_with_shares(get_dyn_CONFIGFILE())) {
		DBG_ERR("failed to load %s\n",get_dyn_CONFIGFILE());
		return -1;
	}
	request = talloc(ctx, struct wsp_request);
	response = talloc(ctx, struct wsp_response);
	ZERO_STRUCTP(request);
	ZERO_STRUCTP(response);
	ZERO_STRUCT(tracker_cols);

	if (argc < 2) {
		result = 1;
		goto out;
	}


	if (!get_blob_from_file(ctx, argv[argc - 1], &blob)) {
		DBG_ERR("failed to process %s\n", argv[1]);
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

	if (new_generator) {
		status =
			build_restriction_expression(ctx,
						     NULL,
						     restrictionset,
						     !raw,
						     &restrictionset_expr,
						     &share);
	} else {
		DBG_ERR("using old generator\n");
		status = get_filter(ctx,
				    NULL,
				    restrictionset,
				    !raw,
				    &restrictionset_expr,
				    &share,
				    &where_id);
	}

	if (!restrictionset_expr || strlen(restrictionset_expr) == 0) {
		DBG_ERR("failed to generate restriction expression\n");
		goto out;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("status failure detected %s\n",
			nt_errstr(status));
	}

	if (full) {
		struct binding_result_mapper *result_converter;
		struct map_data *map_data;
		struct wsp_ctablecolumn *columns;
		uint32_t  ncolumns;
		struct wsp_csortset *sortset;
		if (query->csortsetpresent) {
			sortset = &query->sortset.sortset;
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
