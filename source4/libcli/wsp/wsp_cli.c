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
#include "libcli/wsp/wsp_cli.h"
#include "param/param.h"
#include "dcerpc.h"
#include "libcli/raw/interfaces.h"
#include "auth/credentials/credentials.h"
#include "libcli/libcli.h"
#include "libcli/smb/tstream_smbXcli_np.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb/smbXcli_base.h"
#include "smb_composite/smb_composite.h"
#include "lib/cmdline/popt_common.h"
#include "libcli/resolve/resolve.h"
#include <tevent.h>
#include <util/tevent_ntstatus.h>
#include "libcli/tstream_binding_handle/tstream_binding_handle.h"
#include "lib/tsocket/tsocket.h"

#define MSG_HDR_SIZE 16

static const uint32_t CLIENTVERSION = 0x00000109;

static int32_t scope_flags_vector[] = {0x00000001};
static const char * root_scope_string_vector[] = {"\\"};

/* sets sensible defaults */
static void init_wsp_prop(struct wsp_cdbprop *prop)
{
	prop->dbpropoptions =  0x0000000;
	prop->dbpropstatus =  0x0000000;
	ZERO_STRUCT(prop->colid.guid); /* just in case */
	ZERO_STRUCT(prop->vvalue); /* just in case */
	prop->colid.ekind = DBKIND_GUID_PROPID;
	prop->colid.uiid = 0x00000000;
}


static void create_restriction_array(TALLOC_CTX *ctx,
			       struct wsp_crestriction **pelements,
			       uint32_t nnodes)
{
	struct wsp_crestriction *elements = talloc_zero_array(ctx,
						       struct wsp_crestriction,
						       nnodes);
	*pelements = elements;
}


static void create_noderestriction(TALLOC_CTX *ctx,
			       struct wsp_cnoderestriction *pnode,
			       uint32_t nnodes)
{
	pnode->cnode = nnodes;
	create_restriction_array(ctx, &pnode->panode, nnodes);
}

static void fill_sortarray(TALLOC_CTX *ctx, struct wsp_csort **dest,
			   struct wsp_csort *src, uint32_t num)
{
	int i;
	struct wsp_csort *psort = talloc_zero_array(ctx, struct wsp_csort,
						    num);
	for (i = 0; i < num; i++) {
		psort[i] = src[i];
	}
	*dest = psort;
}



static bool set_fullpropspec(TALLOC_CTX *ctx, struct wsp_cfullpropspec *prop,
			     const char* propname, uint32_t kind)
{
	struct GUID guid;
	const struct full_propset_info *prop_info;
	ZERO_STRUCT(guid);
	prop_info = get_propset_info_with_guid(propname, &guid);
	if (!prop_info) {
		/* #FIXME error handling */
		DBG_ERR("Failed to handle property named %s\n",
			propname);
		return false;
	}
	prop->guidpropset = guid;
	prop->ulkind = kind;
	if (kind == PRSPEC_LPWSTR) {
		prop->name_or_id.propname.vstring = talloc_strdup(ctx,
								   propname);
		prop->name_or_id.propname.len = strlen(propname);
	} else {
		prop->name_or_id.prspec = prop_info->id;
	}
	return true;
}

struct binding
{
	uint32_t status_off;
	uint32_t value_off;
	uint32_t len_off;
};

static bool set_ctablecolumn(TALLOC_CTX *ctx, struct wsp_ctablecolumn *tablecol,
			const char* propname, struct binding *offsets)
{
	struct wsp_cfullpropspec *prop = &tablecol->propspec;

	if (!set_fullpropspec(ctx, prop, propname, PRSPEC_PROPID)) {
		return false;
	}
	tablecol->vtype =VT_VARIANT ;
	tablecol->aggregateused = 1;
	tablecol->valueused = 1;
	tablecol->valueoffset.value = offsets->value_off;
	tablecol->valuesize.value = 0x10;
	tablecol->statusused = 1;
	tablecol->statusoffset.value = offsets->status_off;
	tablecol->lengthused = 1;
	tablecol->lengthoffset.value = offsets->len_off;
	return true;
}


static void fill_uint32_vec(TALLOC_CTX* ctx,
			    uint32_t **pdest,
			    uint32_t* ivector, uint32_t elems)
{
	int i;
	uint32_t *dest = talloc_zero_array(ctx, uint32_t, elems);
	for ( i = 0; i < elems; i++ ) {
		dest[ i ] = ivector[ i ];
	}
	*pdest = dest;
}

static void init_propset1(TALLOC_CTX* tmp_ctx,
					struct wsp_cdbpropset *propertyset)
{
	int i;

	GUID_from_string(DBPROPSET_FSCIFRMWRK_EXT,
			 &propertyset->guidpropertyset);

	propertyset->cproperties = 4;
	propertyset->aprops =
		talloc_zero_array(tmp_ctx, struct wsp_cdbprop,
			     propertyset->cproperties);
	/* initialise first 4 props */
	for( i = 0; i < propertyset->cproperties; i++) {
		init_wsp_prop(&propertyset->aprops[i]);
	}

	/* set value prop[0] */
	propertyset->aprops[0].dbpropid = DBPROP_CI_CATALOG_NAME;
	set_variant_lpwstr(tmp_ctx, &propertyset->aprops[0].vvalue,
			"Windows\\SYSTEMINDEX");
	/* set value prop[1] */
	propertyset->aprops[1].dbpropid = DBPROP_CI_QUERY_TYPE;
	set_variant_i4(tmp_ctx, &propertyset->aprops[1].vvalue,
		       CINORMAL);
	/* set value prop[2] */
	propertyset->aprops[2].dbpropid = DBPROP_CI_SCOPE_FLAGS;
	set_variant_i4_vector(tmp_ctx, &propertyset->aprops[2].vvalue,
		       scope_flags_vector, ARRAY_SIZE(scope_flags_vector));
	/* set value prop[3] */
	propertyset->aprops[3].dbpropid = DBPROP_CI_INCLUDE_SCOPES;
	set_variant_lpwstr_vector(tmp_ctx,
				  &propertyset->aprops[3].vvalue,
				  root_scope_string_vector,
				  ARRAY_SIZE(root_scope_string_vector));
}

static void init_propset2(TALLOC_CTX* tmp_ctx,
			  struct wsp_cdbpropset *propertyset,
			  const char* server)
{
	int i;

	GUID_from_string(DBPROPSET_CIFRMWRKCORE_EXT,
			 &propertyset->guidpropertyset);

	propertyset->cproperties = 1;
	propertyset->aprops =
		talloc_zero_array(tmp_ctx, struct wsp_cdbprop,
			     propertyset->cproperties);
	/* initialise first 1 props */
	for( i = 0; i < propertyset->cproperties; i++) {
		init_wsp_prop(&propertyset->aprops[i]);
	}

	/* set value prop[0] */
	propertyset->aprops[0].dbpropid = DBPROP_MACHINE;
	set_variant_bstr(tmp_ctx, &propertyset->aprops[0].vvalue,
			server);
}

static void init_apropset0(TALLOC_CTX* tmp_ctx,
			   struct wsp_cdbpropset *propertyset)
{
	int i;

	GUID_from_string(DBPROPSET_MSIDXS_ROWSETEXT,
			 &propertyset->guidpropertyset);

	propertyset->cproperties = 7;
	propertyset->aprops =
		talloc_zero_array(tmp_ctx, struct wsp_cdbprop,
			     propertyset->cproperties);
	/* initialise props */
	for( i = 0; i < propertyset->cproperties; i++) {
		init_wsp_prop(&propertyset->aprops[i]);
	}

	/* set value prop[0] MSIDXSPROP_ROWSETQUERYSTATUS where is this specified ? */
	propertyset->aprops[0].dbpropid = 0x00000002;
	set_variant_i4(tmp_ctx,  &propertyset->aprops[0].vvalue, 0x00000000);

	/* set value prop[1] MSIDXSPROP_COMMAND_LOCALE_STRING */
	propertyset->aprops[1].dbpropid = 0x00000003;
	set_variant_bstr(tmp_ctx, &propertyset->aprops[1].vvalue,
			"en-ie");
	/* set value prop[2] MSIDXSPROP_QUERY_RESTRICTION */
	propertyset->aprops[2].dbpropid = 0x00000004;
	set_variant_bstr(tmp_ctx, &propertyset->aprops[2].vvalue,
			"");
	/* set value prop[3] MSIDXSPROP_PARSE_TREE */
	propertyset->aprops[3].dbpropid = 0x00000005;
	set_variant_bstr(tmp_ctx, &propertyset->aprops[3].vvalue,
			"");
	/* set value prop[4] MSIDXSPROP_MAX_RANK */
	propertyset->aprops[4].dbpropid = 0x00000006;
	set_variant_i4(tmp_ctx,  &propertyset->aprops[4].vvalue, 0x00000000);
	/* set value prop[5] MSIDXSPROP_RESULTS_FOUND */
	propertyset->aprops[5].dbpropid = 0x00000007;
	set_variant_i4(tmp_ctx,  &propertyset->aprops[5].vvalue, 0x00000000);
	/* set value prop[6] ?? */
	propertyset->aprops[6].dbpropid = 0x00000008;
	set_variant_i4(tmp_ctx,  &propertyset->aprops[6].vvalue, 0x00000000);
}

static void init_apropset1(TALLOC_CTX* tmp_ctx,
			       struct wsp_cdbpropset *propertyset)
{
	int i;
	GUID_from_string(DBPROPSET_QUERYEXT,
			 &propertyset->guidpropertyset);

	propertyset->cproperties = 0x0000000B;
	propertyset->aprops =
		talloc_zero_array(tmp_ctx, struct wsp_cdbprop,
			     propertyset->cproperties);
	/* init properties */
	for( i = 0; i < propertyset->cproperties; i++) {
		init_wsp_prop(&propertyset->aprops[i]);
	}

	/* set value prop[0] */
	propertyset->aprops[0].dbpropid = DBPROP_USECONTENTINDEX;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[0].vvalue, false);
	/* set value prop[1] */
	propertyset->aprops[1].dbpropid = DBPROP_DEFERNONINDEXEDTRIMMING;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[1].vvalue, false);
	/* set value prop[2] */
	propertyset->aprops[2].dbpropid = DBPROP_USEEXTENDEDDBTYPES;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[2].vvalue, false);
	/* set value prop[3] */
	propertyset->aprops[3].dbpropid = DBPROP_IGNORENOISEONLYCLAUSES;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[3].vvalue, false);
	/* set value prop[4] */
	propertyset->aprops[4].dbpropid = DBPROP_GENERICOPTIONS_STRING;
	set_variant_bstr(tmp_ctx,  &propertyset->aprops[4].vvalue, "");
	/* set value prop[5] */
	propertyset->aprops[5].dbpropid = DBPROP_DEFERCATALOGVERIFICATION;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[5].vvalue, false);
	/* set value prop[6] */
	propertyset->aprops[6].dbpropid = DBPROP_IGNORESBRI;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[6].vvalue, false);
	/* set value prop[7] */
	propertyset->aprops[7].dbpropid = DBPROP_GENERATEPARSETREE;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[7].vvalue, false);
	/* set value prop[8] */
	propertyset->aprops[8].dbpropid = DBPROP_FREETEXTANYTERM;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[8].vvalue, false);
	/* set value prop[9] */
	propertyset->aprops[9].dbpropid = DBPROP_FREETEXTUSESTEMMING;
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[9].vvalue, false);
	/* set value prop[10] */
	propertyset->aprops[10].dbpropid = 0x0000000f; /* ??? */
	set_variant_vt_bool(tmp_ctx,  &propertyset->aprops[10].vvalue, false);
}

static void init_apropset2(TALLOC_CTX* tmp_ctx,
			   struct wsp_cdbpropset *propertyset,
			   const char* server)
{
	int i;
	GUID_from_string(DBPROPSET_CIFRMWRKCORE_EXT,
			 &propertyset->guidpropertyset);

	propertyset->cproperties = 0x00000001;
	propertyset->aprops =
		talloc_zero_array(tmp_ctx, struct wsp_cdbprop,
			     propertyset->cproperties);
	/* init properties */
	for( i = 0; i < propertyset->cproperties; i++) {
		init_wsp_prop(&propertyset->aprops[i]);
	}

	/* set value prop[0] */
	propertyset->aprops[0].dbpropid = DBPROP_MACHINE;
	set_variant_bstr(tmp_ctx,  &propertyset->aprops[0].vvalue, server);

}


static void init_apropset3(TALLOC_CTX* tmp_ctx,
			   struct wsp_cdbpropset *propertyset)
{
	int i;

	GUID_from_string(DBPROPSET_FSCIFRMWRK_EXT,
			 &propertyset->guidpropertyset);

	propertyset->cproperties = 0x00000003;
	propertyset->aprops =
		talloc_zero_array(tmp_ctx, struct wsp_cdbprop,
			     propertyset->cproperties);
	/* init properties */
	for( i = 0; i < propertyset->cproperties; i++) {
		init_wsp_prop(&propertyset->aprops[i]);
	}

	/* set value prop[0] */
	propertyset->aprops[0].dbpropid = DBPROP_CI_INCLUDE_SCOPES;
	set_variant_array_bstr(tmp_ctx, &propertyset->aprops[0].vvalue,
			       root_scope_string_vector,
			       ARRAY_SIZE(root_scope_string_vector));
	/* set value prop[1] */
	propertyset->aprops[1].dbpropid = DBPROP_CI_SCOPE_FLAGS;
	set_variant_array_i4(tmp_ctx, &propertyset->aprops[1].vvalue,
			     scope_flags_vector,
			     ARRAY_SIZE(scope_flags_vector));
	/* set value prop[2] */
	propertyset->aprops[2].dbpropid = DBPROP_CI_CATALOG_NAME;
	set_variant_bstr(tmp_ctx, &propertyset->aprops[2].vvalue,
			 "Windows\\SYSTEMINDEX");
}

void init_connectin_request(TALLOC_CTX *ctx,
			    struct wsp_request* request,
			    const char* clientmachine,
			    const char* clientuser,
			    const char* server)
{
	enum ndr_err_code err;
	struct connectin_propsets *props =
		talloc_zero(ctx, struct connectin_propsets);
	struct connectin_extpropsets *ext_props =
		talloc_zero(ctx, struct connectin_extpropsets) ;
	DATA_BLOB props_blob;
	struct ndr_push *ndr_props;
	struct wsp_cpmconnectin *connectin = &request->message.cpmconnect;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;

	request->header.msg = CPMCONNECT;
	connectin->iclientversion = CLIENTVERSION;
	connectin->fclientisremote = 0x00000001;
	connectin->machinename = clientmachine;
	connectin->username = clientuser;
	props->cpropsets = 2;

	/* =================== */
	/* set up PropertySet1 */
	/* =================== */
	init_propset1(ctx, &props->propertyset1);

	/* =================== */
	/* set up PropertySet2 */
	/* =================== */
	init_propset2(ctx, &props->propertyset2, server);
	/* 4 ExtPropSets */
	ext_props->cextpropset = 4;
	ext_props->apropertysets = talloc_zero_array(ctx, struct wsp_cdbpropset,
			     ext_props->cextpropset);

	/* ======================= */
	/* set up aPropertySets[0] */
	/* ======================= */
	init_apropset0(ctx, &ext_props->apropertysets[0]);

	/* ======================= */
	/* set up aPropertySets[1] */
	/* ======================= */
	init_apropset1(ctx, &ext_props->apropertysets[1]);

	/* ======================= */
	/* set up aPropertySets[2] */
	/* ======================= */
	init_apropset2(ctx, &ext_props->apropertysets[2], server);

	/* ======================= */
	/* set up aPropertySets[3] */
	/* ======================= */
	init_apropset3(ctx, &ext_props->apropertysets[3]);

	/* we also have to fill the opaque blobs that contain the propsets */
	ndr_props = ndr_push_init_ctx(ctx);

	/* first connectin_propsets */
	err = ndr_push_connectin_propsets(ndr_props, ndr_flags, props);
	if (err) {
		DBG_ERR("Failed to push propset, error %d\n", err);
		goto out;
	}
	props_blob = ndr_push_blob(ndr_props);
	connectin->cbblob1 = props_blob.length;
	connectin->propsets = talloc_zero_array(ctx, uint8_t,
				   connectin->cbblob1);
	memcpy(connectin->propsets, props_blob.data, props_blob.length);

	/* then connectin_extpropsets */
	TALLOC_FREE(ndr_props);
	ndr_props = ndr_push_init_ctx(ctx);
	err = ndr_push_connectin_extpropsets(ndr_props, ndr_flags, ext_props);

	if (err) {
		DBG_ERR("Failed to push extpropset, error %d\n", err);
		goto out;
	}

	props_blob = ndr_push_blob(ndr_props);
	connectin->cbblob2 = props_blob.length;
	connectin->extpropsets = talloc_zero_array(ctx, uint8_t,
						   connectin->cbblob2);
	memcpy(connectin->extpropsets, props_blob.data, props_blob.length);
	TALLOC_FREE(ndr_props);
out:
	return;
}

void create_seekat_getrows_request(TALLOC_CTX * ctx,
				   struct wsp_request* request,
				   uint32_t cursor,
				   uint32_t bookmark,
				   uint32_t skip,
				   uint32_t rows,
				   uint32_t cbreserved,
				   uint32_t ulclientbase,
				   uint32_t cbrowwidth,
				   uint32_t fbwdfetch)
{
	struct wsp_cpmgetrowsin *getrows = &request->message.cpmgetrows;
	request->header.msg = CPMGETROWS;
	getrows->hcursor = cursor;
	getrows->crowstotransfer = rows;
	getrows->cbrowWidth = cbrowwidth;
	getrows->cbreadbuffer = 0x00004000;
	getrows->ulclientbase = ulclientbase;
	getrows->cbreserved = cbreserved;
	getrows->fbwdfetch = fbwdfetch;
	getrows->etype = EROWSEEKAT;
	getrows->chapt = 0;
	getrows->seekdescription.crowseekat.bmkoffset = bookmark;
	getrows->seekdescription.crowseekat.cskip = skip;
	getrows->seekdescription.crowseekat.hregion = 0;
}


static void extract_crowvariant_fixed(struct wsp_crowvariant32_guess *colval,
				   struct wsp_cbasestoragevariant *outval)
{
	switch (colval->vtype) {
		case VT_I1:
		case VT_UI1:
			outval->vvalue.vt_ui1 = colval->content.ui1_value;
			DBG_INFO("\tval 0x%x\n", colval->content.i1_value);
			break;
		case VT_I2:
		case VT_UI2:
		case VT_BOOL:
			outval->vvalue.vt_ui2 = colval->content.ui2_value;
			if (colval->vtype == VT_BOOL) {
				DBG_INFO("\tval %s\n",colval->content.bool_value == 0xFFFF ? "true" : "false" );
			} else {
				DBG_INFO("\tval 0x%x\n", colval->content.ui2_value);
			}
			break;
		case VT_I4:
		case VT_UI4:
			outval->vvalue.vt_ui4 = colval->content.ui4_value;
			DBG_INFO("\tval 0x%x\n", colval->content.ui4_value);
			break;
			outval->vvalue.vt_bool = colval->content.bool_value;
			break;
		case VT_UI8:
		case VT_R8:
		case VT_I8:
		case VT_FILETIME:
			outval->vvalue.vt_ui8 = colval->content.ui8_value;
			DBG_INFO("\tval hi 0x%x lo 0x%d\n", colval->content.r8_value.hi, colval->content.r8_value.lo);
			break;
		default:
			DBG_INFO("#FIXME unsupported type %s\n",
				get_vtype_name(colval->vtype));
			return;
			break;
	}
	outval->vtype = colval->vtype;
}

static void extract_crowvariant_fixed_vec_item(TALLOC_CTX *ctx, uint16_t type,
				       uint32_t offset, DATA_BLOB *rows_buf,
				       struct wsp_cbasestoragevariant *val)
{
	switch (type) {
		case VT_I1:
		case VT_UI1:
			val->vvalue.vt_ui1 = (uint8_t)*(offset + rows_buf->data);
			DBG_INFO("\tval 0x%x\n", val->vvalue.vt_ui1);
			break;
		case VT_I2:
		case VT_UI2:
		case VT_BOOL:
			val->vvalue.vt_ui2 = SVALS(rows_buf->data, offset);
			if (type == VT_BOOL) {
				DBG_INFO("\tval %s (0x%x)\n",val->vvalue.vt_bool == 0xFFFF ? "true" : "false", val->vvalue.vt_bool );
			} else {
				DBG_INFO("\tval 0x%x\n", val->vvalue.vt_i2);
			}
			break;
		case VT_I4:
		case VT_R4:
		case VT_UINT:
		case VT_UI4:
		case VT_ERROR:
			val->vvalue.vt_i4 = IVALS(rows_buf->data, offset);
			DBG_INFO("\tval 0x%x\n", val->vvalue.vt_i4);
			break;
		case VT_DATE:
		case VT_R8:
		case VT_UI8:
		case VT_FILETIME: {
			struct wsp_hyper *p_hyper = &val->vvalue.vt_ui8;
			uint64_t hyper = BVAL(rows_buf->data, offset);
			uint64_to_wsp_hyper(hyper, p_hyper);
			DBG_INFO("\tval 0x%" PRIx64 "\n", hyper);
			break;
		}
		case VT_DECIMAL: /* FIXME needs implementation */
		default:
			DBG_ERR("#FIXME Unhandled type %d\n", type);
			return;
			break;
	}
	val->vtype = type;
}


static void extract_rowbuf_variable_type(TALLOC_CTX *ctx, uint16_t type, uint32_t offset,
				      DATA_BLOB *rows_buf, uint32_t len,
				      struct wsp_cbasestoragevariant  *val)
{
	enum ndr_err_code err;
	struct ndr_pull *ndr_pull;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB variant_blob = data_blob_null;
	variant_blob.data = rows_buf->data + offset;
	variant_blob.length = len;
	ndr_pull = ndr_pull_init_blob(&variant_blob, ctx);
	switch (type) {
		case VT_LPWSTR: {
			const char *string;
			ndr_set_flags(&ndr_pull->flags, LIBNDR_FLAG_STR_NULLTERM);
			err = ndr_pull_string(ndr_pull, ndr_flags, &string);
			if (err) {
				DBG_ERR("error unmarshalling string from %p\n", variant_blob.data );
			} else {
				DBG_INFO("\tstring val ->>>%s<<<-\n", string );
				val->vtype = type;
				val->vvalue.vt_lpwstr.value = string;
			}
			break;
		}
		default:
			DBG_ERR("#FIXME Unhandled variant type %s\n", get_vtype_name(type));
			break;
	}
}

static void extract_crowvariant32(TALLOC_CTX *ctx,
			       struct wsp_crowvariant32_guess *colval,
			       uint32_t offset,
			       DATA_BLOB *rows_buf, uint32_t len,
			       struct wsp_cbasestoragevariant *val)
{
	int count;
	uint32_t addr;
	switch(colval->vtype) {
		case VT_LPWSTR:
		case VT_COMPRESSED_LPWSTR:
		case VT_BSTR:
		case VT_BLOB:
		case VT_BLOB_OBJECT:
		case VT_VARIANT:
			addr = colval->content.offset - offset;
			extract_rowbuf_variable_type(ctx, colval->vtype, addr,
						  rows_buf, len, val);
			break;
		case VT_I1:
		case VT_UI1:
		case VT_I2:
		case VT_UI2:
		case VT_BOOL:
		case VT_I4:
		case VT_UI4:
		case VT_R4:
		case VT_INT:
		case VT_UINT:
		case VT_ERROR:
		case VT_I8:
		case VT_UI8:
		case VT_R8:
		case VT_CY:
		case VT_DATE:
		case VT_FILETIME:
		case VT_DECIMAL: /* #TODO confirm this one */
		case VT_CLSID: /* #TODO confirm this one */
			extract_crowvariant_fixed(colval, val);
			break;
		case VT_I1 | VT_VECTOR:
		case VT_I2 | VT_VECTOR:
		case VT_UI2 | VT_VECTOR:
		case VT_BOOL | VT_VECTOR:
		case VT_I4 | VT_VECTOR:
		case VT_UI4 | VT_VECTOR:
		case VT_R4 | VT_VECTOR:
		case VT_ERROR | VT_VECTOR:
		case VT_I8 | VT_VECTOR:
		case VT_UI8 | VT_VECTOR:
		case VT_CY | VT_VECTOR:
		case VT_DATE | VT_VECTOR:
		case VT_FILETIME | VT_VECTOR:
		case VT_BSTR | VT_VECTOR:
		case VT_LPWSTR | VT_VECTOR:
		case VT_COMPRESSED_LPWSTR | VT_VECTOR:
		case VT_DECIMAL | VT_VECTOR:
		case VT_CLSID | VT_VECTOR:
		case VT_VARIANT | VT_VECTOR:
			addr = colval->content.offset_vec.offsets_addr - offset;
			DBG_INFO("\tunadjusted offset 0x%x adjusted 0x%x\n", colval->content.offset_vec.offsets_addr, addr);
			if (colval->vtype == (VT_LPWSTR | VT_VECTOR)) {
				val->vtype = colval->vtype;
				val->vvalue.vt_lpwstr_v.vvector_data =
					talloc_zero_array(ctx,
							struct vt_lpwstr,
							colval->content.offset_vec.count);
				val->vvalue.vt_lpwstr_v.vvector_elements =
					colval->content.offset_vec.count;
			}
			for (count = 0; count < colval->content.offset_vec.count;
			     count++) {
				uint32_t vec_item_offset = IVAL(rows_buf->data, addr);
				vec_item_offset = vec_item_offset - offset;
				if (is_variable_size(colval->vtype & ~VT_VECTOR)) {
					struct wsp_cbasestoragevariant tmp;
					extract_rowbuf_variable_type(ctx,
						colval->vtype & ~VT_VECTOR, vec_item_offset,
						rows_buf, len, &tmp);
					if (colval->vtype == (VT_LPWSTR | VT_VECTOR)) {
						val->vvalue.vt_lpwstr_v.vvector_data[count] = tmp.vvalue.vt_lpwstr;
					}

				} else {
					/*
					 * #FIXME but... this doesn't actually
					 * extract an array does it
					 */
					extract_crowvariant_fixed_vec_item(ctx,
						colval->vtype, vec_item_offset,
						rows_buf, val);
				}
				addr += sizeof(vec_item_offset);
			}
	};
}

static enum ndr_err_code process_columns(TALLOC_CTX *ctx,
					 bool is_64bit,
					 uint32_t cbreserved,
					 uint32_t ulclientbase,
					 struct wsp_cpmsetbindingsin *bindingin,
					 DATA_BLOB *rows_buf,
					 uint32_t nrow,
					 struct wsp_cbasestoragevariant *cols)
{
	int i;
	enum ndr_err_code err  = NDR_ERR_SUCCESS;
	struct ndr_pull *ndr_pull;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	uint32_t nrow_offset = nrow * bindingin->brow;
	if (is_64bit) {
		DBG_ERR("We don't handle 64 bit mode yet\n");
		err = NDR_ERR_VALIDATE;
		goto out;
	}
	/* process columns */
	for (i = 0; i < bindingin->ccolumns; i++) {
		struct wsp_ctablecolumn *tab_col = &bindingin->acolumns[i];
		struct wsp_crowvariant32_guess colval;
		DATA_BLOB col_val_blob = data_blob_null;
		DBG_INFO("\nRow[%d]Col[%d] property %s type %s",nrow, i,
		      prop_from_fullprop(ctx, &tab_col->propspec),
		      get_vtype_name(tab_col->vtype));
		if (tab_col->statusused) {
			DBG_INFO("\n\tstatusoffset 0x%x status is %s",
			      tab_col->statusoffset.value, get_store_status((uint8_t)*(rows_buf->data + nrow_offset + tab_col->statusoffset.value)));
		}
		if (tab_col->lengthused) {
			DBG_INFO("\n\tlengthoffset 0x%x value at length is 0x%x",tab_col->lengthoffset.value,  IVAL(rows_buf->data, nrow_offset + tab_col->lengthoffset.value));
		}
		if (tab_col->valueused) {
			int32_t offset = ulclientbase + cbreserved;
			int32_t len = 0;
			DBG_INFO("\n\tvalueoffset:valuesize 0x%x:0x%x crowvariant address = 0x%x",tab_col->valueoffset.value,
				tab_col->valuesize.value,
				(tab_col->valueoffset.value + nrow_offset));


			col_val_blob.data = rows_buf->data + tab_col->valueoffset.value + nrow_offset;
			col_val_blob.length = tab_col->valuesize.value;

			if (tab_col->vtype != VT_VARIANT) {
				if (is_variable_size(tab_col->vtype)) {
					struct wsp_crowvariant32 var_col;
					ndr_pull = ndr_pull_init_blob(&col_val_blob, ctx);
					err = ndr_pull_wsp_crowvariant32(ndr_pull, ndr_flags, &var_col);
					if (err) {
						DBG_ERR("!!! failed to pull row (guess) variant for col data\n");
						goto out;
					}
					if (var_col.vtype != tab_col->vtype) {
						DBG_ERR("!!! column type expected 0x%x doesn't match 0x%x in row buffer\n", tab_col->vtype, var_col.vtype);
						goto out;
					}
					extract_rowbuf_variable_type(ctx,
						var_col.vtype,
						var_col.offset - offset,
						rows_buf,
						tab_col->lengthoffset.value,
						&cols[i]);
				} else {
					extract_crowvariant_fixed_vec_item(ctx,
						tab_col->vtype,
						tab_col->valueoffset.value + nrow_offset,
						rows_buf,
						&cols[i]);
				}
				continue;
			}
			ndr_pull = ndr_pull_init_blob(&col_val_blob, ctx);
			err = ndr_pull_wsp_crowvariant32_guess(ndr_pull, ndr_flags, &colval);
			if (err) {
				DBG_ERR("!!! failed to pull row (guess) variant for col data\n");
				goto out;
			}
			DBG_INFO("\n");
			DBG_INFO("\tcrowvariant contains %s \n",
				get_vtype_name(colval.vtype));
			if (tab_col->lengthused) {
				/* it seems the size is what's at
				 * lengthoffset - tab_col->valuesize.value
				 */
				len = IVAL(rows_buf->data, nrow_offset + tab_col->lengthoffset.value);
				len = len - tab_col->valuesize.value;
			}

			extract_crowvariant32(ctx, &colval, offset, rows_buf, len, &cols[i]);
		}
	}
out:
	return err;
}

enum ndr_err_code extract_rowsarray(
			TALLOC_CTX * ctx,
			DATA_BLOB *rows_buf,
			bool is_64bit,
			struct wsp_cpmsetbindingsin *bindingsin,
			uint32_t cbreserved,
			uint32_t ulclientbase,
			uint32_t rows,
			struct wsp_cbasestoragevariant **rowsarray)
{
	int i;
	enum ndr_err_code err;

	for (i = 0; i < rows; i++ ) {
		struct wsp_cbasestoragevariant *cols =
				talloc_zero_array(ctx,
					  struct wsp_cbasestoragevariant,
					  bindingsin->ccolumns);
		err = process_columns(ctx,
				      is_64bit,
				      cbreserved,
				      ulclientbase,
				      bindingsin,
				      rows_buf,
				      i,
				      cols);
		if (err) {
			break;
		}
		rowsarray[i] = cols;
	}
	return err;
}

static void process_query_node(TALLOC_CTX *ctx,
			struct wsp_crestriction *crestriction,
			t_query *node);

static void process_andornot_node(TALLOC_CTX *ctx,
			struct wsp_crestriction *crestr,
			t_query *node,
			struct wsp_crestriction **left,
			struct wsp_crestriction **right)
{
	struct wsp_cnoderestriction *restriction_node;

	*left = NULL;
	*right = NULL;

	restriction_node =
		&crestr->restriction.cnoderestriction;

	crestr->weight = 1000;

	if (node->type == eAND || node->type == eOR) {
		if (node->type == eAND) {
			crestr->ultype = RTAND;
		} else {
			crestr->ultype = RTOR;
		}
		create_noderestriction(ctx, restriction_node, 2);
		*left = &restriction_node->panode[0];
		*right = &restriction_node->panode[1];
	} else {
		crestr->ultype = RTNOT;
		crestr->restriction.restriction.restriction =
			talloc_zero(ctx, struct wsp_crestriction);
		crestr=
			crestr->restriction.restriction.restriction;
	}
	if (*left == NULL) {
		*left = crestr;
	}
	if (*right == NULL) {
		*right = crestr;
	}
}

static void process_value_node(TALLOC_CTX *ctx,
			struct wsp_crestriction *crestriction,
			t_query *node)
{
	*crestriction = *node->restriction;
}

static void process_query_node(TALLOC_CTX *ctx,
			struct wsp_crestriction *crestriction,
			t_query *node)
{
	struct wsp_crestriction *left = NULL, *right = NULL;
	if (node == NULL) {
		return;
	}
	switch (node->type) {
		case eAND:
		case eOR:
		case eNOT:
			process_andornot_node(ctx, crestriction, node,
					      &left, &right);
			break;
		case eVALUE:
			process_value_node(ctx, crestriction, node);
		default:
			break;
	}
	process_query_node(ctx, left, node->left);
	process_query_node(ctx, right, node->right);
}

void create_querysearch_request(TALLOC_CTX * ctx,
				 struct wsp_request* request,
				 t_select_stmt *sql)
{
	struct wsp_cpmcreatequeryin *createquery = &request->message.cpmcreatequery;
	uint32_t indices[sql->cols->num_cols];
	int i;

	for (i = 0; i < sql->cols->num_cols; i++) {
		indices[i] = i;
	}

	request->header.msg = CPMCREATEQUERY;
	createquery->ccolumnsetpresent = 1;
	createquery->columnset.columnset.count = sql->cols->num_cols;
	fill_uint32_vec(ctx, &createquery->columnset.columnset.indexes,
			indices,
			sql->cols->num_cols);

	/* handle restrictions */
	createquery->crestrictionpresent = 1;
	createquery->restrictionarray.restrictionarray.count = 1;
	createquery->restrictionarray.restrictionarray.ispresent = 1;

	create_restriction_array(ctx,
				 &createquery->restrictionarray.restrictionarray.restrictions,
				 createquery->restrictionarray.restrictionarray.count);

	process_query_node(ctx, &createquery->restrictionarray.restrictionarray.restrictions[0], sql->where);


	/* handle rest */
	createquery->csortsetpresent = 1;
	if (createquery->csortsetpresent) {
		/* sort on first column */
		struct wsp_csort data[] = {
			{0x00000000, 0x00000000, 0x00000000, 0x00001809},
		};
		struct wsp_csortset *sortset;
		struct wsp_cingroupsortaggregsets *aggregsets;

		aggregsets = &createquery->sortset.groupsortaggregsets;
		aggregsets->ccount = 1;
		aggregsets->sortsets =
			talloc_zero_array(ctx,
					  struct wsp_cingroupsortaggregset,
					  aggregsets->ccount);
		sortset = &aggregsets->sortsets[0].sortaggregset;
		sortset->count = ARRAY_SIZE(data);
		fill_sortarray(ctx, &sortset->sortarray, data,sortset->count);
	}

	createquery->ccategorizationsetpresent = 0;

	createquery->rowsetproperties.ubooleanoptions = 0x00000203;
	createquery->rowsetproperties.ulmaxopenrows = 0x00000000;
	createquery->rowsetproperties.ulmemoryusage = 0x00000000;
	createquery->rowsetproperties.cmaxresults = 0x00000000;
	createquery->rowsetproperties.ccmdtimeout = 0x00000005;

	createquery->pidmapper.count = sql->cols->num_cols;
	createquery->pidmapper.apropspec = talloc_zero_array(ctx,
						struct wsp_cfullpropspec,
						createquery->pidmapper.count);
	for(i = 0; i < sql->cols->num_cols; i++) {
		struct wsp_cfullpropspec *prop =
				&createquery->pidmapper.apropspec[i];
		if (!set_fullpropspec(ctx,
				      prop, sql->cols->cols[i],
				      PRSPEC_PROPID)) {
			/* #FIXME error handling */
			DBG_ERR("Failed to handle property named %s\n",
				sql->cols->cols[i]);
			continue;
		}
	}
	createquery->lcid = 0x00001809;
}

static uint32_t alignval(uint32_t num, int32_t align) {
	num = num + (align - (num % align)) % align;
	return num;
}

static int32_t getNextAddress(int32_t value_off, int32_t status_off, int32_t len_off)
{
//	uint32_t tmp = MAX(value_off + 0x10, status_off + 1);
//	return MAX(tmp, len_off + 2);
	return MAX(MAX(value_off + 0x10, status_off + 1), len_off + 2);
}

static void create_binding_offsets(struct binding *binding, int no_cols)
{
	uint32_t buf_addr = 0x0;
	uint32_t i;

	uint32_t value_off = 0;
	uint32_t len_off = 0;

	/* initial state, seems weird but can't handle it any other way */
	uint32_t status_off = 0x1; /* this will get incremented to the desired 0x2 */
	uint32_t avail = 0x4;
	int status_remain = 0x2;
	int len_remain = -1;

	const static uint32_t WINDOW = 0x8;
	const static uint32_t LEN_STAT_SIZE = 0x4;
	for (i = 0; i < no_cols; i++) {
		buf_addr = buf_addr + WINDOW;
		value_off = buf_addr;

		if (status_remain <= 0) {
			if (avail) {
				status_off = avail;
				status_remain = LEN_STAT_SIZE;
				avail = 0;
			} else {
				/*
				 * we prepare the address to allocate
				 * another block from here. It will
				 * be allocated automatically when we
				 * re-enter the loop */
				status_off = getNextAddress(value_off, status_off, len_off) + WINDOW;
				status_remain = LEN_STAT_SIZE;
				buf_addr = status_off;
				avail = buf_addr + LEN_STAT_SIZE;
			}
		} else {
			status_off++;
			buf_addr = getNextAddress(value_off, status_off, len_off);
		}

		if (len_remain <= 0) {
			if (avail) {
				len_off = avail;
				len_remain = LEN_STAT_SIZE;
				avail = 0;
			} else {
				/*
				 * we prepare the address to allocate
				 * another block from here. It will
				 * be allocated automatically when we
				 * re-enter the loop */
				len_off = getNextAddress(value_off, status_off, len_off) + WINDOW;
				len_remain = LEN_STAT_SIZE;
				buf_addr = len_off;
				avail = buf_addr + LEN_STAT_SIZE;
			}
		} else {
			len_off += 0x4;
			buf_addr = getNextAddress(value_off, status_off, len_off);
		}
		status_remain--;
		len_remain -= LEN_STAT_SIZE;
		binding[i].value_off = value_off;
		binding[i].status_off = status_off;
		binding[i].len_off = len_off;
#if 0
		printf("Col[%d]\n", i);
		printf("\t value offset: 0x%x\n", value_off);
		printf("\t status offset: 0x%x remain(%d)\n", status_off, status_remain);
		printf("\t length offset: 0x%x remain(%d)\n", len_off, len_remain );
		printf("current buff addr 0x%x\n", buf_addr);
#endif
	}
}

static void fill_bindings(TALLOC_CTX *ctx,
		   struct wsp_cpmsetbindingsin *bindingsin,
		   char **col_names)
{
	uint32_t i;
	struct binding *offsets;
	uint32_t num_cols;
	struct wsp_ctablecolumn *tablecols = bindingsin->acolumns;
	bindingsin->brow = 0x0;
	num_cols = bindingsin->ccolumns;

	offsets = talloc_zero_array(ctx, struct binding, num_cols);
	create_binding_offsets(offsets, num_cols);
	for (i = 0; i < num_cols; i++) {
		uint32_t max_off;
		if (!set_ctablecolumn(ctx, &tablecols[i], col_names[i],
				      &offsets[i])) {
			DBG_ERR("Failed to handle property named %s\n",
				col_names[i]);
			continue;
		}
		max_off = MAX(offsets[i].value_off + 0x10,
			      offsets[i].status_off + 1);
		max_off = MAX(max_off, offsets[i].len_off + 2);
		if (max_off > bindingsin->brow) {
			bindingsin->brow = max_off;
		}
	}
	/* important */
	bindingsin->brow = alignval(bindingsin->brow,4);
}

void create_setbindings_request(TALLOC_CTX * ctx,
				struct wsp_request* request,
				t_select_stmt *sql,
				uint32_t cursor)
{
	struct wsp_cpmsetbindingsin *bindingsin = &request->message.cpmsetbindings;
	request->header.msg = CPMSETBINDINGSIN;
	bindingsin->hcursor = cursor;
	bindingsin->ccolumns = sql->cols->num_cols;

	bindingsin->acolumns = talloc_zero_array(ctx, struct wsp_ctablecolumn,
						 bindingsin->ccolumns);
	fill_bindings(ctx, bindingsin, sql->cols->cols);

}

enum search_kind get_kind(const char* kind_str)
{
	enum search_kind result = Unknown;
	int i;
	const static struct {
		const char* str;
		enum search_kind search_kind;
	} kind_map[] = {
		{"Calendar", Calendar},
		{"Communication", Communication},
		{"Contact", Contact},
		{"Document", Document},
		{"Email", Email},
		{"Feed", Feed},
		{"Folder", Folder},
		{"Game", Game},
		{"InstantMessage", InstantMessage},
		{"Journal", Journal},
		{"Link", Link},
		{"Movie", Movie},
		{"Music", Music},
		{"Note", Note},
		{"Picture", Picture},
		{"Program", Program},
		{"RecordedTV", RecordedTV},
		{"SearchFolder", SearchFolder},
		{"Task", Task},
		{"Video", Video},
		{"WebHistory", WebHistory},
	};
	for (i = 0; i < ARRAY_SIZE(kind_map); i++) {
		if (strequal(kind_str, kind_map[i].str)) {
			result = kind_map[i].search_kind;
			break;
		}
	}
	return result;
}

struct wsp_client_ctx
{
	struct dcerpc_pipe *p;
	struct smbcli_state *cli;
	struct smb2_tree *tree;
};

static NTSTATUS connect_server_smb(TALLOC_CTX *mem_ctx,
			const char *host,
			struct tevent_context *ev_ctx,
			struct cli_credentials *credentials,
			struct smbcli_state **cli)
{
	NTSTATUS status;
	struct smbcli_options options;
	struct smbcli_session_options session_options;
	lpcfg_smbcli_options(cmdline_lp_ctx, &options);

	lpcfg_smbcli_session_options(cmdline_lp_ctx, &session_options);

	status = smbcli_full_connection(mem_ctx,
					cli,
					host,
					lpcfg_smb_ports(cmdline_lp_ctx),
					"IPC$", NULL,
					lpcfg_socket_options(cmdline_lp_ctx),
					credentials,
					lpcfg_resolve_context(cmdline_lp_ctx),
					ev_ctx, &options, &session_options,
					lpcfg_gensec_settings(mem_ctx,
							      cmdline_lp_ctx));
	return status;
}

static NTSTATUS connect_server_smb2(TALLOC_CTX *mem_ctx,
			const char *host,
			struct tevent_context *ev_ctx,
			struct cli_credentials *credentials,
			struct smb2_tree **tree)
{
	NTSTATUS status;
	struct smbcli_options options;
	struct smbcli_session_options session_options;
	lpcfg_smbcli_options(cmdline_lp_ctx, &options);

	lpcfg_smbcli_session_options(cmdline_lp_ctx, &session_options);

	status = smb2_connect(mem_ctx,
			      host,
			      lpcfg_smb_ports(cmdline_lp_ctx),
			      "IPC$",
			      lpcfg_resolve_context(cmdline_lp_ctx),
			      credentials,
			      tree,
			      ev_ctx,
			      &options,
			      lpcfg_socket_options(cmdline_lp_ctx),
			      lpcfg_gensec_settings(mem_ctx,
						    cmdline_lp_ctx)
			      );
	return status;
}

static NTSTATUS wait_for_pipe(TALLOC_CTX *mem_ctx,
			      struct tevent_context *ev_ctx,
			      bool smb2_or_greater,
			      struct wsp_client_ctx *ctx,
			      const char *pipe_name)
{
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smb2_or_greater) {
		struct smb2_tree *tree = ctx->tree;
		status = smb2cli_ioctl_pipe_wait(
				tree->session->transport->conn,
				tree->session->transport->options.request_timeout,
				tree->session->smbXcli,
				tree->smbXcli,
				pipe_name,
				1);
	} else {
		struct smbcli_state *cli = ctx->cli;
		struct smbcli_tree *tree = cli->tree;
		/* WHY isn't the tid set already here ? */
		smb1cli_tcon_set_id(tree->smbXcli, tree->tid);
		status = smb1cli_ioctl_pipe_wait(
				tree->session->transport->conn,
				tree->session->transport->options.request_timeout,
				tree->session->pid,
				tree->session->smbXcli,
				tree->smbXcli,
				pipe_name,
				1);
	}
	return status;
}

static NTSTATUS wsp_resp_pdu_complete(struct tstream_context *stream,
				      void *private_data,
				      DATA_BLOB blob,
				      size_t *packet_size)
{
	ssize_t to_read;

	to_read = tstream_pending_bytes(stream);
	if (to_read == -1) {
		return NT_STATUS_IO_DEVICE_ERROR;
	}

	if (to_read > 0) {
		*packet_size = blob.length + to_read;
		return STATUS_MORE_ENTRIES;
	}

	return NT_STATUS_OK;
}

NTSTATUS wsp_server_connect(TALLOC_CTX *mem_ctx,
			    const char *servername,
			    struct tevent_context *ev_ctx,
			    struct cli_credentials *credentials,
			    struct wsp_client_ctx **wsp_ctx)
{
	struct wsp_client_ctx *ctx = talloc_zero(mem_ctx,
						 struct wsp_client_ctx);
	struct dcerpc_pipe *p;
	struct dcerpc_binding_handle *h;
	NTSTATUS status;
	bool smb2_or_greater =
		(lpcfg_client_max_protocol(cmdline_lp_ctx) >= PROTOCOL_SMB2_02);
	if (smb2_or_greater) {
		status = connect_server_smb2(mem_ctx,
					     servername,
					     ev_ctx,
					     credentials,
					     &ctx->tree);
	} else {
		status  = connect_server_smb(mem_ctx,
					     servername,
					     ev_ctx,
					     credentials,
					     &ctx->cli);
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to connect to server status: %s)\n",
			nt_errstr(status));
		return status;
	}
	p = dcerpc_pipe_init(mem_ctx, ev_ctx);

	if (!p) {
		DBG_ERR("failed to int the pipe)\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	status = wait_for_pipe(mem_ctx,
			       ev_ctx,
			       smb2_or_greater,
			       ctx,
			       "MsFteWds");
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("wait for pipe failed: %s)\n",
			nt_errstr(status));
		return status;
	}
	if (smb2_or_greater) {
		status = dcerpc_pipe_open_smb2(p, ctx->tree, "MsFteWds");
	} else {
		status = dcerpc_pipe_open_smb(p, ctx->cli->tree, "MsFteWds");
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to connect to server status: %s)\n",
		      nt_errstr(status));
		return status;
	}

	h = tstream_binding_handle_create(p,
					  NULL,
					  &p->conn->transport.stream,
					  MSG_HDR_SIZE,
					  wsp_resp_pdu_complete,
					  ctx, 42280);

	if (!h) {
		DBG_ERR("failed to create the pipe handle)\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	p->binding_handle = h;
	ctx->p = p;
	*wsp_ctx = ctx;

	return status;
}

static NTSTATUS write_something(TALLOC_CTX* ctx,
				struct dcerpc_pipe *p,
				DATA_BLOB *blob_in,
				DATA_BLOB *blob_out)
{
	uint32_t outflags;
	struct dcerpc_binding_handle *handle = p->binding_handle;
	NTSTATUS status;

	status = dcerpc_binding_handle_raw_call(handle,
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

static enum ndr_err_code parse_blob(TALLOC_CTX *ctx, DATA_BLOB *blob,
		struct wsp_request *request, struct wsp_response *response,
		DATA_BLOB *unread)
{
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	uint32_t status = 0;

	ndr = ndr_pull_init_blob(blob, ctx);

	/* peek at the status */
	status = IVAL(blob->data, 4);

	/* is hard error ?*/
	if (status & 0x80000000 && blob->length == MSG_HDR_SIZE) {
		/* just pull the header */
		err = ndr_pull_wsp_header(ndr, ndr_flags, &response->header);
		DBG_ERR("error: %s\n", nt_errstr(NT_STATUS(status)));
		goto out;
	}
	err = ndr_pull_wsp_response(ndr, ndr_flags, response);
	if (err) {
		DBG_ERR("Failed to pull header from response blob error %d\n",  err);
		goto out;
	}
	if (DEBUGLEVEL >=6) {
		NDR_PRINT_DEBUG(wsp_response, response);
	}
	if (response->header.msg == CPMGETROWS) {
		if (request) {
			/* point to rows buffer */
			ndr->offset = request->message.cpmgetrows.cbreserved;
		}
	}

	if (ndr->offset < blob->length) {
		int bytes = blob->length - ndr->offset;
		*unread = data_blob_named(blob->data + ndr->offset,
					  bytes, "UNREAD");
		DBG_WARNING("\nThere are unprocessed bytes (len 0x%x) at end of message\n", bytes);
	}

out:
	return err;
}

static void set_msg_checksum(DATA_BLOB *blob, struct wsp_header *hdr)
{
	/* point at payload */
	uint32_t i;
	uint8_t *buffer = blob->data + MSG_HDR_SIZE;
	uint32_t buf_size = blob->length - MSG_HDR_SIZE;
	uint32_t nwords = buf_size/4;
	uint32_t offset = 0;
	uint32_t checksum = 0;

	static const uint32_t xor_const = 0x59533959;
	for(i = 0; i < nwords; i++) {
		checksum += IVAL(buffer, offset);
		offset += 4;
	}

	checksum ^= xor_const;
	checksum -= hdr->msg;
	hdr->checksum = checksum;
}

static enum ndr_err_code insert_header_and_checksum(TALLOC_CTX *ctx, DATA_BLOB* blob,
				struct wsp_request *request)
{
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	struct ndr_push *header_ndr = ndr_push_init_ctx(ctx);

	if (request->header.msg == CPMCONNECT
	|| request->header.msg == CPMCREATEQUERY
	|| request->header.msg == CPMSETBINDINGSIN
	|| request->header.msg == CPMGETROWS
	|| request->header.msg == CPMFETCHVALUE) {

		set_msg_checksum(blob, &request->header);
	}
	err = ndr_push_wsp_header(header_ndr, ndr_flags, &request->header);
	if (err) {
		DBG_ERR("Failed to push header, error %d\n", err);
		return err;
	}
	memcpy(blob->data, header_ndr->data, MSG_HDR_SIZE);
	return err;
}

NTSTATUS wsp_request_response(TALLOC_CTX* ctx,
			      struct wsp_client_ctx *wsp_ctx,
			      struct wsp_request *request,
			      struct wsp_response *response,
			      DATA_BLOB *unread)
{
	struct dcerpc_pipe *p = wsp_ctx->p;
	NTSTATUS status = NT_STATUS_OK;

	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	struct ndr_push* push_ndr;
	enum ndr_err_code err;

	DATA_BLOB req_blob;
	DATA_BLOB resp_blob;

	ZERO_STRUCT(req_blob);
	ZERO_STRUCT(resp_blob);

	push_ndr = ndr_push_init_ctx(ctx);

	/* write message payload first */
	push_ndr->offset = MSG_HDR_SIZE;
	DBG_INFO("\n");

	switch(request->header.msg) {
		case CPMCONNECT:
			err =  ndr_push_wsp_cpmconnectin(push_ndr, ndr_flags,
						&request->message.cpmconnect);
			break;
		case CPMCREATEQUERY:
		{
			err = ndr_push_wsp_cpmcreatequeryin(push_ndr, ndr_flags,
						&request->message.cpmcreatequery);
			req_blob = ndr_push_blob(push_ndr);
			/* we need to set cpmcreatequery.size */
			request->message.cpmcreatequery.size =  req_blob.length - MSG_HDR_SIZE;
			SIVAL(req_blob.data, MSG_HDR_SIZE,
			      request->message.cpmcreatequery.size);

			break;
		}
		case CPMSETBINDINGSIN:
			err = ndr_push_wsp_cpmsetbindingsin(push_ndr, ndr_flags,
						&request->message.cpmsetbindings);
			req_blob = ndr_push_blob(push_ndr);
			/* we need to set cpmsetbindings.bbindingdesc (size) */
			request->message.cpmsetbindings.bbindingdesc =
							req_blob.length - MSG_HDR_SIZE - 16;
			SIVAL(req_blob.data, MSG_HDR_SIZE + 8,
			      request->message.cpmsetbindings.bbindingdesc);
			break;
		case CPMGETROWS:
			err = ndr_push_wsp_cpmgetrowsin(push_ndr, ndr_flags,
						&request->message.cpmgetrows);
			req_blob = ndr_push_blob(push_ndr);
			request->message.cpmgetrows.cbseek = req_blob.length - MSG_HDR_SIZE - 32;
			/* we need to set cpmgetrowsin.cbseek (size) */
			SIVAL(req_blob.data, MSG_HDR_SIZE + 12,
			      request->message.cpmgetrows.cbseek);
			SIVAL(req_blob.data, MSG_HDR_SIZE + 16,
			      request->message.cpmgetrows.cbreserved);
			break;
		case CPMGETQUERYSTATUS:
			err = ndr_push_wsp_cpmgetquerystatusin(push_ndr, ndr_flags,
						&request->message.cpmgetquerystatus);
			break;
		case CPMGETQUERYSTATUSEX:
			err = ndr_push_wsp_cpmgetquerystatusexin(push_ndr, ndr_flags,
						&request->message.cpmgetquerystatusex);
			break;
		case CPMFREECURSOR:
			err = ndr_push_wsp_cpmfreecursorin(push_ndr, ndr_flags,
						&request->message.cpmfreecursor);
			break;
/*
		case CPMFREECURSOR:
			status = push_wsp_cpmfreecursorin(buffer, request,
							  &offset);
			break;
		case CPMDISCONNECT:
			push_wsp_cpmdisconnect(buffer, request, &offset);
			break;
*/
		default:
			status = NT_STATUS_MESSAGE_NOT_FOUND;
			goto out;
			break;
	}
	if (err) {
		DBG_ERR("failed to serialise message! (%d)\n", err);
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	if (!req_blob.data) {
		req_blob = ndr_push_blob(push_ndr);
	}
	err = insert_header_and_checksum(ctx, &req_blob, request);

	DBG_NOTICE("\nsending raw message from client len %d\n", (int)req_blob.length);
	DBG_NOTICE("\nsending raw message from client\n");
	DBG_NOTICE(  "===============================\n");

	dump_data(5, req_blob.data, req_blob.length);

	status = write_something(ctx, p, &req_blob, &resp_blob);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to write message\n");
		goto out;
	}
	DBG_NOTICE("\nraw response from server\n");
	DBG_NOTICE(  "========================\n");
	dump_data(5,  resp_blob.data, resp_blob.length);

	err = parse_blob(ctx, &resp_blob, request, response, unread);
	if (err) {
		DBG_ERR("Failed to parse response error %d\n", err);
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	DBG_NOTICE("response status is 0x%x\n", response->header.status);
	/* propagate error status to return status */
	if (response->header.status & 0x80000000) {
		status = NT_STATUS_UNSUCCESSFUL;
	}
out:
	return status;
}

/*
 * tmp accessors, hoping we can remove the need for clients to know about
 */

struct dcerpc_pipe * get_wsp_pipe(struct wsp_client_ctx *ctx)
{
	return ctx->p;
}

struct smbcli_state * get_wsp_clistate(struct wsp_client_ctx *ctx)
{
	return ctx->cli;
}
