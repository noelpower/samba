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
#include "librpc/wsp/wsp_helper.h"
#include "bin/default/librpc/gen_ndr/ndr_wsp.h"

void uint64_to_wsp_hyper(uint64_t src, struct wsp_hyper *dest)
{
	dest->hi = (uint32_t)src;
	dest->lo = (uint32_t)(src>>32);
}

void wsp_hyper_to_uint64(struct wsp_hyper *src, uint64_t *dest)
{
	*dest = src->lo;
	*dest <<= 32;
	*dest |= src->hi;
}

uint32_t calc_array_size(struct safearraybound *bounds, uint32_t ndims)
{
	int i;
	int result = 0;

	for(i = 0; i < ndims; i++) {
		uint32_t celements = bounds[i].celements;
		if (i) {
			result = result * celements;
		} else {
			result = celements;
		}
	}
	return result;
}

const struct full_propset_info *get_propset_info_with_guid(
						const char *prop_name,
						struct GUID *propset_guid)
{
	int i;
	const struct full_guid_propset *guid_propset = NULL;
	const struct full_propset_info *result = NULL;
	for (i = 0; full_propertyset[i].prop_info != NULL; i++) {
		const struct full_propset_info *item = NULL;
		guid_propset = &full_propertyset[i];
		item = guid_propset->prop_info;
		while (item->id) {
			if (strequal(prop_name, item->name)) {
				*propset_guid = guid_propset->guid;
				result = item;
				break;
			}
			item++;
		}
		if (result) {
			break;
		}
	}
	return result;
}

const struct full_propset_info *get_prop_info(const char *prop_name)
{
	const struct full_propset_info *result = NULL;
	struct GUID guid;
	result = get_propset_info_with_guid(prop_name, &guid);
	return result;
}

char *prop_from_fullprop(TALLOC_CTX *ctx, struct wsp_cfullpropspec *fullprop)
{
	int i;
	char *result = NULL;
	const struct full_propset_info *item = NULL;
	bool search_by_id = (fullprop->ulkind == PRSPEC_PROPID);

	for (i = 0; full_propertyset[i].prop_info != NULL; i++) {
		/* find propset */
		if (GUID_equal(&fullprop->guidpropset,
			       &full_propertyset[i].guid)) {
			item = full_propertyset[i].prop_info;
			break;
		}
	}
	if (item) {
		while (item->id) {
			if (search_by_id) {
				if( fullprop->name_or_id.prspec == item->id) {
					result = talloc_strdup(ctx, item->name);
					break;
				}
			} else if (strcmp(item->name,
					fullprop->name_or_id.propname.vstring)
					== 0) {
				result = talloc_strdup(ctx, item->name);
				break;
			}
			item++;
		}
	}

	if (!result) {
		result = GUID_string(ctx, &fullprop->guidpropset);

		if (search_by_id) {
			result = talloc_asprintf(result, "%s/%d", result,
						 fullprop->name_or_id.prspec);
		} else {
			result = talloc_asprintf(result, "%s/%s", result,
					fullprop->name_or_id.propname.vstring);
		}
	}
	return result;
}

static const struct {
	uint32_t id;
	const char *name;
} typename_map[] = {
	{VT_EMPTY, "Empty"},
	{VT_NULL, "Null"},
	{VT_I2, "VT_I2"},
	{VT_I4, "VT_I4"},
	{VT_I4, "VT_I4"},
	{VT_R4, "VT_R4"},
	{VT_R8, "VT_R8"},
	{VT_CY, "VT_CY"},
	{VT_DATE, "VT_DATE"},
	{VT_BSTR, "VT_BSTR"},
	{VT_I1, "VT_I1"},
	{VT_UI1, "VT_UI1"},
	{VT_UI2, "VT_UI2"},
	{VT_UI4, "VT_UI4"},
	{VT_I8, "VT_I8"},
	{VT_UI8, "VT_UI8"},
	{VT_INT, "VT_INT"},
	{VT_UINT, "VT_UINT"},
	{VT_ERROR, "VT_ERROR"},
	{VT_BOOL, "VT_BOOL"},
	{VT_VARIANT, "VT_VARIANT"},
	{VT_DECIMAL, "VT_DECIMAL"},
	{VT_FILETIME, "VT_FILETIME"},
	{VT_BLOB, "VT_BLOB"},
	{VT_BLOB_OBJECT, "VT_BLOB_OBJECT"},
	{VT_CLSID, "VT_CLSID"},
	{VT_LPSTR, "VT_LPSTR"},
	{VT_LPWSTR, "VT_LPWSTR"},
	{VT_COMPRESSED_LPWSTR, "VT_COMPRESSED_LPWSTR"},
};

const char * get_vtype_name(uint32_t type)
{
	const char *type_name = NULL;
	static char result_buf[255];
	int i;
	uint32_t temp = type & ~(VT_VECTOR | VT_ARRAY);
	for (i = 0; i < ARRAY_SIZE(typename_map); i++) {
		if (temp == typename_map[i].id) {
			type_name = typename_map[i].name;
			break;
		}
	}
	if (type & VT_VECTOR) {
		snprintf(result_buf, sizeof(result_buf), "Vector | %s", type_name);
	} else if (type & VT_ARRAY) {
		snprintf(result_buf, sizeof(result_buf), "Array | %s", type_name);
	} else {
		snprintf(result_buf, sizeof(result_buf), "%s", type_name);
	}
	return result_buf;
}

bool is_variable_size(uint16_t vtype)
{
	bool result;
	switch(vtype) {
		case VT_LPWSTR:
		case VT_BSTR:
		case VT_BLOB:
		case VT_BLOB_OBJECT:
		case VT_VARIANT:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

const char *get_store_status(uint8_t status_byte)
{
	const char *result;
	switch(status_byte) {
		case 0:
			result = "StoreStatusOk";
			break;
		case 1:
			result = "StoreStatusDeferred";
			break;
		case 2:
			result = "StoreStatusNull";
			break;
		default:
			result = "Unknown Status";
			break;
	}
	return result;
}

void set_variant_lpwstr(TALLOC_CTX *ctx,
			struct wsp_cbasestoragevariant *vvalue,
			const char *string_val)
{
	vvalue->vtype = VT_LPWSTR;
	vvalue->vvalue.vt_lpwstr.value = talloc_strdup(ctx, string_val);
}

void set_variant_i4(TALLOC_CTX *ctx,
		    struct wsp_cbasestoragevariant *vvalue,
		    uint32_t val)
{
	vvalue->vtype = VT_I4;
	vvalue->vvalue.vt_i4 = val;
}

void set_variant_vt_bool(TALLOC_CTX *ctx,
			struct wsp_cbasestoragevariant *variant,
			bool bval)
{
	variant->vtype = VT_BOOL;
	variant->vvalue.vt_bool = bval;
}

static void fill_int32_vec(TALLOC_CTX* ctx,
			    int32_t **pdest,
			    int32_t* ivector, uint32_t elems)
{
	int i;
	int32_t *dest = talloc_zero_array(ctx, int32_t, elems);
	for ( i = 0; i < elems; i++ ) {
		dest[ i ] = ivector[ i ];
	}
	*pdest = dest;
}

void set_variant_i4_vector(TALLOC_CTX *ctx,
			   struct wsp_cbasestoragevariant *variant,
			   int32_t* ivector, uint32_t elems)
{
	variant->vtype = VT_VECTOR | VT_I4;
	variant->vvalue.vt_i4_vec.vvector_elements = elems;
	fill_int32_vec(ctx, &variant->vvalue.vt_i4_vec.vvector_data, ivector, elems);
}

static void fill_string_vec(TALLOC_CTX* ctx,
				struct wsp_cbasestoragevariant *variant,
				const char **strings, uint16_t elems)
{
	int i;
	variant->vvalue.vt_lpwstr_v.vvector_elements = elems;
	variant->vvalue.vt_lpwstr_v.vvector_data = talloc_zero_array(ctx,
							struct vt_lpwstr,
							elems);

	for( i = 0; i < elems; i++ ) {
		variant->vvalue.vt_lpwstr_v.vvector_data[ i ].value = talloc_strdup(ctx, strings[ i ]);
	}
}

static void fill_bstr_vec(TALLOC_CTX *ctx,
		  struct vt_bstr **pvector,
		  const char **strings, uint16_t elems)
{
	int i;
	struct vt_bstr *vdata = talloc_zero_array(ctx, struct vt_bstr, elems);

	for( i = 0; i < elems; i++ ) {
		vdata [ i ].value = talloc_strdup(ctx, strings[ i ]);
	}
	*pvector = vdata;
}

void set_variant_bstr(TALLOC_CTX *ctx, struct wsp_cbasestoragevariant *variant,
			const char *string_val)
{
	variant->vtype = VT_BSTR;
	variant->vvalue.vt_bstr.value = talloc_strdup(ctx, string_val);
}

void set_variant_lpwstr_vector(TALLOC_CTX *ctx,
			      struct wsp_cbasestoragevariant *variant,
			      const char **string_vals, uint32_t elems)
{
	variant->vtype = VT_LPWSTR | VT_VECTOR;
	fill_string_vec(ctx, variant, string_vals, elems);
}

void set_variant_array_bstr(TALLOC_CTX *ctx,
			   struct wsp_cbasestoragevariant *variant,
			   const char **string_vals, uint16_t elems)
{
	variant->vtype = VT_BSTR | VT_ARRAY;
	variant->vvalue.vt_bstr_array.cdims = 1;
	variant->vvalue.vt_bstr_array.ffeatures = 0;

	variant->vvalue.vt_bstr_array.rgsabound =
		talloc_zero_array(ctx, struct safearraybound, 1);

	variant->vvalue.vt_bstr_array.rgsabound[0].celements = elems;
	variant->vvalue.vt_bstr_array.rgsabound[0].ilbound = 0;
	variant->vvalue.vt_bstr_array.cbelements = 0;
	fill_bstr_vec(ctx, &variant->vvalue.vt_bstr_array.vdata,
		      string_vals, elems);
	/*
	 * if cbelements is the num bytes per elem it kindof means each
	 * string in the array must be the same size ?
	 */

	if (elems >0) {
		variant->vvalue.vt_bstr_array.cbelements =
			strlen_m_term(variant->vvalue.vt_bstr_array.vdata[0].value)*2;
	}
}

/* create single dim array of vt_i4 */
void set_variant_array_i4(TALLOC_CTX *ctx,
			 struct wsp_cbasestoragevariant *variant,
			 int32_t *vals, uint16_t elems)
{
	/* #TODO see if we can combine with other set_variant_array methods */
	variant->vtype = VT_I4 | VT_ARRAY;
	variant->vvalue.vt_i4_array.cdims = 1;
	variant->vvalue.vt_i4_array.ffeatures = 0;

	variant->vvalue.vt_i4_array.rgsabound =
		talloc_zero_array(ctx, struct safearraybound, 1);

	variant->vvalue.vt_i4_array.rgsabound[0].celements = elems;
	variant->vvalue.vt_i4_array.rgsabound[0].ilbound = 0;
	variant->vvalue.vt_i4_array.cbelements = sizeof(uint32_t);
	fill_int32_vec(ctx, &variant->vvalue.vt_i4_array.vdata, vals, elems);
}

const char *genmeth_to_string(uint32_t genmethod)
{
	const char *result;
	switch (genmethod) {
		case 0:
			result = "equals";
			break;
		case 1:
			result = "starts with";
			break;
		case 2:
			result = "matches inflection";
			break;
		default:
			result = "ERROR, unknown generate method";
			break;
	}
	return result;
}

bool is_operator(struct wsp_crestriction *restriction) {
	bool result;
	switch(restriction->ultype) {
		case RTAND:
		case RTOR:
		case RTNOT:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

const char *op_as_string(struct wsp_crestriction *restriction)
{
	const char *op = NULL;
	if (is_operator(restriction)) {
		switch(restriction->ultype) {
			case RTAND:
				op = " && ";
				break;
			case RTOR:
				op = " || ";
				break;
			case RTNOT:
				op = "!";
				break;
		}
	} else if (restriction->ultype == RTPROPERTY) {
		struct wsp_cpropertyrestriction *prop_restr =
			&restriction->restriction.cpropertyrestriction;
		switch (prop_restr->relop & 0XF) {
			case PREQ:
				op = "=";
				break;
			case PRNE:
				op = "!=";
				break;
			case PRGE:
				op = ">=";
				break;
			case PRLE:
				op = "<=";
				break;
			case PRLT:
				op = "<";
				break;
			case PRGT:
				op = ">";
				break;
			default:
				break;
		}
	} else if (restriction->ultype == RTCONTENT) {
		struct wsp_ccontentrestriction *content = NULL;
		content = &restriction->restriction.ccontentrestriction;
		op = genmeth_to_string(content->ulgeneratemethod);
	} else if (restriction->ultype == RTNATLANGUAGE) {
		op = "=";
	}
	return op;
}

struct wsp_cfullpropspec *get_full_prop(struct wsp_crestriction *restriction)
{
	struct wsp_cfullpropspec *result;
	switch (restriction->ultype) {
		case RTPROPERTY:
			result = &restriction->restriction.cpropertyrestriction.property;
			break;
		case RTCONTENT:
			result = &restriction->restriction.ccontentrestriction.property;
			break;
		case RTNATLANGUAGE:
			result = &restriction->restriction.cnatlanguagerestriction.property;
			break;
		default:
			result = NULL;
			break;
	}
	return result;
}

const char *variant_as_string(TALLOC_CTX *ctx,
			struct wsp_cbasestoragevariant *value, bool quote)
{
	const char* result = NULL;
	switch(value->vtype) {
		case VT_I4:
		case VT_UI4:
		case VT_INT:
		case VT_UINT:
		case VT_I2:
		case VT_UI2:
			result = talloc_asprintf(ctx, "%d",
						 value->vvalue.vt_i4);
			break;
		case VT_I8:
		case VT_UI8:
		case VT_R8:
		case VT_CY:
		case VT_DATE:
		case VT_FILETIME: {
			uint64_t val;
			wsp_hyper_to_uint64(&value->vvalue.vt_ui8, &val);
			result = talloc_asprintf(ctx, "%" PRId64,
						 val);
			break;
		}
		case VT_LPWSTR:
			result = talloc_asprintf(ctx, "%s%s%s",
						quote ? "\'" : "",
						value->vvalue.vt_lpwstr.value,
						quote ? "\'" : "");
			break;
		case VT_LPWSTR | VT_VECTOR: {
			int num_elems =
			value->vvalue.vt_lpwstr_v.vvector_elements;
			int i;
			for(i = 0; i < num_elems; i++) {
				struct vt_lpwstr_vec *vec;
				const char *val;
				vec = &value->vvalue.vt_lpwstr_v;
				val = vec->vvector_data[i].value;
				result =
					talloc_asprintf(ctx,
							"%s%s%s%s%s",
							result ? result : "",
							i ? "," : "",
							quote ? "\'" : "",
							val,
							quote ? "\'" : "");
			}
			break;
		}
		default:
			DBG_INFO("#FIXME unsupported type 0x%x\n",
				value->vtype);
			break;
	}
	return result;
}

static NTSTATUS restriction_node_to_string(TALLOC_CTX *ctx,
			 struct wsp_crestriction *restriction,
			 const char **str_result)
{
	const char *result = NULL;
	struct wsp_cfullpropspec *full_prop = get_full_prop(restriction);
	const char *op_str = op_as_string(restriction);
	const char *propname = NULL;
	const char *value = NULL;
	NTSTATUS status = NT_STATUS_OK;
	if (is_operator(restriction)) {
		result = talloc_strdup(ctx, op_str);
		goto out;
	}

	if (restriction->ultype == RTPROPERTY
	|| restriction->ultype == RTCONTENT
	|| restriction->ultype == RTNATLANGUAGE) {
		if (full_prop) {
			propname = prop_from_fullprop(ctx, full_prop);
		}
		if (propname == NULL) {
			DBG_ERR("Unknown propname\n");
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
	}
	if (op_str == NULL) {
		DBG_WARNING("Unknow operation for prop %s\n", propname);
	}
	switch(restriction->ultype) {
		case RTCONTENT: {
			struct wsp_ccontentrestriction *content = NULL;
			content =
				&restriction->restriction.ccontentrestriction;
			value = talloc_strdup(ctx, content->pwcsphrase);
			result = talloc_asprintf(ctx, "RTCONTENT %s %s %s", propname, op_str, value);
			break;
		}
		case RTPROPERTY: {
			struct wsp_cpropertyrestriction *prop =
				&restriction->restriction.cpropertyrestriction;
			struct wsp_cbasestoragevariant *variant = &prop->prval;
			value = variant_as_string(ctx, variant, true);
			result = talloc_asprintf(ctx, "RTPROPERTY %s %s %s", propname, op_str, value);
			break;
		}
		case RTNATLANGUAGE: {
			struct wsp_cnatlanguagerestriction *cnat =
				&restriction->restriction.cnatlanguagerestriction;
			result = talloc_asprintf(ctx,
						"RTNATLANGUAGE %s %s %s",
						propname,
						op_str,
						cnat->pwcsphrase);

			break;
		}
		case RTCOERCE_ABSOLUTE: {
			struct wsp_crestriction *child_restrict =
				restriction->restriction.ccoercionrestriction_abs.childres;
			result = raw_restriction_to_string(ctx, child_restrict);
			if (!result) {
				status = NT_STATUS_UNSUCCESSFUL;
			}
			break;
		}
		case RTREUSEWHERE: {
			uint32_t id =
				restriction->restriction.reusewhere.whereid;
			result = talloc_asprintf(ctx,
					"insert expression for WHEREID = %d",
					id);

			break;
		}
		default:
			DBG_ERR("## unknown type 0x%x\n", restriction->ultype);
			status = NT_STATUS_INVALID_PARAMETER;
			break;
	}
out:
	*str_result = result;
	return status;
}

static NTSTATUS infix_restriction(TALLOC_CTX *ctx,
			 struct wsp_crestriction *restriction,
			 const char **str_result)
{
	const char *tmp = *str_result;
	const char *token = NULL;
	struct wsp_crestriction *left = NULL;
	struct wsp_crestriction *right = NULL;
	NTSTATUS status;
	if (!restriction) {
		status = NT_STATUS_OK;
		goto out;
	}
	if (is_operator(restriction)) {
		if (restriction->ultype == RTAND
		|| restriction->ultype == RTOR) {
			struct wsp_cnoderestriction *cnodes =
				&restriction->restriction.cnoderestriction;
			if (cnodes->cnode) {
				left = &cnodes->panode[0];
				if (cnodes->cnode > 1) {
					right = &cnodes->panode[1];
				}
			}
		} else {
			right = restriction->restriction.restriction.restriction;
		}
		tmp = talloc_asprintf(ctx, "%s(", tmp ? tmp : "");
	}
	status = infix_restriction(ctx, left, &tmp);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = restriction_node_to_string(ctx, restriction, &token);

	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}
	tmp = talloc_asprintf(ctx, "%s%s", tmp ? tmp : "", token);

	status = infix_restriction(ctx, right, &tmp);

	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	if (is_operator(restriction)) {
		tmp = talloc_asprintf(ctx, "%s)",tmp);
	}
	*str_result = tmp;
out:
	return status;
}

const char *raw_restriction_to_string(TALLOC_CTX *ctx,
				  struct wsp_crestriction *restriction)
{
	const char *result = NULL;
	infix_restriction(ctx, restriction, &result);
	return result;
}
