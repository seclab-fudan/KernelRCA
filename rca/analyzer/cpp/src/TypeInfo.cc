#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <dwarf.h>
#include <libdwarf.h>
#include <libelf.h>

#include <map>

#include <typeinfo.h>
#include <dwarf_error.h>

#define TRUE 1
#define FALSE 0

struct LocalRecord {
	/* hipc is the key of map */
	Dwarf_Addr lowpc;
	Dwarf_Off die_off;
};

/* 
 * map: hipc -> LocalRecord
 * Suppose that for each op, the loc ranges are not overlap
 * So we can use lower_bound to find the target die rapidly
 */
typedef std::map<Dwarf_Addr, struct LocalRecord> LocalRecordMap;

/* arr: op -> LocalRecordMap */
LocalRecordMap localrecord_map[DW_OP_hi_user];

struct GlobalRecord {
	Dwarf_Off die_off;
};

/* map: global addr -> GlobalRecord */
typedef std::map<Dwarf_Unsigned, struct GlobalRecord> GlobalRecordMap;

GlobalRecordMap globalrecord_map;

static void get_die_off_by_op_ip(Dwarf_Small op, Dwarf_Addr ip, Dwarf_Off *die_offset_out)
{
	LocalRecordMap::iterator it = localrecord_map[op].lower_bound(ip);

	*die_offset_out = 0;

	if (it == localrecord_map[op].end()) {
		return;
	}

	struct LocalRecord rec = it->second;
	Dwarf_Addr lowpc = rec.lowpc;
	// printf("MADOKA: %llx %llx %llx\n", lowpc, it->first, rec.die_off);
	
	if (lowpc <= ip)
	{
		*die_offset_out = rec.die_off;
	}
}

/* Type Lattice */
struct TypeLatticeNode {
	std::string name;
	struct TypeLatticeNode* child;
	int depth;
};

typedef std::map<std::string, struct TypeLatticeNode*> TypeLattice;

TypeLattice lattice;

void type_lattice_insert(const char *struct_type, const char *member_type)
{
	struct TypeLatticeNode *member = NULL;
	// printf("%s->%s\n", struct_type, member_type);
	std::string member_type_name = std::string(member_type);
	auto it_member = lattice.find(member_type_name);
	if (it_member == lattice.end()) {
		member = new TypeLatticeNode();
		member->name = member_type_name;
		member->child = NULL;
		member->depth = 0;
		lattice[member_type_name] = member;
	}
	else {
		member = it_member->second;
	}

	struct TypeLatticeNode *structure = NULL;
	std::string struct_type_name = std::string(struct_type);
	auto it_struct = lattice.find(struct_type_name);
	if (it_struct == lattice.end()) {
		structure = new TypeLatticeNode();
		structure->name = struct_type_name;
		structure->depth = 1;
		lattice[struct_type_name] = structure;
	}
	else {
		structure = it_struct->second;
	}

	structure->child = member;

	/* update depth */
	while (structure->child) {
		if (structure->child->depth >= structure->depth + 1)
			break;
		structure->child->depth = structure->depth + 1;
		structure = structure->child;
	}
}

/* check if typeA and typeB can covert to each other */
bool type_lattice_check_convert(std::string& typeA, std::string& typeB)
{
	auto itA = lattice.find(typeA);
	if (itA == lattice.end())
		return false;

	auto itB = lattice.find(typeB);
	if (itB == lattice.end())
		return false;

	struct TypeLatticeNode *nodeA = itA->second;
	struct TypeLatticeNode *nodeB = itB->second;

	if (nodeA->depth > nodeB->depth) {
		TypeLatticeNode *tmp = nodeA;
		nodeA = nodeB;
		nodeB = tmp;
	}

	while (nodeA != NULL) {
		if (nodeA == nodeB)
			return true;
		nodeA = nodeA->child;
	}
	return false;
}

/*
static void get_die_off_by_addr(Dwarf_Unsigned addr, Dwarf_Off *die_offset_out)
{
	GlobalRecordMap::iterator it = globalrecord_map.find(addr);

	*die_offset_out = 0;

	if (it == globalrecord_map.end()) {
		return;
	}

	GlobalRecord rec = it->second;
	*die_offset_out = rec.die_off;
}
*/

static void get_type_dieoff_and_name_recursive(Dwarf_Debug dbg, Dwarf_Off var_off, Dwarf_Off *type_die_off_out, char *type_name_out)
{
	int ret = DW_DLV_ERROR;
	Dwarf_Error error;

	Dwarf_Die var_die;
	Dwarf_Bool has_type = FALSE;
	Dwarf_Die type_die = 0;
	Dwarf_Off type_off = 0;

	Dwarf_Bool done = FALSE;

	/* get the first type node of the provided variable die */

	ret = dwarf_offdie_b(dbg, var_off, TRUE, &var_die, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_offdie_b 11 %llx\n", var_off);
		exit(1);
	}

	ret = dwarf_hasattr(var_die, DW_AT_type, &has_type, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_hasattr\n");
		exit(1);
	}

	if (!has_type) {
		strcpy(type_name_out, "<invalid>");
		goto finish;
	}

	ret = dwarf_dietype_offset(var_die, &type_off, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_dietype_offset\n");
		exit(1);
	}

	/* compose the type name recursively from the first type_die */
	while (!done) {
		// printf("off %lx\n", type_off);

		ret = dwarf_offdie_b(dbg, type_off, TRUE, &type_die, &error);
		if (ret == DW_DLV_ERROR) {
			warnx("Error in dwarf_offdie_b 1\n");
			exit(1);
		}

		/* get name from type_die */
		Dwarf_Bool has_name = TRUE;
		ret = dwarf_hasattr(type_die, DW_AT_name, &has_name, &error);
		if (ret == DW_DLV_ERROR) {
			warnx("Error in dwarf_has_attr\n");
			exit(1);
		}

		if (has_name) {
			/* we reach the target */
			char *name = 0;
			ret = dwarf_diename(type_die, &name, &error);
			if (ret == DW_DLV_ERROR) {
				warnx("Error in dwarf_diename:%s\n", dwarf_errmsg(error));
				exit(1);
			}

			strcat(type_name_out, name);
			done = TRUE;
		}
		else {
			Dwarf_Half tag = 0;
			ret = dwarf_tag(type_die, &tag, &error);
			if (ret == DW_DLV_ERROR) {
				warnx("Error in dwarf_tag: %s\n", dwarf_errmsg(error));
				exit(1);
			}

			/* a non-leaf type die, might be a pointer, union, etc. */
			if (tag == DW_TAG_pointer_type) {
				strcat(type_name_out, "*");
				strcat(type_name_out, " ");
			}
			else if (tag == DW_TAG_union_type) {
				strcat(type_name_out, "<union>");
				done = TRUE;
			}

			/* find next-level type_die's offset */
			ret = dwarf_hasattr(type_die, DW_AT_type, &has_type, &error);
			if (ret == DW_DLV_ERROR) {
				warnx("Error in dwarf_hasattr\n");
				exit(1);
			}
			if (has_type) {
				ret = dwarf_dietype_offset(type_die, &type_off, &error);
				if (ret == DW_DLV_ERROR) {
					warnx("Error in dwarf_dietype_offset\n");
					exit(1);
				}
			}
			else {
				done = TRUE;
			}
		}

		dwarf_dealloc(dbg, type_die, DW_DLA_DIE);
	}

finish:
	dwarf_dealloc(dbg, var_die, DW_DLA_DIE);
	*type_die_off_out = type_off;
}

static void get_typedie_and_name_by_dieoff(Dwarf_Debug dbg, Dwarf_Off die_off, Dwarf_Off *type_die_off_out, char **name_out)
{
	*name_out = (char *)malloc(100); /* may overflow if the name is too long */
	memset(*name_out, 0, 100);
	get_type_dieoff_and_name_recursive(dbg, die_off, type_die_off_out, *name_out);
}

static void get_memberdie_by_typedie_and_offset(Dwarf_Debug dbg, Dwarf_Off struct_die_off, Dwarf_Unsigned member_off, Dwarf_Off *member_die_off_out)
{
	int ret = DW_DLV_ERROR;
	Dwarf_Error error;
	Dwarf_Bool is_info = TRUE;
	Dwarf_Die die = NULL;
	Dwarf_Die child = NULL;

	ret = dwarf_offdie_b(dbg, struct_die_off, is_info, &die, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_offdie_b 3\n");
		exit(1);
	}

	ret = dwarf_child(die, &child, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_child\n");
		exit(1);
	}
	dwarf_dealloc(dbg, die, DW_DLA_DIE);

	*member_die_off_out = 0;
	while (child)
	{
		Dwarf_Half tag = 0;
		ret = dwarf_tag(child, &tag, &error);
		if (ret == DW_DLV_ERROR) {
			warnx("Error in dwarf_tag: %s\n", dwarf_errmsg(error));
			exit(1);
		}

		if (tag != DW_TAG_member) {
			/* 
			 * 按理来说，struct的child都是member
			 * 不会出现非member的情况
			 * 一旦出现直接报错
			 * */
			warnx("Error child of struct is not member\n");
			exit(1);
		}

		Dwarf_Attribute attr;
		ret = dwarf_attr(child, DW_AT_data_member_location, &attr, &error);
		if (ret == DW_DLV_ERROR) {
			warnx("Error in dwarf_attr\n");
			exit(1);
		}

		if (ret == DW_DLV_OK) {
			Dwarf_Unsigned off;
			ret = dwarf_formudata(attr, &off, &error);
			if (ret == DW_DLV_ERROR) {
				warnx("Error in dwarf_formudata\n");
				exit(1);
			}

			if (off == member_off)
			{
				/*
				char *member_name = 0;
				ret = dwarf_diename(child, &member_name, &error);
				if (ret == DW_DLV_ERROR) {
					warnx("Error in dwarf_diename\n");
					exit(1);
				}
				if (member_name) {
					*name_out = (char *)malloc(strlen(member_name) + 1);
					(*name_out)[strlen(member_name)] = 0;
					strncpy(*name_out, member_name, strlen(member_name));
				}
				else{
					const char *unk_name = "<unknown>";
					*name_out = (char *)malloc(strlen(unk_name) + 1);
					(*name_out)[strlen(unk_name)] = 0;
					strncpy(*name_out, unk_name, strlen(unk_name));
				}
				*/
			
				ret = dwarf_dieoffset(child, member_die_off_out, &error);
				if (ret == DW_DLV_ERROR) {
					warnx("Error in dwarf_dieoffset\n");
					exit(1);
				}

				dwarf_dealloc(dbg, child, DW_DLA_DIE);
				return;
			}
		}

		Dwarf_Die next = 0;
		ret = dwarf_siblingof_b(dbg, child, is_info, &next, &error);
		if (ret == DW_DLV_ERROR) {
			warnx("Error in dwarf_siblingof_b\n");
			exit(1);
		}

		dwarf_dealloc(dbg, child, DW_DLA_DIE);
		child = next;

		if (ret == DW_DLV_NO_ENTRY) {
			/* we reach the end, but not found */
			*member_die_off_out = 0;
			return;
		}
	}
}

/*
 * take DW_TAG_variable or DW_TAG_formal_parameter die as input
 * output the original definition of this variable or parameter
 * to be specific, the definition should contains a DW_AT_type field
 */

static void get_ref_source(Dwarf_Debug dbg, Dwarf_Die in_die, Dwarf_Die *out_die)
{
	int ret = DW_DLV_ERROR;
	Dwarf_Error error = 0;

	Dwarf_Attribute attr = 0;

	ret = dwarf_attr(in_die, DW_AT_specification, &attr, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_attr\n");
		exit(1);
	}

	if (ret == DW_DLV_NO_ENTRY || attr == 0) {
		ret = dwarf_attr(in_die, DW_AT_abstract_origin, &attr, &error);
		if (ret == DW_DLV_ERROR) {
			warnx("Error in dwarf_attr\n");
			exit(1);
		}
	}

	/* This die has no source */
	if (ret == DW_DLV_NO_ENTRY || attr == 0) {
		*out_die = 0;
		return;
	}

	Dwarf_Off source_off;
	Dwarf_Bool is_info = TRUE;

	ret = dwarf_global_formref_b(attr, &source_off, &is_info, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_global_formref_b\n");
		exit(1);
	}

	ret = dwarf_offdie_b(dbg, source_off, is_info, out_die, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_offdie_b 4\n");
		exit(1);
	}
}

static void find_definition_die(Dwarf_Debug dbg, Dwarf_Die in_die, Dwarf_Die *out_die)
{
	int ret = DW_DLV_ERROR;
	Dwarf_Error error = 0;
	Dwarf_Die tmp_die = in_die;

	do {
		Dwarf_Bool has_type;
		ret = dwarf_hasattr(tmp_die, DW_AT_type, &has_type, &error);
		if (ret == DW_DLV_ERROR) {
			warnx("Error in dwarf_hasattr\n");
			exit(1);
		}

		/* we find a die contains DW_AT_type */
		if (has_type) {
			*out_die = tmp_die;
			return;
		}

		get_ref_source(dbg, tmp_die, out_die);
		if (tmp_die != in_die) {
			dwarf_dealloc(dbg, tmp_die, DW_DLA_DIE);
		}
		tmp_die = *out_die;
	} while (tmp_die != NULL);
}

/*
 * die with DW_TAG_structure_type
 * in kernel, the data type can be converted
 * when the first member of a structure is also a full structure
 * e.g. struct A { struct B; int c;};
 * Then,
 *   A *a = (A*)malloc(sizeof(A));
 *   B *b = (B*)a;
 * is valid to implement the inheritance in non-object-oriented language like C.
 * So we need a type lattice to recognize such 'inheritance' relationship.
 */
static void try_insert_type_lattice(Dwarf_Debug dbg, Dwarf_Die type_die)
{
	/* type_die is a die with DW_TAG_structure_type */
	int ret = DW_DLV_ERROR;
	Dwarf_Error error;
	Dwarf_Bool is_info = TRUE;
	Dwarf_Die first_member_die = NULL;
	Dwarf_Attribute attr;

	Dwarf_Bool has_type = FALSE;
	Dwarf_Off member_type_off = 0;
	Dwarf_Die member_type_die = 0;
	char *struct_type_name = 0;
	char *member_type_name = 0;

	ret = dwarf_child(type_die, &first_member_die, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_child\n");
		exit(1);
	}

	if (!first_member_die) {
		/* we cannot find the first member of a struct */
		return;
	}

	Dwarf_Half tag = 0;
	ret = dwarf_tag(first_member_die, &tag, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_tag: %s\n", dwarf_errmsg(error));
		exit(1);
	}

	if (tag != DW_TAG_member) {
		warnx("Error child of struct is not member\n");
		exit(1);
	}

	ret = dwarf_attr(first_member_die, DW_AT_data_member_location, &attr, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_attr\n");
		exit(1);
	}

	if (ret == DW_DLV_OK) {
		Dwarf_Unsigned off;
		ret = dwarf_formudata(attr, &off, &error);
		if (ret == DW_DLV_ERROR) {
			warnx("Error in dwarf_formudata\n");
			exit(1);
		}

		if (off != 0)
			goto out_first_member_die;
		/* we have found the first member */
	}

	/* parse the type of the first member */
	ret = dwarf_hasattr(first_member_die, DW_AT_type, &has_type, &error);
	if (ret == DW_DLV_ERROR || !has_type) {
		warnx("Cannot read the type of the first member in struct\n");
		exit(1);
	}

	ret = dwarf_dietype_offset(first_member_die, &member_type_off, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_dietype_offset\n");
		exit(1);
	}

	ret = dwarf_offdie_b(dbg, member_type_off, TRUE, &member_type_die, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in find dieoff of member_type_off\n");
		exit(1);
	}

	/* if the type of first member is another struct, they can convert */
	ret = dwarf_tag(member_type_die, &tag, &error);
    if (ret == DW_DLV_ERROR) {
        warnx("Error in dwarf_tag: %s\n", dwarf_errmsg(error));
        exit(1);
    }

	if (tag != DW_TAG_structure_type)
		goto out_member_type_die;

	/* get the name of the member struct */
	ret = dwarf_diename(member_type_die, &member_type_name, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in get first member type name\n");
		exit(1);
	}

	/* get the name of current struct */
	ret = dwarf_diename(type_die, &struct_type_name, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in get struct type name\n");
		exit(1);
	}

	/* insert into typelattice */
	if (struct_type_name != NULL && member_type_name != NULL) {
		/* we just ignore anonymous struct currently,
		 * like struct mm_struct { struct {int a}; int b};
		 */
		type_lattice_insert(struct_type_name, member_type_name);
	}

out_member_type_die:
	dwarf_dealloc(dbg, member_type_die, DW_DLA_DIE);
out_first_member_die:
	dwarf_dealloc(dbg, first_member_die, DW_DLA_DIE);
	return;
}

/*
 * scan all die in .debug_info
 * to find out global/local variable information
 * and fill in necessary global data structure
 */
static void scan_die(Dwarf_Debug dbg, Dwarf_Die die)
{
	int ret = DW_DLV_ERROR;
	Dwarf_Error error = 0;

	/* for dwarf_tag */
	Dwarf_Half tag = 0;

	/* for dwarf_attr */
	Dwarf_Attribute location_attr = 0;

	/* for dwarf_get_loclist_c */
	Dwarf_Loc_Head_c loclist_head = 0;
	Dwarf_Unsigned locentry_count = 0;
	/* for dwarf_get_loclist_head_kind */
	unsigned int lkind = DW_LKIND_unknown;

	/* for dwarf_dieoffset */
	Dwarf_Off die_offset = 0;

	/* for find_definition_die */
	Dwarf_Die def_die;

	/* for dwarf_get_locdesc_entry_d */
	Dwarf_Small lle_value_out = 0;
	Dwarf_Unsigned rawlopc = 0;
	Dwarf_Unsigned rawhipc = 0;
	Dwarf_Bool debug_addr_unavailable = FALSE;
	Dwarf_Addr lowpc_cooked = 0;
	Dwarf_Addr hipc_cooked = 0;
	Dwarf_Unsigned locexpr_op_count = 0;
	Dwarf_Locdesc_c locentry = 0;
	Dwarf_Small loclist_source = 0;
	Dwarf_Unsigned expression_offset = 0;
	Dwarf_Unsigned locdesc_offset = 0;

	/* for dwarf_get_location_op_value_c */
	Dwarf_Small op = 0;
	Dwarf_Unsigned operand1 = 0;
	Dwarf_Unsigned operand2 = 0;
	Dwarf_Unsigned operand3 = 0;
	Dwarf_Unsigned offset_for_branch = 0;

	/* struct LocalRecord to be inserted into global map */
	struct LocalRecord lrec;
	struct GlobalRecord grec;

	int i = 0;

	/*
	 * 首先检查是不是DW_TAG_variable或DW_TAG_formal_parameter
	 * 然后检查是否有DW_AT_location
	 * 两点都满足后
	 * 沿着DW_AT_specification或者DW_AT_abstract_origin回溯
	 * 直到遇到一个die，具有DW_AT_type为止
	 * 只有记录了DW_AT_type的才是可以分析出数据类型的die
	 * 否则这些variable和formal_parameter节点都只是中间节点
	 */

	ret = dwarf_tag(die, &tag, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_tag\n");	
		exit(1);
	}

	/* tag is DW_TAG_structure_type, just build type lattice and return */
	if (tag == DW_TAG_structure_type) {
		try_insert_type_lattice(dbg, die);
		return;
	}

	/* tag is not in [DW_TAG_variable, DW_TAG_formal_parameter], just return */
	if (tag != DW_TAG_variable && tag != DW_TAG_formal_parameter) {
		return;
	}

	ret = dwarf_attr(die, DW_AT_location, &location_attr, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_attr\n");
		exit(1);
	}
	/* no DW_AT_location, just return */
	if (ret == DW_DLV_NO_ENTRY) {
		return;
	}

	/* get location related information */
	ret = dwarf_get_loclist_c(location_attr, &loclist_head, &locentry_count, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("%s", static_cast<const char*>(error->er_msg));
		warnx("Error in dwarf_get_loclist_c\n");
		exit(1);
	}

	ret = dwarf_get_loclist_head_kind(loclist_head, &lkind, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_get_loclist_head_kind\n");
		exit(1);
	}

	/* find the definition source */
	find_definition_die(dbg, die, &def_die);
	if (def_die == NULL) {
		/* the definition is not a type define */
		warnx("Error source not type die\n");
		exit(1);
	}

	/*
	 * 得到die的offset，记入全局数据结构，可以按需分析
	 * 从die中可以得到type_die，一直回溯可以得到struct_die，进而计算出member
	 * 对局部变量，全局数据结构存 map[op][hipc] = {lowpc, die_offset}
	 * 一直迭代type_die即可找出最终的struct_die
	 * 对全局变量，全局数据结构存 map[op][addr] = {die_offset}
	 */
	ret = dwarf_dieoffset(def_die, &die_offset, &error);
	if (ret == DW_DLV_ERROR) {
		warnx("Error in dwarf_dieoffset\n");
		exit(1);
	}

	/* 
	 * 这里需要区分两种情况
	 * 一种是单个expression，从这里可以找到全局变量
	 * 一种是loclist，用于定位有生命周期的变量的生命周期范围
	 */
	if (lkind == DW_LKIND_expression) {
		/* 
		 * 这里只考虑单个expression是addr的情况
		 * 其实这里的expression还可以代表相对fbreg的偏移，参数所在寄存器(rsi, rdi)等
		 * 暂时先不考虑了，只考虑全局变量
		 * 单个expression的情况下，locentry_count永远等于1
		 */
		for (i = 0; i < locentry_count; i ++) {
			ret = dwarf_get_locdesc_entry_d(loclist_head, i,
					&lle_value_out, &rawlopc, &rawhipc,
					&debug_addr_unavailable, &lowpc_cooked, &hipc_cooked,
					&locexpr_op_count, &locentry, &loclist_source,
					&expression_offset, &locdesc_offset, &error);
			if (ret == DW_DLV_ERROR) {
				warnx("Error in dwarf_get_locdesc_entry_d\n");
				exit(1);
			}

			ret = dwarf_get_location_op_value_c(locentry, 0,
					&op, &operand1, &operand2, &operand3,
					&offset_for_branch, &error);
			if (ret == DW_DLV_ERROR) {
				warnx("Error in dwarf_get_location_op_value_c\n");
				exit(1);
			}

			if (op == DW_OP_addr) {
				grec.die_off = die_offset;
				globalrecord_map[operand1] = grec;
			}

			dwarf_dealloc(dbg, locentry, DW_DLA_LOCDESC_C);
		}
	}
	else if (lkind == DW_LKIND_loclist) {	
		for (i = 0; i < locentry_count; i ++) {
			ret = dwarf_get_locdesc_entry_d(loclist_head, i,
					&lle_value_out, &rawlopc, &rawhipc,
					&debug_addr_unavailable, &lowpc_cooked, &hipc_cooked,
					&locexpr_op_count, &locentry, &loclist_source,
					&expression_offset, &locdesc_offset, &error);
			if (ret == DW_DLV_ERROR) {
				warnx("Error in dwarf_get_locdesc_entry_d\n");
				exit(1);
			}

			if (locexpr_op_count == 1) {
				ret = dwarf_get_location_op_value_c(locentry, 0,
						&op, &operand1, &operand2, &operand3,
						&offset_for_branch, &error);
				if (ret == DW_DLV_ERROR) {
					warnx("Error in dwarf_get_location_op_value_c\n");
					exit(1);
				}

				lrec.lowpc = lowpc_cooked;
				lrec.die_off = die_offset;
				localrecord_map[op][hipc_cooked] = lrec;
			}

			//if (lowpc_cooked <= 0xffffffff81873ee7LL && 0xffffffff81873ee7 <= hipc_cooked)
			//	printf("MADOKA: %llx, %llx, %x\n", lowpc_cooked, hipc_cooked, op);

			dwarf_dealloc(dbg, locentry, DW_DLA_LOCDESC_C);
		}
	}

	dwarf_dealloc(dbg, loclist_head, DW_DLA_LOC_HEAD_C);
	dwarf_dealloc(dbg, location_attr, DW_DLA_ATTR);
	return;
}

static void get_die_and_siblings(Dwarf_Debug dbg, Dwarf_Die in_die,
		Dwarf_Bool is_info, int level)
{
	int ret = DW_DLV_ERROR;
	Dwarf_Die cur_die = in_die;
	Dwarf_Die child = 0;
	Dwarf_Error error = 0;

	scan_die(dbg, cur_die);

	for (;;) {
		Dwarf_Die sib_die = 0;
		ret = dwarf_child(cur_die, &child, &error);

		if (ret == DW_DLV_ERROR) {
			warnx("Error in dwarf_child, level %d\n", level);
			exit(1);
		}
		if (ret == DW_DLV_OK) {
			get_die_and_siblings(dbg, child, is_info, level + 1);
			dwarf_dealloc(dbg, child, DW_DLA_DIE);
			child = 0;
		}

		/* ret == DW_DLV_OK or DW_DLV_NO_ENTRY, process this DIE */
		ret = dwarf_siblingof_b(dbg, cur_die, is_info, &sib_die, &error);
		if (ret == DW_DLV_ERROR) {
			warnx("Error in dwarf_siblingof_b, level %d: %s\n", level, dwarf_errmsg(error));
			exit(1);
		}
		if (ret == DW_DLV_NO_ENTRY) {
			break;
		}
		if (cur_die != in_die) {
			dwarf_dealloc(dbg, cur_die, DW_DLA_DIE);
			cur_die = 0;
		}
		cur_die = sib_die;

		scan_die(dbg, cur_die);
	}
}

static void read_cu_list(Dwarf_Debug dbg)
{
	Dwarf_Bool is_info = TRUE;
	Dwarf_Unsigned cu_header_length = 0;
	Dwarf_Half version_stamp = 0;
	Dwarf_Off abbrev_offset = 0;
	Dwarf_Half address_size = 0;
	Dwarf_Half offset_size = 0;
	Dwarf_Half extension_size = 0;
	Dwarf_Sig8 type_signature;
	Dwarf_Unsigned typeoffset;
	Dwarf_Unsigned next_cu_header_offset;
	Dwarf_Half header_cu_type;
	Dwarf_Error error;

	int ret = DW_DLV_ERROR;
	int cu_number = 0;

	for (;;cu_number ++) {
		Dwarf_Die no_die = 0;
		Dwarf_Die cu_die = 0;

		ret = dwarf_next_cu_header_d(dbg, is_info, &cu_header_length,
				&version_stamp, &abbrev_offset, &address_size,
				&offset_size, &extension_size, &type_signature,
				&typeoffset, &next_cu_header_offset, &header_cu_type,
				&error);
		if (ret == DW_DLV_ERROR) {
			warnx("dwarf_next_cu_header_d error: %s\n", dwarf_errmsg(error));
			exit(1);
		}
		else if (ret == DW_DLV_NO_ENTRY) {
			return;
		}

		ret = dwarf_siblingof_b(dbg, no_die, is_info, &cu_die, &error);
		if (ret == DW_DLV_ERROR) {
			warnx("dwarf_siblingof_b error: %s\n", dwarf_errmsg(error));
			exit(1);
		}
		else if (ret == DW_DLV_NO_ENTRY) {
			warnx("dwarf_siblingof_b no entry!\n");
			exit(1);
		}

		get_die_and_siblings(dbg, cu_die, is_info, 0);

		dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
	}
}

Dwarf_Debug dbg = 0;
int fd = 0;

void init(const char *binpath)
{
	int ret = DW_DLV_ERROR;
	Dwarf_Error error;
	Dwarf_Handler errhand = NULL;
	Dwarf_Ptr errarg = NULL;

	if (dbg || fd) {
		warnx("do not re-init dwarf_accel\n");
		return;
	}

	fd = open(binpath, O_RDONLY);
	if (fd <= 0) {
		warnx("open vmlinux failed!\n");
		return;
	}

	ret = dwarf_init_b(fd, DW_GROUPNUMBER_ANY, errhand, errarg, &dbg, &error);
	if (ret != DW_DLV_OK) {
		warnx("init dwarf fail!\n");
		if (fd) {
			close(fd);
			fd = 0;
		}
		return;
	}

	read_cu_list(dbg);
	return;
}

void exit(void)
{
	int ret = dwarf_finish(dbg);
	if (ret != DW_DLV_OK) {
		warnx("dwarf_finish failed!\n");
	}

	if (fd) {
		close(fd);
		fd = 0;
	}
}

void retrive_by_ip_reg(Dwarf_Addr ip, Dwarf_Small op /* reg */, char **type_name)
{
	Dwarf_Off die_off;
	Dwarf_Off type_die_off;

	/* 首先，查找loclist包含ip的，op能对上的die，这个就是局部变量或参数 */
	get_die_off_by_op_ip(op, ip, &die_off);
	if (die_off == 0) {
		*type_name = NULL;
		return;
	}

	/* 之后，从变量die找到其根类型die，并得到type名 */
	get_typedie_and_name_by_dieoff(dbg, die_off, &type_die_off, type_name);
}

void retrive_by_ip_reg_disp(Dwarf_Addr ip, Dwarf_Small op /* reg */, Dwarf_Unsigned disp, char **type_name)
{
	Dwarf_Off die_off;
	Dwarf_Off type_die_off;
	Dwarf_Off member_die_off;

	/* 首先，查找loclist包含ip的，op能对上的die，这个就是局部变量或参数 */
	get_die_off_by_op_ip(op, ip, &die_off);
	if (die_off == 0) {
		*type_name = NULL;
		return;
	}
	/* 之后，从变量die找到其类型die，并得到type名 */
	get_typedie_and_name_by_dieoff(dbg, die_off, &type_die_off, type_name);
	free(*type_name); /* base type is not needed */
	/* 之后，从其根类型die找到offset=disp的member die，即可知道变量是struct中的何种member */
	get_memberdie_by_typedie_and_offset(dbg, type_die_off, disp, &member_die_off);
	if (member_die_off == 0) {
		*type_name = NULL;
		return;
	}
	/* 最后，从member die找到其根类型die，并得到type名 */
	get_typedie_and_name_by_dieoff(dbg, member_die_off, &type_die_off, type_name);
}

/*
void retrive_by_addr(Dwarf_Unsigned addr, char **type_name, char **member_name)
{
	Dwarf_Off die_off;
	Dwarf_Off type_die_off;

	// 首先，查找location==addr的die，这个就是全局变量
	get_die_off_by_addr(addr, &die_off);
	if (die_off == 0) {
		*type_name = NULL;
		*member_name = NULL;
		return;
	}
	// 之后，从变量die找到其根类型die，并得到type名
	get_typedie_and_name_by_dieoff(dbg, die_off, &type_die_off, type_name);
	// 最后，从其根类型die找到offset=disp的member die，即可知道变量是struct中的何种member
	get_membername_by_typedie_and_offset(dbg, type_die_off, 0x0, member_name);
}
*/

static void free_str(char **str)
{
	if (*str) {
		free(*str);
		*str = NULL;
	}
}

/* cpp interfaces */

void typeinfo_init(const std::string& binpath)
{
	init(binpath.c_str());
}

void typeinfo_exit()
{
	exit();
}

std::string typeinfo_retrive_by_ip_reg(uint64_t ip, uint32_t op)
{
	char *type_name = 0;
	retrive_by_ip_reg(ip, op, &type_name);
	std::string ret;
	if (type_name == 0)
		ret = "";
	else
		ret.assign(type_name);
	free_str(&type_name);
	return ret;
}

std::string typeinfo_retrive_by_ip_reg_disp(uint64_t ip, uint32_t op, uint64_t disp)
{
	char *type_name = 0;
	retrive_by_ip_reg_disp(ip, op, disp, &type_name);
	std::string ret;
	if (type_name == 0)
		ret = "";
	else
		ret.assign(type_name);
	free_str(&type_name);
	return ret;
}

bool typeinfo_check_compatible(const std::string& typeA, const std::string& typeB)
{
	/* pointer level matching */
	int i;
	for (i = 0; i < std::min(typeA.size(), typeB.size()); i ++) {
		if (!(typeA[i] == typeB[i] && (typeA[i] == ' ' || typeA[i] == '*')))
			break;
	}
	std::string typeA_raw = typeA.substr(i);
	std::string typeB_raw = typeB.substr(i);
	return type_lattice_check_convert(typeA_raw, typeB_raw);
}
