#ifndef __TYPEINFO_H__
#define __TYPEINFO_H__

#include <string>

void typeinfo_init(const std::string& binpath);
void typeinfo_exit();
std::string typeinfo_retrive_by_ip_reg(uint64_t ip, uint32_t op);
std::string typeinfo_retrive_by_ip_reg_disp(uint64_t ip, uint32_t op, uint64_t disp);
bool typeinfo_check_compatible(const std::string& typeA, const std::string& typeB);

#endif
