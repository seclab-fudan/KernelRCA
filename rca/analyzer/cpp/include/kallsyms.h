#ifndef __KALLSYMS_H__
#define __KALLSYMS_H__

#include <fstream>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <algorithm>


class Kallsyms
{
private:
	static bool cmp_sym(const std::pair<uint64_t, std::string> &a, const std::pair<uint64_t, std::string> &b)
	{
		return a.first > b.first;
	}
public:
	std::vector<std::pair<uint64_t, std::string>> syms;
	std::unordered_map<std::string, std::uint64_t> name_to_addr;
	std::unordered_map<std::string, std::vector<uint64_t>> name_to_addrs;
	std::unordered_map<std::uint64_t, std::string> addr_to_name;

	Kallsyms(std::string path)
	{
		std::fstream fs;
		std::string line;

		uint64_t addr;
		std::string type, name;

		fs.open(path, std::ios::in);
		while (fs)
		{
			std::getline(fs, line);
			line = "0x" + line;
			std::istringstream iss = std::istringstream(line);
			iss >> std::hex >> addr >> type >> name;

			size_t pos = name.find(".");
			if (pos != std::string::npos)
				name = name.substr(0, pos);

			name_to_addr[name] = addr;
			addr_to_name[addr] = name;
			syms.push_back(std::make_pair(addr, name));

			if (name_to_addrs.find(name) == name_to_addrs.end()) {
				name_to_addrs[name] = std::vector<uint64_t>();
			}
			name_to_addrs[name].push_back(addr);
		}

		std::sort(syms.begin(), syms.end(), cmp_sym);
		fs.close();
	}

	std::pair<std::string, uint64_t> get_name_by_addr(uint64_t addr)
	{
		auto it = std::lower_bound(syms.begin(), syms.end(), std::make_pair(addr, ""), cmp_sym);
		uint64_t offset = addr - it->first;
		return std::make_pair(it->second, offset);
	}
};

#endif /* __KALLSYMS_H__ */
