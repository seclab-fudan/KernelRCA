#ifndef __ANALYZECONFIG_H__
#define __ANALYZECONFIG_H__

#include <string>
#include <fstream>
#include <filesystem>
namespace fs = std::filesystem;

#include "nlohmann/json.hpp"
using json = nlohmann::json;

class AnalyzeConfig
{
public:
	fs::path s2e_home;
	std::string crash_id;
	fs::path proj_home;

	uint64_t blamed_pc;
	std::string blamed_type;
	uint64_t blamed_loc;
	std::string blamed_seg_id;
	uint64_t fixup_offset;

	AnalyzeConfig(std::string path)
	{
		json j;
		std::ifstream(path) >> j;
		s2e_home = fs::path(j["s2e_home"]);
		crash_id = j["crash_id"];
		proj_home = s2e_home / "projects" / fs::path(crash_id);
		blamed_pc = j["blamed_pc"];
		blamed_type = j["blamed_type"];
		blamed_loc = j["blamed_loc"];
		blamed_seg_id = j["blamed_seg_id"];
		if (j.count("fixup_offset"))
			fixup_offset = j["fixup_offset"];
		else
			fixup_offset = 4;
	}
};

#endif /* __ANALYZECONFIG_H__ */
