#pragma once

#include <sstream>
#include <vector>

inline std::string str(uint64_t &a)
{
	std::stringstream ss;
	ss << a;
	return ss.str();
}

inline std::string str(int64_t &a)
{
	std::stringstream ss;
	ss << a;
	return ss.str();
}

inline std::string str(int32_t &a)
{
	std::stringstream ss;
	ss << a;
	return ss.str();
}

inline std::string str(__int128 unsigned &a)
{
	std::stringstream ss;
	ss << (uint64_t)a;
	return ss.str();
}

inline std::string hex(uint64_t &a)
{
	std::stringstream ss;
	ss << "0x" << std::hex << a;
	return ss.str();
}

inline std::string hex(int64_t &a)
{
	std::stringstream ss;
	ss << "0x" << std::hex << a;
	return ss.str();
}

inline std::string hex(int32_t &a)
{
	std::stringstream ss;
	ss << "0x" << std::hex << a;
	return ss.str();
}

inline std::string hex(__int128 unsigned &a)
{
	std::stringstream ss;
	ss << "0x" << std::hex << (uint64_t)a;
	return ss.str();
}

inline std::vector<std::string> Split(const std::string& str, char comma, size_t split_cnt) {
    std::stringstream ss(str);
    std::string str_piece; 
    std::vector<std::string> result;
    for (; split_cnt > 0 && getline(ss, str_piece, comma); --split_cnt) 
        result.push_back(str_piece);

    if (split_cnt == 0) {
        getline(ss, str_piece);
        result.push_back(str_piece);
    }

    return result; 
}