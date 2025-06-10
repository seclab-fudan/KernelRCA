#pragma once 
#include <cstdint>
#include <string> 
#include <sstream>
#include <vector>


class NoImplemntionException {
public:
    NoImplemntionException(const uint64_t& addr) {
        this->addr = addr; 
    }

    virtual std::string what() const {
        std::stringstream ss; 
        ss << "Instruction at " << std::hex << addr << " cannot be translated.";
        return ss.str();
    }
private:
    uint64_t addr;
};

class IndexOutOfBoundException {
public:
    IndexOutOfBoundException(const int& index, const int& size) {
        this->index = index;
        this->size = size; 
    }

    virtual std::string what() const {
        std::stringstream ss; 
        ss << "Index: " << index << " Size: " << size << "\n";
        return ss.str();
    }
private:
    int index, size; 
};

class LiftErrorException {
public:
    LiftErrorException(std::vector<uint8_t> bytes, const uint64_t& address) {
         this->bytes = std::move(bytes); 
         this->address = address; 
    }

    virtual std::string what() const {
        std::stringstream ss; 
        ss << "Instruction at " << std::hex << this->address << " cannot be lifted\n";
        ss << "Bytes: \n";
        for (auto& byte: bytes) {
            ss << std::hex << byte << " ";
        }
        ss << "\n";
        return ss.str();
    }
private:
    std::vector<uint8_t> bytes; 
    uint64_t address; 
}; 

class InconsistencyException {
public:
    InconsistencyException() {
    }

    virtual std::string what() const {
        std::stringstream ss; 
        ss << "VM Inconsistency!!!";
        return ss.str();
    }
private:
};