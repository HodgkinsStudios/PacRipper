#pragma once
// Created by Jacob Hodgkins

#include <cstdint>
#include <map>
#include <string>

namespace pacripper {

struct UserSymbol {
    std::uint16_t address = 0;
    std::string name;
    std::string comment;
};

class SymbolDatabase {
public:
    bool load(const std::string& path, std::string& error);
    bool save(const std::string& path, std::string& error) const;
    bool set(std::uint16_t address, const std::string& name, const std::string& comment, std::string& error);
    void erase(std::uint16_t address);
    void clear();

    const UserSymbol* find(std::uint16_t address) const;
    const std::map<std::uint16_t, UserSymbol>& entries() const { return entries_; }
    const std::string& sourcePath() const { return sourcePath_; }

    static bool validIdentifier(const std::string& name);

private:
    std::map<std::uint16_t, UserSymbol> entries_;
    std::string sourcePath_;
};

} // namespace pacripper
