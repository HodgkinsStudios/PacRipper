#pragma once
// Created by Jacob Hodgkins

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace pacripper {

struct RomFile {
    std::string name;
    std::string sourcePath;
    std::vector<std::uint8_t> data;
    std::uint32_t crc32 = 0;
};


struct CanonicalRomDescriptor {
    std::string name;
    std::size_t size = 0;
    std::uint32_t crc32 = 0;
    std::string resourceClass;
    bool program = false;
};

enum class RomVariant {
    Unknown = 0,
    Pacman,
    Puckman
};

struct ValidationItem {
    std::string name;
    std::size_t expectedSize = 0;
    std::uint32_t expectedCrc = 0;
    std::size_t actualSize = 0;
    std::uint32_t actualCrc = 0;
    bool present = false;
    bool valid = false;
};

class RomSet {
public:
    bool load(const std::string& path, std::string& error);
    void clear();

    bool loaded() const { return loaded_; }
    const std::string& sourcePath() const { return sourcePath_; }
    const std::map<std::string, RomFile>& files() const { return files_; }
    const RomFile* find(const std::string& name) const;

    std::vector<ValidationItem> validationItems() const;
    std::vector<ValidationItem> validationItems(RomVariant variant) const;
    bool validateCanonicalPacman(std::string& error) const;
    bool validateCanonicalPuckman(std::string& error) const;
    bool validateSupportedPacmanFamily(std::string& error, RomVariant* variant=nullptr) const;
    RomVariant detectVariant() const;
    static const char* variantName(RomVariant variant);
    std::vector<std::uint8_t> assembledProgramROM() const;
    std::vector<std::uint8_t> assembledGraphicsROM() const;

    static const std::vector<CanonicalRomDescriptor>& canonicalPacmanManifest();
    static const std::vector<CanonicalRomDescriptor>& canonicalPuckmanManifest();
    static std::uint32_t crc32(const std::vector<std::uint8_t>& data);

private:
    bool loadDirectory(const std::string& path, std::string& error);
    bool loadZip(const std::string& path, std::string& error);
    void addFile(const std::string& displayName, const std::string& sourcePath, std::vector<std::uint8_t>&& data);

    bool loaded_ = false;
    std::string sourcePath_;
    std::map<std::string, RomFile> files_;
};

} // namespace pacripper
