// Created by Jacob Hodgkins
#include "RomSet.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace pacripper {
namespace {

std::string lower(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

std::string baseName(const std::string& path) {
    const std::size_t p = path.find_last_of("/\\");
    return p == std::string::npos ? path : path.substr(p + 1);
}

bool endsWithInsensitive(const std::string& s, const std::string& suffix) {
    if (s.size() < suffix.size()) return false;
    return lower(s.substr(s.size() - suffix.size())) == lower(suffix);
}

bool readFile(const std::string& path, std::vector<std::uint8_t>& out) {
    std::ifstream in(path.c_str(), std::ios::binary);
    if (!in) return false;
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

void scanDirectoryRecursive(const std::string& path, int depth,
                            std::vector<std::pair<std::string, std::vector<std::uint8_t>>>& out) {
    namespace fs = std::filesystem;
    if (depth > 4) return;
    std::error_code ec;
    if (!fs::is_directory(fs::path(path), ec)) return;
    for (const auto& entry : fs::directory_iterator(fs::path(path), fs::directory_options::skip_permission_denied, ec)) {
        if (ec) break;
        const auto full = entry.path();
        if (entry.is_directory(ec)) {
            scanDirectoryRecursive(full.string(), depth + 1, out);
        } else if (entry.is_regular_file(ec)) {
            std::vector<std::uint8_t> data;
            if (readFile(full.string(), data)) out.push_back(std::make_pair(full.string(), std::move(data)));
        }
    }
}


} // namespace

const std::vector<CanonicalRomDescriptor>& RomSet::canonicalPacmanManifest() {
    static const std::vector<CanonicalRomDescriptor> manifest = {
        {"pacman.6e",0x1000,0xC1E6AB10u,"program",true},
        {"pacman.6f",0x1000,0x1A6FB2D4u,"program",true},
        {"pacman.6h",0x1000,0xBCDD1BEBu,"program",true},
        {"pacman.6j",0x1000,0x817D94E3u,"program",true},
        {"pacman.5e",0x1000,0x0C944964u,"character_graphics",false},
        {"pacman.5f",0x1000,0x958FEDF9u,"sprite_graphics",false},
        {"82s123.7f",0x0020,0x2FC650BDu,"palette_prom",false},
        {"82s126.4a",0x0100,0x3EB3A8E4u,"color_lookup_prom",false},
        {"82s126.1m",0x0100,0xA9CC86BFu,"waveform_prom",false},
        {"82s126.3m",0x0100,0x77245B66u,"sound_timing_control_prom",false}
    };
    return manifest;
}

const std::vector<CanonicalRomDescriptor>& RomSet::canonicalPuckmanManifest() {
    static const std::vector<CanonicalRomDescriptor> manifest = {
        {"pm1_prg1.6e",0x0800,0xF36E88ABu,"program",true},
        {"pm1_prg2.6k",0x0800,0x618BD9B3u,"program",true},
        {"pm1_prg3.6f",0x0800,0x7D177853u,"program",true},
        {"pm1_prg4.6m",0x0800,0xD3E8914Cu,"program",true},
        {"pm1_prg5.6h",0x0800,0x6BF4F625u,"program",true},
        {"pm1_prg6.6n",0x0800,0xA948CE83u,"program",true},
        {"pm1_prg7.6j",0x0800,0xB6289B26u,"program",true},
        {"pm1_prg8.6p",0x0800,0x17A88C13u,"program",true},
        {"pm1_chg1.5e",0x0800,0x2066A0B7u,"character_graphics",false},
        {"pm1_chg2.5h",0x0800,0x3591B89Du,"character_graphics",false},
        {"pm1_chg3.5f",0x0800,0x9E39323Au,"sprite_graphics",false},
        {"pm1_chg4.5j",0x0800,0x1B1D9096u,"sprite_graphics",false},
        {"pm1-1.7f",0x0020,0x2FC650BDu,"palette_prom",false},
        {"pm1-4.4a",0x0100,0x3EB3A8E4u,"color_lookup_prom",false},
        {"pm1-3.1m",0x0100,0xA9CC86BFu,"waveform_prom",false},
        {"pm1-2.3m",0x0100,0x77245B66u,"sound_timing_control_prom",false}
    };
    return manifest;
}

void RomSet::clear() {
    loaded_ = false;
    sourcePath_.clear();
    files_.clear();
}

void RomSet::addFile(const std::string& displayName, const std::string& sourcePath,
                     std::vector<std::uint8_t>&& data) {
    RomFile rf;
    rf.name = baseName(displayName);
    rf.sourcePath = sourcePath;
    rf.crc32 = crc32(data);
    rf.data = std::move(data);
    const std::string key = lower(rf.name);
    if (files_.find(key) == files_.end()) files_[key] = std::move(rf);
}

bool RomSet::load(const std::string& path, std::string& error) {
    clear();
    namespace fs = std::filesystem;
    std::error_code ec;
    const fs::path p(path);
    if (!fs::exists(p, ec)) {
        error = "Path does not exist: " + path;
        return false;
    }
    bool ok = false;
    if (fs::is_directory(p, ec)) ok = loadDirectory(path, error);
    else if (fs::is_regular_file(p, ec) && endsWithInsensitive(path, ".zip")) ok = loadZip(path, error);
    else error = "Choose a ROM directory or a .zip archive.";
    if (ok) {
        loaded_ = true;
        sourcePath_ = path;
    }
    return ok;
}

bool RomSet::loadDirectory(const std::string& path, std::string& error) {
    std::vector<std::pair<std::string, std::vector<std::uint8_t>>> found;
    scanDirectoryRecursive(path, 0, found);
    for (auto& f : found) addFile(baseName(f.first), f.first, std::move(f.second));
    if (files_.empty()) {
        error = "ROM directory contained no readable files.";
        return false;
    }
    return true;
}

bool RomSet::loadZip(const std::string&, std::string& error) {
    // The public PacRipper wrapper extracts ZIPs with Python's cross-platform
    // standard library before invoking this private C++ core.  Keeping archive
    // handling out of the core avoids shelling out to platform-specific unzip tools.
    error = "ZIP input is handled by the PacRipper front end; PacRipperCore expects an extracted ROM directory.";
    return false;
}


const RomFile* RomSet::find(const std::string& name) const {
    const auto it = files_.find(lower(name));
    return it == files_.end() ? nullptr : &it->second;
}

std::vector<ValidationItem> RomSet::validationItems() const {
    const RomVariant variant = detectVariant();
    return validationItems(variant == RomVariant::Unknown ? RomVariant::Pacman : variant);
}

std::vector<ValidationItem> RomSet::validationItems(RomVariant variant) const {
    std::vector<ValidationItem> out;
    const auto& manifest = variant == RomVariant::Puckman ? canonicalPuckmanManifest() : canonicalPacmanManifest();
    for (const CanonicalRomDescriptor& e : manifest) {
        ValidationItem v;
        v.name = e.name;
        v.expectedSize = e.size;
        v.expectedCrc = e.crc32;
        const RomFile* f = find(e.name);
        if (f) {
            v.present = true;
            v.actualSize = f->data.size();
            v.actualCrc = f->crc32;
            v.valid = v.actualSize == v.expectedSize && v.actualCrc == v.expectedCrc;
        }
        out.push_back(v);
    }
    return out;
}

static bool validateVariantItems(const std::vector<ValidationItem>& items, const char* label, std::string& error) {
    for (const ValidationItem& v : items) {
        if (!v.present) { error = std::string("Missing canonical ") + label + " ROM/PROM: " + v.name; return false; }
        if (v.actualSize != v.expectedSize) {
            std::ostringstream o; o << v.name << " size mismatch: " << v.actualSize << " bytes; expected " << v.expectedSize << "."; error=o.str(); return false;
        }
        if (v.actualCrc != v.expectedCrc) {
            std::ostringstream o; o << v.name << " CRC32 mismatch: loaded 0x" << std::hex << std::uppercase << v.actualCrc << ", expected 0x" << v.expectedCrc << "."; error=o.str(); return false;
        }
    }
    error.clear(); return true;
}

bool RomSet::validateCanonicalPacman(std::string& error) const { return validateVariantItems(validationItems(RomVariant::Pacman), "Pac-Man", error); }
bool RomSet::validateCanonicalPuckman(std::string& error) const { return validateVariantItems(validationItems(RomVariant::Puckman), "Puckman", error); }

RomVariant RomSet::detectVariant() const {
    std::string ignored;
    if (validateCanonicalPuckman(ignored)) return RomVariant::Puckman;
    if (validateCanonicalPacman(ignored)) return RomVariant::Pacman;
    return RomVariant::Unknown;
}

const char* RomSet::variantName(RomVariant variant) {
    switch (variant) { case RomVariant::Pacman: return "Pac-Man"; case RomVariant::Puckman: return "Puckman"; default: return "Unknown"; }
}

bool RomSet::validateSupportedPacmanFamily(std::string& error, RomVariant* variant) const {
    const RomVariant detected = detectVariant();
    if (variant) *variant = detected;
    if (detected != RomVariant::Unknown) { error.clear(); return true; }
    std::string p, u; validateCanonicalPacman(p); validateCanonicalPuckman(u);
    error = "Unsupported Pac-Man-family ROM set. Pac-Man check: " + p + " Puckman check: " + u;
    return false;
}

std::vector<std::uint8_t> RomSet::assembledProgramROM() const {
    std::vector<std::uint8_t> out; out.reserve(0x4000);
    if (detectVariant() == RomVariant::Puckman) {
        static const char* names[] = {"pm1_prg1.6e","pm1_prg2.6k","pm1_prg3.6f","pm1_prg4.6m","pm1_prg5.6h","pm1_prg6.6n","pm1_prg7.6j","pm1_prg8.6p"};
        for (const char* name : names) { const RomFile* f=find(name); if(!f||f->data.size()!=0x800) return {}; out.insert(out.end(),f->data.begin(),f->data.end()); }
        return out;
    }
    static const char* names[] = {"pacman.6e", "pacman.6f", "pacman.6h", "pacman.6j"};
    for (const char* name : names) { const RomFile* f=find(name); if(!f||f->data.size()!=0x1000) return {}; out.insert(out.end(),f->data.begin(),f->data.end()); }
    return out;
}

std::vector<std::uint8_t> RomSet::assembledGraphicsROM() const {
    std::vector<std::uint8_t> out; out.reserve(0x2000);
    if (detectVariant() == RomVariant::Puckman) {
        static const char* names[] = {"pm1_chg1.5e","pm1_chg2.5h","pm1_chg3.5f","pm1_chg4.5j"};
        for (const char* name : names) { const RomFile* f=find(name); if(!f||f->data.size()!=0x800) return {}; out.insert(out.end(),f->data.begin(),f->data.end()); }
        return out;
    }
    const RomFile* a=find("pacman.5e"); const RomFile* b=find("pacman.5f");
    if(!a||!b||a->data.size()!=0x1000||b->data.size()!=0x1000) return {};
    out.insert(out.end(),a->data.begin(),a->data.end()); out.insert(out.end(),b->data.begin(),b->data.end()); return out;
}

std::uint32_t RomSet::crc32(const std::vector<std::uint8_t>& data) {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::uint8_t v : data) {
        crc ^= v;
        for (int i = 0; i < 8; ++i)
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

} // namespace pacripper
