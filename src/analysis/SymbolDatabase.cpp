// Created by Jacob Hodgkins
#include "SymbolDatabase.h"

#include <cctype>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace pacripper {
namespace {
std::string trim(const std::string& s) {
    std::size_t a=0,b=s.size();
    while(a<b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while(b>a && std::isspace(static_cast<unsigned char>(s[b-1]))) --b;
    return s.substr(a,b-a);
}
bool parseHexAddress(std::string text,std::uint16_t& out) {
    text=trim(text);
    if(!text.empty() && text[0]=='$') text.erase(0,1);
    else if(text.size()>2 && text[0]=='0' && (text[1]=='x'||text[1]=='X')) text.erase(0,2);
    if(text.empty() || text.size()>4) return false;
    unsigned long v=0;
    for(char c:text) {
        unsigned d=0;
        if(c>='0'&&c<='9') d=static_cast<unsigned>(c-'0');
        else if(c>='a'&&c<='f') d=10u+static_cast<unsigned>(c-'a');
        else if(c>='A'&&c<='F') d=10u+static_cast<unsigned>(c-'A');
        else return false;
        v=(v<<4)|d;
    }
    if(v>0xFFFFul) return false;
    out=static_cast<std::uint16_t>(v); return true;
}
}

bool SymbolDatabase::validIdentifier(const std::string& name) {
    if(name.empty()) return false;
    const auto first=static_cast<unsigned char>(name[0]);
    if(!(std::isalpha(first)||name[0]=='_')) return false;
    for(char c:name) {
        const auto u=static_cast<unsigned char>(c);
        if(!(std::isalnum(u)||c=='_')) return false;
    }
    return true;
}

bool SymbolDatabase::set(std::uint16_t address,const std::string& name,const std::string& comment,std::string& error) {
    if(!validIdentifier(name)) { error="Symbol names must use C-style identifier characters and may not begin with a digit."; return false; }
    for(const auto& kv:entries_) {
        if(kv.first!=address && kv.second.name==name) { error="Symbol name is already assigned to another address."; return false; }
    }
    entries_[address]=UserSymbol{address,name,comment}; error.clear(); return true;
}

void SymbolDatabase::erase(std::uint16_t address) { entries_.erase(address); }
void SymbolDatabase::clear() { entries_.clear(); sourcePath_.clear(); }
const UserSymbol* SymbolDatabase::find(std::uint16_t address) const { const auto it=entries_.find(address); return it==entries_.end()?nullptr:&it->second; }

bool SymbolDatabase::load(const std::string& path,std::string& error) {
    std::ifstream f(path.c_str()); if(!f) { error="Unable to open symbol database: "+path; return false; }
    std::map<std::uint16_t,UserSymbol> parsed;
    std::string line; std::size_t lineNo=0;
    while(std::getline(f,line)) {
        ++lineNo; const std::string t=trim(line); if(t.empty()||t[0]=='#'||t[0]==';') continue;
        std::string addrText,name,comment;
        const std::size_t t1=t.find_first_of("\t ");
        if(t1==std::string::npos) { error="Malformed symbol line "+std::to_string(lineNo)+"."; return false; }
        addrText=t.substr(0,t1);
        std::size_t p=t.find_first_not_of("\t ",t1);
        if(p==std::string::npos) { error="Missing symbol name on line "+std::to_string(lineNo)+"."; return false; }
        const std::size_t cpos=t.find_first_of("\t ",p);
        if(cpos==std::string::npos) name=t.substr(p);
        else { name=t.substr(p,cpos-p); const std::size_t cp=t.find_first_not_of("\t ",cpos); if(cp!=std::string::npos) comment=t.substr(cp); }
        std::uint16_t address=0;
        if(!parseHexAddress(addrText,address)) { error="Invalid address on symbol line "+std::to_string(lineNo)+"."; return false; }
        if(!validIdentifier(name)) { error="Invalid symbol name on line "+std::to_string(lineNo)+"."; return false; }
        for(const auto& kv:parsed) if(kv.second.name==name && kv.first!=address) { error="Duplicate symbol name on line "+std::to_string(lineNo)+"."; return false; }
        parsed[address]=UserSymbol{address,name,comment};
    }
    if(!f.eof() && f.fail()) { error="Failed while reading symbol database."; return false; }
    entries_.swap(parsed); sourcePath_=path; error.clear(); return true;
}

bool SymbolDatabase::save(const std::string& path,std::string& error) const {
    std::ofstream f(path.c_str()); if(!f) { error="Unable to write symbol database: "+path; return false; }
    f<<"# PacRipper researcher symbol database v1\n";
    f<<"# ADDRESS  NAME  OPTIONAL COMMENT\n";
    for(const auto& kv:entries_) {
        f<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<static_cast<unsigned>(kv.first)<<std::dec<<"\t"<<kv.second.name;
        if(!kv.second.comment.empty()) f<<"\t"<<kv.second.comment;
        f<<"\n";
    }
    if(!f) { error="Failed while writing symbol database."; return false; }
    error.clear(); return true;
}

} // namespace pacripper
