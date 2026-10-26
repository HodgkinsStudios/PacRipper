// PacRipper deterministic ROM rebuilder integrated deterministic ROM rebuilder
// Created by Jacob Hodgkins

#include "RomRebuilder.h"

#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <utility>

namespace pacripper {
namespace {

std::uint32_t rotr(std::uint32_t v,unsigned n){return (v>>n)|(v<<(32u-n));}

const std::array<std::uint32_t,64> kSha256K={{
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
}};

struct LedgerBuild {
    std::vector<std::uint8_t> bytes;
    std::vector<const RomReconstructionReconstructionByteRecord*> owners;
    std::size_t ownedAddresses=0;
    std::size_t missingAddresses=0;
    std::size_t duplicateAddresses=0;
    std::size_t outOfRangeRecords=0;
};

LedgerBuild rebuildFromLedger(const std::vector<RomReconstructionReconstructionByteRecord>& ledger){
    LedgerBuild out;
    out.bytes.assign(RomRebuilder::kCanonicalProgramSize,0);
    out.owners.assign(RomRebuilder::kCanonicalProgramSize,nullptr);
    std::vector<bool> seen(RomRebuilder::kCanonicalProgramSize,false);
    for(const auto& record:ledger){
        const std::size_t address=record.address;
        if(address>=RomRebuilder::kCanonicalProgramSize){++out.outOfRangeRecords;continue;}
        if(seen[address]){++out.duplicateAddresses;continue;}
        seen[address]=true;
        if(!record.owned)continue;
        out.bytes[address]=record.emittedByte;
        out.owners[address]=&record;
        ++out.ownedAddresses;
    }
    out.missingAddresses=RomRebuilder::kCanonicalProgramSize-out.ownedAddresses;
    return out;
}

std::string hex16(std::uint16_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(4)<<std::setfill('0')<<(unsigned)v;return o.str();}
std::string hex8(std::uint8_t v){std::ostringstream o;o<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill('0')<<(unsigned)v;return o.str();}

} // namespace

const char* RomRebuilder::canonicalProgramSha256(){
    return "e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77";
}

std::string RomRebuilder::sha256(const std::vector<std::uint8_t>& bytes){
    std::vector<std::uint8_t> message=bytes;
    const std::uint64_t bitLength=static_cast<std::uint64_t>(message.size())*8u;
    message.push_back(0x80u);
    while((message.size()%64u)!=56u)message.push_back(0u);
    for(int shift=56;shift>=0;shift-=8)message.push_back(static_cast<std::uint8_t>((bitLength>>static_cast<unsigned>(shift))&0xFFu));

    std::array<std::uint32_t,8> h={{
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    }};
    std::array<std::uint32_t,64> w{};
    for(std::size_t offset=0;offset<message.size();offset+=64u){
        for(std::size_t i=0;i<16u;++i){
            const std::size_t p=offset+i*4u;
            w[i]=(static_cast<std::uint32_t>(message[p])<<24u)|
                 (static_cast<std::uint32_t>(message[p+1u])<<16u)|
                 (static_cast<std::uint32_t>(message[p+2u])<<8u)|
                 static_cast<std::uint32_t>(message[p+3u]);
        }
        for(std::size_t i=16u;i<64u;++i){
            const std::uint32_t s0=rotr(w[i-15u],7u)^rotr(w[i-15u],18u)^(w[i-15u]>>3u);
            const std::uint32_t s1=rotr(w[i-2u],17u)^rotr(w[i-2u],19u)^(w[i-2u]>>10u);
            w[i]=w[i-16u]+s0+w[i-7u]+s1;
        }
        std::uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(std::size_t i=0;i<64u;++i){
            const std::uint32_t s1=rotr(e,6u)^rotr(e,11u)^rotr(e,25u);
            const std::uint32_t ch=(e&f)^((~e)&g);
            const std::uint32_t temp1=hh+s1+ch+kSha256K[i]+w[i];
            const std::uint32_t s0=rotr(a,2u)^rotr(a,13u)^rotr(a,22u);
            const std::uint32_t maj=(a&b)^(a&c)^(b&c);
            const std::uint32_t temp2=s0+maj;
            hh=g;g=f;f=e;e=d+temp1;d=c;c=b;b=a;a=temp1+temp2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }

    std::ostringstream out;out<<std::hex<<std::setfill('0');
    for(const auto v:h)out<<std::setw(8)<<v;
    return out.str();
}

RomRebuildResult RomRebuilder::rebuildAndVerify(
    const std::vector<std::uint8_t>& originalProgram,
    const std::vector<RomReconstructionReconstructionByteRecord>& ledger){

    RomRebuildResult result;auto& st=result.stats;
    st.originalBytes=originalProgram.size();st.ledgerRecords=ledger.size();
    st.originalSha256=sha256(originalProgram);
    const bool knownPacman = st.originalSha256==canonicalProgramSha256();
    const bool knownPuckman = st.originalSha256=="de87b3024a309377f5cf438455ed7f37a7aa8b5db5da5189f9b8240f90057cef";
    st.canonicalInput=originalProgram.size()==kCanonicalProgramSize&&(knownPacman||knownPuckman);

    const auto first=rebuildFromLedger(ledger);
    const auto second=rebuildFromLedger(ledger);
    result.rebuiltBytes=first.bytes;result.repeatedBytes=second.bytes;
    st.rebuiltBytes=result.rebuiltBytes.size();st.ownedAddresses=first.ownedAddresses;
    st.missingAddresses=first.missingAddresses;st.duplicateAddresses=first.duplicateAddresses;
    st.outOfRangeRecords=first.outOfRangeRecords;
    st.ownershipComplete=st.ownedAddresses==kCanonicalProgramSize&&st.missingAddresses==0&&
                         st.duplicateAddresses==0&&st.outOfRangeRecords==0;
    st.rebuiltSha256=sha256(result.rebuiltBytes);st.repeatedSha256=sha256(result.repeatedBytes);
    st.deterministicRepeat=result.rebuiltBytes==result.repeatedBytes&&st.rebuiltSha256==st.repeatedSha256;
    st.sizeMatch=st.originalBytes==st.rebuiltBytes;

    const std::size_t compareBytes=originalProgram.size()<result.rebuiltBytes.size()?originalProgram.size():result.rebuiltBytes.size();
    for(std::size_t address=0;address<compareBytes;++address){
        if(originalProgram[address]==result.rebuiltBytes[address]){++st.matchingBytes;continue;}
        RomRebuildMismatchRecord mismatch;mismatch.id=result.mismatches.size();
        mismatch.address=static_cast<std::uint16_t>(address);mismatch.originalByte=originalProgram[address];mismatch.rebuiltByte=result.rebuiltBytes[address];
        if(address<first.owners.size()&&first.owners[address]){
            const auto& owner=*first.owners[address];mismatch.ownerKind=owner.ownerKind;mismatch.sourceId=owner.sourceId;
            mismatch.sourceText=owner.sourceText;mismatch.provenance=owner.provenance;
        }
        result.mismatches.push_back(std::move(mismatch));
    }
    if(st.sizeMatch)st.mismatchCount=result.mismatches.size();
    else st.mismatchCount=result.mismatches.size()+(st.originalBytes>st.rebuiltBytes?st.originalBytes-st.rebuiltBytes:st.rebuiltBytes-st.originalBytes);
    st.sha256Match=st.sizeMatch&&st.originalSha256==st.rebuiltSha256;
    st.safeToWrite=st.canonicalInput&&st.ownershipComplete&&st.sizeMatch&&st.mismatchCount==0&&st.sha256Match&&st.deterministicRepeat;
    st.verified=st.safeToWrite;

    if(!st.canonicalInput)result.diagnostic="Refusing rebuild output: loaded program is not one of the supported canonical Pac-Man/Puckman revisions.";
    else if(!st.ownershipComplete)result.diagnostic="Refusing rebuild output: reconstruction ledger does not own exactly one record for every canonical address.";
    else if(!st.sizeMatch)result.diagnostic="Refusing rebuild output: rebuilt image size differs from the canonical input image.";
    else if(st.mismatchCount!=0)result.diagnostic="Refusing rebuild output: byte verification found reconstruction mismatches.";
    else if(!st.sha256Match)result.diagnostic="Refusing rebuild output: SHA-256 verification failed.";
    else if(!st.deterministicRepeat)result.diagnostic="Refusing rebuild output: repeated ledger reconstruction was not deterministic.";
    else result.diagnostic="Integrated deterministic rebuild verified and safe to write.";
    return result;
}

bool RomRebuilder::writeBinary(const std::string& path,const std::vector<std::uint8_t>& bytes,std::string& error){
    std::ofstream out(path.c_str(),std::ios::binary|std::ios::trunc);
    if(!out){error="Could not open rebuild output path: "+path;return false;}
    if(!bytes.empty())out.write(reinterpret_cast<const char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
    if(!out){error="Failed while writing rebuilt program ROM: "+path;return false;}
    error.clear();return true;
}

std::vector<std::string> RomRebuilder::reportLines(const RomRebuildResult& result){
    const auto& s=result.stats;std::vector<std::string> out;
    out.push_back("PacRipper deterministic ROM rebuilder integrated deterministic ROM rebuilder");
    out.push_back("canonical input="+(s.canonicalInput?std::string("yes"):std::string("no"))+" original bytes="+std::to_string(s.originalBytes)+" rebuilt bytes="+std::to_string(s.rebuiltBytes));
    out.push_back("ledger records="+std::to_string(s.ledgerRecords)+" owned="+std::to_string(s.ownedAddresses)+" missing="+std::to_string(s.missingAddresses)+" duplicates="+std::to_string(s.duplicateAddresses)+" out-of-range="+std::to_string(s.outOfRangeRecords));
    out.push_back("matching bytes="+std::to_string(s.matchingBytes)+" mismatches="+std::to_string(s.mismatchCount));
    out.push_back("original SHA-256="+s.originalSha256);
    out.push_back("rebuilt  SHA-256="+s.rebuiltSha256);
    out.push_back("repeat   SHA-256="+s.repeatedSha256);
    out.push_back("ownership complete="+(s.ownershipComplete?std::string("yes"):std::string("no"))+" SHA-256 match="+(s.sha256Match?std::string("yes"):std::string("no"))+" deterministic repeat="+(s.deterministicRepeat?std::string("yes"):std::string("no")));
    out.push_back("verification="+(s.verified?std::string("PASS"):std::string("FAIL"))+" safe-to-write="+(s.safeToWrite?std::string("yes"):std::string("no"))+" diagnostic="+result.diagnostic);
    for(const auto& mismatch:result.mismatches){
        std::ostringstream line;line<<"mismatch #"<<mismatch.id<<" $"<<hex16(mismatch.address)<<" original=$"<<hex8(mismatch.originalByte)<<" rebuilt=$"<<hex8(mismatch.rebuiltByte)
            <<" owner="<<ExactRomReconstruction::ownerKindText(mismatch.ownerKind);
        if(mismatch.sourceId!=static_cast<std::size_t>(-1))line<<" source-id="<<mismatch.sourceId;
        if(!mismatch.sourceText.empty())line<<" source=\""<<mismatch.sourceText<<"\"";
        if(!mismatch.provenance.empty())line<<" provenance=\""<<mismatch.provenance<<"\"";
        out.push_back(line.str());
    }
    return out;
}

} // namespace pacripper
