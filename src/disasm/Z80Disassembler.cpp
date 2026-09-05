// Created by Jacob Hodgkins
#include "Z80Disassembler.h"

#include <iomanip>
#include <sstream>

namespace pacripper {
namespace {

std::uint8_t rb(const std::vector<std::uint8_t>& rom, std::size_t a) {
    return a < rom.size() ? rom[a] : 0;
}

std::uint16_t rw(const std::vector<std::uint8_t>& rom, std::size_t a) {
    return static_cast<std::uint16_t>(rb(rom, a) | (static_cast<std::uint16_t>(rb(rom, a + 1)) << 8));
}

const char* ccName(int y) {
    static const char* cc[8] = {"NZ", "Z", "NC", "C", "PO", "PE", "P", "M"};
    return cc[y & 7];
}

const char* aluName(int y) {
    static const char* n[8] = {"ADD", "ADC", "SUB", "SBC", "AND", "XOR", "OR", "CP"};
    return n[y & 7];
}

const char* rotName(int y) {
    static const char* n[8] = {"RLC", "RRC", "RL", "RR", "SLA", "SRA", "SLL", "SRL"};
    return n[y & 7];
}

std::string rpName(int p, int indexMode) {
    static const char* rp[4] = {"BC", "DE", "HL", "SP"};
    if (p == 2 && indexMode == 1) return "IX";
    if (p == 2 && indexMode == 2) return "IY";
    return rp[p & 3];
}

std::string rp2Name(int p, int indexMode) {
    static const char* rp[4] = {"BC", "DE", "HL", "AF"};
    if (p == 2 && indexMode == 1) return "IX";
    if (p == 2 && indexMode == 2) return "IY";
    return rp[p & 3];
}

std::string idxName(int indexMode) { return indexMode == 1 ? "IX" : "IY"; }

std::string regName(int r, int indexMode, bool memoryUsesIndex, std::int8_t disp) {
    static const char* regs[8] = {"B", "C", "D", "E", "H", "L", "(HL)", "A"};
    if (r == 6 && indexMode != 0 && memoryUsesIndex) {
        return "(" + idxName(indexMode) + Z80Disassembler::signedDisp(disp) + ")";
    }
    if (indexMode != 0 && r == 4 && !memoryUsesIndex) return indexMode == 1 ? "IXH" : "IYH";
    if (indexMode != 0 && r == 5 && !memoryUsesIndex) return indexMode == 1 ? "IXL" : "IYL";
    return regs[r & 7];
}

void setBytes(Instruction& i, const std::vector<std::uint8_t>& rom, std::size_t start, std::size_t length) {
    i.bytes.clear();
    for (std::size_t n = 0; n < length && start + n < rom.size(); ++n) i.bytes.push_back(rom[start + n]);
    if (i.bytes.empty()) i.bytes.push_back(0);
}

std::uint16_t relativeTarget(std::uint16_t after, std::int8_t d) {
    return static_cast<std::uint16_t>(after + d);
}

} // namespace

std::string Instruction::text() const {
    if (operands.empty()) return mnemonic;
    return mnemonic + " " + operands;
}

std::string Z80Disassembler::hex8(std::uint8_t v) {
    std::ostringstream o; o << "$" << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(v); return o.str();
}

std::string Z80Disassembler::hex16(std::uint16_t v) {
    std::ostringstream o; o << "$" << std::uppercase << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(v); return o.str();
}

std::string Z80Disassembler::signedDisp(std::int8_t d) {
    if (d == 0) return "+0";
    std::ostringstream o;
    if (d > 0) o << "+" << static_cast<int>(d);
    else o << static_cast<int>(d);
    return o.str();
}

Instruction Z80Disassembler::decode(const std::vector<std::uint8_t>& rom, std::uint16_t address) const {
    Instruction bad; bad.address = address; bad.mnemonic = "DB"; bad.operands = hex8(rb(rom, address)); setBytes(bad, rom, address, 1);
    if (address >= rom.size()) return bad;

    std::size_t p = address;
    int indexMode = 0;
    int prefixBytes = 0;
    // Repeated DD/FD prefixes are legal; the last one wins.
    while (p < rom.size() && (rom[p] == 0xDD || rom[p] == 0xFD)) {
        indexMode = rom[p] == 0xDD ? 1 : 2;
        ++p; ++prefixBytes;
        if (prefixBytes > 8) return bad;
    }
    if (p >= rom.size()) return bad;
    if (rom[p] == 0xCB) {
        if (indexMode != 0) return decodeCB(rom, address, prefixBytes, indexMode, true);
        return decodeCB(rom, address, prefixBytes, 0, false);
    }
    if (rom[p] == 0xED) return decodeED(rom, address, prefixBytes);
    return decodeBase(rom, address, prefixBytes, indexMode);
}

Instruction Z80Disassembler::decodeBase(const std::vector<std::uint8_t>& rom, std::uint16_t address,
                                        int prefixBytes, int indexMode) const {
    Instruction in; in.address = address;
    const std::size_t opPos = static_cast<std::size_t>(address) + prefixBytes;
    if (opPos >= rom.size()) { in.mnemonic="DB"; in.operands=hex8(rb(rom,address)); setBytes(in,rom,address,1); return in; }
    const std::uint8_t op = rb(rom, opPos);
    const int x = op >> 6, y = (op >> 3) & 7, z = op & 7, p = y >> 1, q = y & 1;
    std::size_t cursor = opPos + 1;

    bool indexedMemory = indexMode != 0 && ((x == 1 && (y == 6 || z == 6) && !(y == 6 && z == 6)) || (x == 2 && z == 6) || (x == 0 && z >= 4 && z <= 6 && y == 6));
    std::int8_t disp = 0;
    if (indexedMemory) { disp = static_cast<std::int8_t>(rb(rom, cursor)); ++cursor; }

    auto byteImm = [&]() { const std::uint8_t v = rb(rom, cursor); ++cursor; return v; };
    auto wordImm = [&]() { const std::uint16_t v = rw(rom, cursor); cursor += 2; return v; };
    auto finish = [&]() { setBytes(in, rom, address, cursor - address); return in; };
    auto memRef = [&](std::uint16_t a, RefAccess access) { in.memoryRefs.push_back({a, access}); };

    if (x == 0) {
        switch (z) {
            case 0:
                if (y == 0) in.mnemonic = "NOP";
                else if (y == 1) { in.mnemonic = "EX"; in.operands = "AF,AF'"; }
                else if (y == 2) {
                    const std::int8_t d = static_cast<std::int8_t>(byteImm());
                    const std::uint16_t t = relativeTarget(static_cast<std::uint16_t>(cursor), d);
                    in.mnemonic = "DJNZ"; in.operands = hex16(t); in.flow = FlowKind::RelativeJump; in.conditional = true; in.target = t;
                } else if (y == 3) {
                    const std::int8_t d = static_cast<std::int8_t>(byteImm());
                    const std::uint16_t t = relativeTarget(static_cast<std::uint16_t>(cursor), d);
                    in.mnemonic = "JR"; in.operands = hex16(t); in.flow = FlowKind::RelativeJump; in.target = t;
                } else {
                    const std::int8_t d = static_cast<std::int8_t>(byteImm());
                    const std::uint16_t t = relativeTarget(static_cast<std::uint16_t>(cursor), d);
                    in.mnemonic = "JR"; in.operands = std::string(ccName(y - 4)) + "," + hex16(t); in.flow = FlowKind::RelativeJump; in.conditional = true; in.target = t;
                }
                break;
            case 1:
                if (!q) { const std::uint16_t n = wordImm(); in.mnemonic="LD"; in.operands=rpName(p,indexMode)+","+hex16(n); }
                else { in.mnemonic="ADD"; in.operands=rpName(2,indexMode)+","+rpName(p,indexMode); }
                break;
            case 2:
                if (!q) {
                    if (p == 0) { in.mnemonic="LD"; in.operands="(BC),A"; }
                    else if (p == 1) { in.mnemonic="LD"; in.operands="(DE),A"; }
                    else if (p == 2) { const auto n=wordImm(); in.mnemonic="LD"; in.operands="("+hex16(n)+"),"+rpName(2,indexMode); memRef(n,RefAccess::Write); }
                    else { const auto n=wordImm(); in.mnemonic="LD"; in.operands="("+hex16(n)+"),A"; memRef(n,RefAccess::Write); }
                } else {
                    if (p == 0) { in.mnemonic="LD"; in.operands="A,(BC)"; }
                    else if (p == 1) { in.mnemonic="LD"; in.operands="A,(DE)"; }
                    else if (p == 2) { const auto n=wordImm(); in.mnemonic="LD"; in.operands=rpName(2,indexMode)+",("+hex16(n)+")"; memRef(n,RefAccess::Read); }
                    else { const auto n=wordImm(); in.mnemonic="LD"; in.operands="A,("+hex16(n)+")"; memRef(n,RefAccess::Read); }
                }
                break;
            case 3: in.mnemonic = q ? "DEC" : "INC"; in.operands = rpName(p,indexMode); break;
            case 4: in.mnemonic="INC"; in.operands=regName(y,indexMode,indexedMemory,disp); break;
            case 5: in.mnemonic="DEC"; in.operands=regName(y,indexMode,indexedMemory,disp); break;
            case 6: { const std::uint8_t n=byteImm(); in.mnemonic="LD"; in.operands=regName(y,indexMode,indexedMemory,disp)+","+hex8(n); break; }
            case 7: {
                static const char* misc[8] = {"RLCA","RRCA","RLA","RRA","DAA","CPL","SCF","CCF"};
                in.mnemonic = misc[y]; break;
            }
        }
        return finish();
    }

    if (x == 1) {
        if (y == 6 && z == 6) { in.mnemonic="HALT"; in.flow=FlowKind::Halt; return finish(); }
        in.mnemonic="LD";
        const bool mem = indexMode != 0 && (y == 6 || z == 6);
        // For the four IX/IY+d transfer exceptions, H/L stay H/L rather than IXH/IXL.
        auto indexedReg = [&](int r) {
            if (mem && r != 6 && (r == 4 || r == 5)) {
                static const char* regs[8]={"B","C","D","E","H","L","(HL)","A"}; return std::string(regs[r]);
            }
            return regName(r,indexMode,mem,disp);
        };
        in.operands=indexedReg(y)+","+indexedReg(z);
        return finish();
    }

    if (x == 2) {
        in.mnemonic=aluName(y);
        const std::string rhs=regName(z,indexMode,indexedMemory,disp);
        in.operands=(y==0 || y==1 || y==3) ? "A,"+rhs : rhs;
        return finish();
    }

    // x == 3
    switch (z) {
        case 0:
            in.mnemonic="RET"; in.operands=ccName(y); in.flow=FlowKind::Return; in.conditional=true; break;
        case 1:
            if (!q) { in.mnemonic="POP"; in.operands=rp2Name(p,indexMode); }
            else {
                if (p == 0) { in.mnemonic="RET"; in.flow=FlowKind::Return; }
                else if (p == 1) in.mnemonic="EXX";
                else if (p == 2) { in.mnemonic="JP"; in.operands="("+rpName(2,indexMode)+")"; in.flow=FlowKind::Jump; in.indirect=true; }
                else { in.mnemonic="LD"; in.operands="SP,"+rpName(2,indexMode); }
            }
            break;
        case 2: {
            const auto n=wordImm(); in.mnemonic="JP"; in.operands=std::string(ccName(y))+","+hex16(n); in.flow=FlowKind::Jump; in.conditional=true; in.target=n; break;
        }
        case 3:
            switch (y) {
                case 0: { const auto n=wordImm(); in.mnemonic="JP"; in.operands=hex16(n); in.flow=FlowKind::Jump; in.target=n; break; }
                case 1: // CB should have been dispatched before base decode.
                    in.mnemonic="DB"; in.operands=hex8(op); break;
                case 2: { const auto n=byteImm(); in.mnemonic="OUT"; in.operands="("+hex8(n)+"),A"; break; }
                case 3: { const auto n=byteImm(); in.mnemonic="IN"; in.operands="A,("+hex8(n)+")"; break; }
                case 4: in.mnemonic="EX"; in.operands="(SP),"+rpName(2,indexMode); break;
                case 5: in.mnemonic="EX"; in.operands="DE,HL"; break; // DD/FD prefix is ignored for EX DE,HL.
                case 6: in.mnemonic="DI"; break;
                case 7: in.mnemonic="EI"; break;
            }
            break;
        case 4: {
            const auto n=wordImm(); in.mnemonic="CALL"; in.operands=std::string(ccName(y))+","+hex16(n); in.flow=FlowKind::Call; in.conditional=true; in.target=n; break;
        }
        case 5:
            if (!q) { in.mnemonic="PUSH"; in.operands=rp2Name(p,indexMode); }
            else if (p == 0) { const auto n=wordImm(); in.mnemonic="CALL"; in.operands=hex16(n); in.flow=FlowKind::Call; in.target=n; }
            else { in.mnemonic="DB"; in.operands=hex8(op); }
            break;
        case 6: { const auto n=byteImm(); in.mnemonic=aluName(y); const std::string rhs=hex8(n); in.operands=(y==0 || y==1 || y==3) ? "A,"+rhs : rhs; break; }
        case 7:
            in.mnemonic="RST"; in.operands=hex16(static_cast<std::uint16_t>(y*8)); in.flow=FlowKind::Restart; in.target=y*8; break;
    }
    return finish();
}

Instruction Z80Disassembler::decodeCB(const std::vector<std::uint8_t>& rom, std::uint16_t address,
                                      int prefixBytes, int indexMode, bool indexedCB) const {
    Instruction in; in.address = address;
    std::size_t p = static_cast<std::size_t>(address) + prefixBytes;
    if (p >= rom.size() || rb(rom,p) != 0xCB) { in.mnemonic="DB"; in.operands=hex8(rb(rom,address)); setBytes(in,rom,address,1); return in; }
    ++p;
    std::int8_t disp = 0;
    if (indexedCB) { disp = static_cast<std::int8_t>(rb(rom,p)); ++p; }
    const std::uint8_t op=rb(rom,p++);
    const int x=op>>6,y=(op>>3)&7,z=op&7;
    std::string operand;
    if (indexedCB) operand="("+idxName(indexMode)+signedDisp(disp)+")";
    else operand=regName(z,0,false,0);

    if (x==0) {
        in.mnemonic=rotName(y);
        in.operands=operand;
        if (indexedCB && z != 6) in.operands += "," + regName(z,0,false,0);
    } else if (x==1) {
        in.mnemonic="BIT"; in.operands=std::to_string(y)+","+operand;
    } else if (x==2) {
        in.mnemonic="RES"; in.operands=std::to_string(y)+","+operand;
        if (indexedCB && z != 6) in.operands += "," + regName(z,0,false,0);
    } else {
        in.mnemonic="SET"; in.operands=std::to_string(y)+","+operand;
        if (indexedCB && z != 6) in.operands += "," + regName(z,0,false,0);
    }
    setBytes(in,rom,address,p-address);
    return in;
}

Instruction Z80Disassembler::decodeED(const std::vector<std::uint8_t>& rom, std::uint16_t address,
                                      int prefixBytes) const {
    Instruction in; in.address=address;
    std::size_t p=static_cast<std::size_t>(address)+prefixBytes;
    if (p>=rom.size() || rb(rom,p)!=0xED) { in.mnemonic="DB"; in.operands=hex8(rb(rom,address)); setBytes(in,rom,address,1); return in; }
    ++p;
    const std::uint8_t op=rb(rom,p++);
    const int x=op>>6,y=(op>>3)&7,z=op&7,rp=y>>1,q=y&1;
    auto wordImm=[&](){ auto n=rw(rom,p); p+=2; return n; };
    auto memRef=[&](std::uint16_t a, RefAccess access){ in.memoryRefs.push_back({a,access}); };

    if (x==1) {
        switch(z) {
            case 0:
                in.mnemonic="IN";
                in.operands = y==6 ? "(C)" : regName(y,0,false,0)+",(C)";
                break;
            case 1:
                in.mnemonic="OUT";
                in.operands = y==6 ? "(C),0" : "(C),"+regName(y,0,false,0);
                break;
            case 2:
                in.mnemonic=q?"ADC":"SBC"; in.operands="HL,"+rpName(rp,0); break;
            case 3: {
                const auto n=wordImm(); in.mnemonic="LD";
                if (!q) { in.operands="("+hex16(n)+"),"+rpName(rp,0); memRef(n,RefAccess::Write); }
                else { in.operands=rpName(rp,0)+",("+hex16(n)+")"; memRef(n,RefAccess::Read); }
                break;
            }
            case 4: in.mnemonic="NEG"; break;
            case 5: in.mnemonic=(y==1)?"RETI":"RETN"; in.flow=FlowKind::Return; break;
            case 6: {
                static const int im[8]={0,0,1,2,0,0,1,2}; in.mnemonic="IM"; in.operands=std::to_string(im[y]); break;
            }
            case 7:
                switch(y) {
                    case 0: in.mnemonic="LD"; in.operands="I,A"; break;
                    case 1: in.mnemonic="LD"; in.operands="R,A"; break;
                    case 2: in.mnemonic="LD"; in.operands="A,I"; break;
                    case 3: in.mnemonic="LD"; in.operands="A,R"; break;
                    case 4: in.mnemonic="RRD"; break;
                    case 5: in.mnemonic="RLD"; break;
                    default: in.mnemonic="NOP"; in.comment="Undocumented ED NOP"; break;
                }
                break;
        }
    } else if (x==2 && y>=4 && z<=3) {
        static const char* block[4][4] = {
            {"LDI","CPI","INI","OUTI"},
            {"LDD","CPD","IND","OUTD"},
            {"LDIR","CPIR","INIR","OTIR"},
            {"LDDR","CPDR","INDR","OTDR"}
        };
        in.mnemonic=block[y-4][z];
    } else {
        in.mnemonic="NOP"; in.comment="Undocumented ED NOP";
    }
    setBytes(in,rom,address,p-address);
    return in;
}

} // namespace pacripper
