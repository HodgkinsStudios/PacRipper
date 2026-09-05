// Created by Jacob Hodgkins
#include "ConditionSemantics.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <map>
#include <sstream>
#include <vector>

namespace pacripper {
namespace {
std::vector<std::string> splitOperands(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    int depth=0;
    for(char c:s) {
        if(c=='(') ++depth;
        else if(c==')') --depth;
        if(c==',' && depth==0) { out.push_back(cur);cur.clear(); }
        else cur+=c;
    }
    if(!cur.empty() || !s.empty()) out.push_back(cur);
    for(auto& x:out) {
        std::size_t a=0,b=x.size();
        while(a<b && std::isspace(static_cast<unsigned char>(x[a]))) ++a;
        while(b>a && std::isspace(static_cast<unsigned char>(x[b-1]))) --b;
        x=x.substr(a,b-a);
    }
    return out;
}

bool isPair(const std::string& op) {
    return op=="BC" || op=="DE" || op=="HL" || op=="SP" || op=="IX" || op=="IY";
}

bool isRotateShift(const std::string& m) {
    return m=="RLC" || m=="RRC" || m=="RL" || m=="RR" ||
           m=="SLA" || m=="SRA" || m=="SLL" || m=="SRL";
}

bool isBlockIO(const std::string& m) {
    return m=="INI" || m=="IND" || m=="INIR" || m=="INDR" ||
           m=="OUTI" || m=="OUTD" || m=="OTIR" || m=="OTDR";
}

bool isBlockCompare(const std::string& m) {
    return m=="CPI" || m=="CPD" || m=="CPIR" || m=="CPDR";
}

bool isBlockMove(const std::string& m) {
    return m=="LDI" || m=="LDD" || m=="LDIR" || m=="LDDR";
}

bool isLogical(const std::string& m) {
    return m=="AND" || m=="OR" || m=="XOR";
}

std::string zeroExpr(const std::string& value,bool zero) {
    return value + (zero ? " == $00" : " != $00");
}

std::string bitMaskExpr(const Instruction& in,bool zero) {
    const auto p=splitOperands(in.operands);
    if(p.size()<2) return {};
    char* end=nullptr;
    const long bit=std::strtol(p[0].c_str(),&end,10);
    if(!end || *end!='\0' || bit<0 || bit>7) return {};
    std::ostringstream mask;
    mask<<"$"<<std::uppercase<<std::hex;
    if((1u<<bit)<0x10) mask<<"0";
    mask<<(1u<<bit);
    return "("+p[1]+" & "+mask.str()+")"+(zero?" == $00":" != $00");
}


void addRegisterAndAliases(std::set<std::string>& out,const std::string& reg) {
    auto add=[&](const char* r){out.insert(r);};
    if(reg=="B"||reg=="C"){out.insert(reg);add("BC");return;}
    if(reg=="D"||reg=="E"){out.insert(reg);add("DE");return;}
    if(reg=="H"||reg=="L"){out.insert(reg);add("HL");return;}
    if(reg=="BC"){add("BC");add("B");add("C");return;}
    if(reg=="DE"){add("DE");add("D");add("E");return;}
    if(reg=="HL"){add("HL");add("H");add("L");return;}
    if(reg=="IXH"||reg=="IXL"){out.insert(reg);add("IX");return;}
    if(reg=="IYH"||reg=="IYL"){out.insert(reg);add("IY");return;}
    if(reg=="A"||reg=="SP"||reg=="IX"||reg=="IY")out.insert(reg);
}

std::set<std::string> operandDependencies(const std::string& op) {
    std::set<std::string> out;
    if(op.empty())return out;
    if(op.front()=='('){
        out.insert("MEM");
        if(op.find("HL")!=std::string::npos)out.insert("HL");
        else if(op.find("IX")!=std::string::npos)out.insert("IX");
        else if(op.find("IY")!=std::string::npos)out.insert("IY");
        else if(op.find("BC")!=std::string::npos)out.insert("BC");
        else if(op.find("DE")!=std::string::npos)out.insert("DE");
        else if(op.find("SP")!=std::string::npos)out.insert("SP");
        return out;
    }
    static const std::set<std::string> regs={"A","B","C","D","E","H","L","BC","DE","HL","SP","IX","IY","IXH","IXL","IYH","IYL"};
    if(regs.count(op))out.insert(op);
    return out;
}

bool memoryOperand(const std::string& op){return !op.empty()&&op.front()=='('; }
std::string resultOperand(const Instruction& in) {
    const auto p=splitOperands(in.operands);
    if(in.mnemonic=="INC" || in.mnemonic=="DEC" || isRotateShift(in.mnemonic)) {
        if(!p.empty()) return p.back();
    }
    if(in.mnemonic=="NEG" || in.mnemonic=="RLD" || in.mnemonic=="RRD") return "A";
    if(in.mnemonic=="LD" && (in.operands=="A,I" || in.operands=="A,R")) return "A";
    if(in.mnemonic=="ADD" || in.mnemonic=="ADC" || in.mnemonic=="SUB" ||
       in.mnemonic=="SBC" || isLogical(in.mnemonic)) {
        if(in.mnemonic=="ADD" || in.mnemonic=="ADC" || in.mnemonic=="SBC") {
            if(p.size()>=2 && p[0]!="A") return {};
        }
        return "A";
    }
    return {};
}
}

unsigned ConditionSemantics::flagMaskForCondition(const std::string& raw) {
    if(raw=="Z" || raw=="NZ") return FlagZ;
    if(raw=="C" || raw=="NC") return FlagC;
    if(raw=="M" || raw=="P") return FlagS;
    if(raw=="PE" || raw=="PO") return FlagPV;
    return FlagNone;
}

std::string ConditionSemantics::inverseCondition(const std::string& raw) {
    static const std::map<std::string,std::string> inv={
        {"Z","NZ"},{"NZ","Z"},{"C","NC"},{"NC","C"},
        {"M","P"},{"P","M"},{"PE","PO"},{"PO","PE"}
    };
    const auto it=inv.find(raw);
    return it==inv.end()?std::string():it->second;
}

FlagEffect ConditionSemantics::flagEffect(const Instruction& in) {
    FlagEffect e;
    const auto p=splitOperands(in.operands);
    const std::string& m=in.mnemonic;

    // A CALL/RST instruction itself preserves flags, but the fallthrough state is
    // after the callee/handler returned. Without an ABI or callee summary, all
    // tested flags are conservatively unknown at that continuation.
    if(in.flow==FlowKind::Call || in.flow==FlowKind::Restart) { e.unknown=FlagAll;return e; }

    if(m=="DB") { e.unknown=FlagAll;return e; }
    if(m=="POP" && in.operands=="AF") { e.unknown=FlagAll;return e; }
    if(m=="EX" && in.operands=="AF,AF'") { e.unknown=FlagAll;return e; }

    if(m=="CP" || m=="NEG" || m=="DAA" || isRotateShift(m) || isBlockIO(m)) {
        e.defined=FlagAll;return e;
    }
    if(m=="ADC" || m=="SBC") {
        e.defined=FlagAll;return e;
    }
    if(m=="ADD") {
        if(p.size()>=2 && (p[0]=="HL" || p[0]=="IX" || p[0]=="IY")) e.defined=FlagC;
        else e.defined=FlagAll;
        return e;
    }
    if(m=="SUB" || isLogical(m)) { e.defined=FlagAll;return e; }
    if(m=="INC" || m=="DEC") {
        if(!p.empty() && isPair(p[0])) return e;
        e.defined=FlagZ|FlagS|FlagPV;return e;
    }
    if(m=="BIT") { e.defined=FlagZ|FlagS|FlagPV;return e; }
    if(m=="RLCA" || m=="RRCA" || m=="RLA" || m=="RRA" || m=="SCF" || m=="CCF") {
        e.defined=FlagC;return e;
    }
    if(m=="RLD" || m=="RRD" || isBlockCompare(m)) { e.defined=FlagZ|FlagS|FlagPV;return e; }
    if(isBlockMove(m)) { e.defined=FlagPV;return e; }
    if(m=="IN") {
        if(in.operands.find("(C)")!=std::string::npos) e.defined=FlagZ|FlagS|FlagPV;
        return e;
    }
    if(m=="LD" && (in.operands=="A,I" || in.operands=="A,R")) { e.defined=FlagZ|FlagS|FlagPV;return e; }

    // Exact tracked-flag preservation for the remaining decoder mnemonics.
    if(m=="LD" || m=="JP" || m=="JR" || m=="RET" || m=="RETI" || m=="RETN" ||
       m=="DJNZ" || m=="HALT" || m=="NOP" || m=="DI" || m=="EI" || m=="IM" ||
       m=="EX" || m=="EXX" || m=="PUSH" || m=="POP" || m=="OUT" || m=="RES" ||
       m=="SET" || m=="CPL") return e;

    // If a new/undocumented instruction reaches this layer, losing the producer
    // is safer than silently carrying a stale flag provenance across it.
    e.unknown=FlagAll;
    return e;
}

std::set<std::string> ConditionSemantics::writtenRegisters(const Instruction& in) {
    std::set<std::string> out;
    const auto p=splitOperands(in.operands);
    const std::string& m=in.mnemonic;
    auto addOp=[&](const std::string& op){
        if(!memoryOperand(op)) addRegisterAndAliases(out,op);
    };

    if(m=="LD") {
        if(!p.empty()) addOp(p[0]);
        return out;
    }
    if(m=="INC" || m=="DEC") {
        if(!p.empty()) addOp(p[0]);
        return out;
    }
    if(m=="ADD" || m=="ADC" || m=="SBC") {
        if(p.size()>=2) addOp(p[0]);
        else addRegisterAndAliases(out,"A");
        return out;
    }
    if(m=="SUB" || isLogical(m) || m=="NEG" || m=="DAA" || m=="CPL" ||
       m=="RLCA" || m=="RRCA" || m=="RLA" || m=="RRA" || m=="RLD" || m=="RRD") {
        addRegisterAndAliases(out,"A");
        return out;
    }
    if(isRotateShift(m)) {
        for(const auto& op:p) addOp(op);
        return out;
    }
    if(m=="RES" || m=="SET") {
        for(std::size_t i=1;i<p.size();++i) addOp(p[i]);
        return out;
    }
    if(m=="DJNZ") {
        addRegisterAndAliases(out,"B");
        return out;
    }
    if(m=="POP") {
        if(!p.empty()) addOp(p[0]);
        addRegisterAndAliases(out,"SP");
        return out;
    }
    if(m=="PUSH") {
        addRegisterAndAliases(out,"SP");
        return out;
    }
    if(m=="EX") {
        for(const auto& op:p) addOp(op);
        return out;
    }
    if(m=="EXX") {
        addRegisterAndAliases(out,"BC");
        addRegisterAndAliases(out,"DE");
        addRegisterAndAliases(out,"HL");
        return out;
    }
    if(m=="IN") {
        if(!p.empty() && p[0]!="(C)") addOp(p[0]);
        return out;
    }
    if(isBlockMove(m)) {
        addRegisterAndAliases(out,"HL");
        addRegisterAndAliases(out,"DE");
        addRegisterAndAliases(out,"BC");
        return out;
    }
    if(isBlockCompare(m)) {
        addRegisterAndAliases(out,"HL");
        addRegisterAndAliases(out,"BC");
        return out;
    }
    if(isBlockIO(m)) {
        addRegisterAndAliases(out,"B");
        addRegisterAndAliases(out,"HL");
        return out;
    }
    if(in.flow==FlowKind::Call || in.flow==FlowKind::Restart) {
        addRegisterAndAliases(out,"SP");
        return out;
    }
    return out;
}

bool ConditionSemantics::writesMemory(const Instruction& in) {
    const auto p=splitOperands(in.operands);
    const std::string& m=in.mnemonic;
    if(m=="LD") return !p.empty() && memoryOperand(p[0]);
    if((m=="INC" || m=="DEC") && !p.empty()) return memoryOperand(p[0]);
    if(isRotateShift(m)) return !p.empty() && memoryOperand(p[0]);
    if((m=="RES" || m=="SET") && p.size()>=2) return memoryOperand(p[1]);
    if(m=="RLD" || m=="RRD" || m=="PUSH" || in.flow==FlowKind::Call || in.flow==FlowKind::Restart) return true;
    if(m=="EX") {
        for(const auto& op:p) if(memoryOperand(op)) return true;
    }
    if(isBlockMove(m) || m=="INI" || m=="IND" || m=="INIR" || m=="INDR") return true;
    return false;
}

std::set<std::string> ConditionSemantics::expressionDependencies(const std::string& raw,const Instruction& in) {
    std::set<std::string> out;
    const auto p=splitOperands(in.operands);
    if(expressionFor(raw,in).empty()) return out;
    auto addDeps=[&](const std::string& op){
        const auto d=operandDependencies(op);
        out.insert(d.begin(),d.end());
    };

    if(raw=="Z" || raw=="NZ") {
        if(in.mnemonic=="CP" && !p.empty()) {
            addRegisterAndAliases(out,"A");
            addDeps(p.back());
            return out;
        }
        if(in.mnemonic=="BIT" && p.size()>=2) {
            addDeps(p[1]);
            return out;
        }
        const auto r=resultOperand(in);
        if(!r.empty()) addDeps(r);
        return out;
    }
    if(raw=="C" || raw=="NC") {
        if(in.mnemonic=="CP" && !p.empty()) {
            addRegisterAndAliases(out,"A");
            addDeps(p.back());
        }
        return out; // SCF/logical carry forms are constants and need no value dependency.
    }
    if(raw=="M" || raw=="P") {
        const auto r=resultOperand(in);
        if(!r.empty()) addDeps(r);
        return out;
    }
    if(raw=="PE" || raw=="PO") {
        if(in.mnemonic=="BIT" && p.size()>=2) {
            addDeps(p[1]);
            return out;
        }
        if((in.mnemonic=="INC" || in.mnemonic=="DEC") && !p.empty()) {
            addDeps(p.back());
            return out;
        }
        if(isLogical(in.mnemonic)) addRegisterAndAliases(out,"A");
    }
    return out;
}

std::string ConditionSemantics::expressionFor(const std::string& raw,const Instruction& in) {
    const auto p=splitOperands(in.operands);
    const bool set = raw=="Z" || raw=="C" || raw=="M" || raw=="PE";

    if(raw=="Z" || raw=="NZ") {
        if(in.mnemonic=="CP" && !p.empty()) return "A" + std::string(set?" == ":" != ") + p.back();
        if(in.mnemonic=="BIT") return bitMaskExpr(in,set);
        const auto result=resultOperand(in);
        if(!result.empty()) return zeroExpr(result,set);
    }

    if(raw=="C" || raw=="NC") {
        if(in.mnemonic=="CP" && !p.empty()) return "A" + std::string(set?" < ":" >= ") + p.back();
        if(in.mnemonic=="SCF") return set?"true":"false";
        if(isLogical(in.mnemonic)) return set?"false":"true"; // AND/OR/XOR clear C on Z80.
    }

    if(raw=="M" || raw=="P") {
        const auto result=resultOperand(in);
        if(!result.empty()) return "("+result+" & $80)" + std::string(set?" != $00":" == $00");
    }

    if(raw=="PE" || raw=="PO") {
        if(in.mnemonic=="BIT") return bitMaskExpr(in,set);
        if(in.mnemonic=="INC" && !p.empty()) return p.back()+std::string(set?" == $80":" != $80");
        if(in.mnemonic=="DEC" && !p.empty()) return p.back()+std::string(set?" == $7F":" != $7F");
        if(isLogical(in.mnemonic)) return std::string(set?"parity_even(A)":"parity_odd(A)");
    }

    return {};
}

} // namespace pacripper
