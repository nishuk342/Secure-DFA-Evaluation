#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "common.hpp"
#include "network.hpp"

namespace floram_mpc {

using mpcdpf::Block;
using mpcdpf::random_u64;

struct BoolTripleBit {
    std::uint8_t A{};
    std::uint8_t B{};
    std::uint8_t C{};
};

inline void helper_send_boolbit_triples(SOCKET s1, SOCKET s2, std::size_t count) {
    net::send_u64(s1, static_cast<std::uint64_t>(count));
    net::send_u64(s2, static_cast<std::uint64_t>(count));
    for (std::size_t i = 0; i < count; ++i) {
        const auto a0 = static_cast<std::uint8_t>(random_u64() & 1U);
        const auto a1 = static_cast<std::uint8_t>(random_u64() & 1U);
        const auto b0 = static_cast<std::uint8_t>(random_u64() & 1U);
        const auto b1 = static_cast<std::uint8_t>(random_u64() & 1U);
        const auto c = static_cast<std::uint8_t>((a0 ^ a1) & (b0 ^ b1));
        const auto c0 = static_cast<std::uint8_t>(random_u64() & 1U);
        const auto c1 = static_cast<std::uint8_t>(c ^ c0);
        net::send_byte(s1,a0); net::send_byte(s1,b0); net::send_byte(s1,c0);
        net::send_byte(s2,a1); net::send_byte(s2,b1); net::send_byte(s2,c1);
    }
}

inline std::vector<BoolTripleBit> receive_boolbit_triples(SOCKET helper) {
    const auto n = static_cast<std::size_t>(net::recv_u64(helper));
    std::vector<BoolTripleBit> out(n);
    for(auto& t:out){t.A=net::recv_byte(helper);t.B=net::recv_byte(helper);t.C=net::recv_byte(helper);}
    return out;
}

class BoolMpcBit {
public:
    BoolMpcBit(int party, SOCKET peer, std::vector<BoolTripleBit>& triples, std::size_t& pos)
        : party_(party), peer_(peer), triples_(triples), pos_(pos) {}
    int party() const { return party_; }
    std::vector<std::uint8_t> and_batch(const std::vector<std::pair<std::uint8_t,std::uint8_t>>& in){
        if(pos_+in.size()>triples_.size()) throw std::runtime_error("secure AES: Boolean triple pool exhausted");
        std::vector<std::uint8_t>d(in.size()),e(in.size());
        for(size_t i=0;i<in.size();++i){const auto&t=triples_[pos_+i];d[i]=in[i].first^t.A;e[i]=in[i].second^t.B;}
        for(auto x:d)net::send_byte(peer_,x);
        std::vector<std::uint8_t>d2(in.size());for(auto&x:d2)x=net::recv_byte(peer_);
        for(auto x:e)net::send_byte(peer_,x);
        std::vector<std::uint8_t>e2(in.size());for(auto&x:e2)x=net::recv_byte(peer_);
        std::vector<std::uint8_t>out(in.size());
        for(size_t i=0;i<in.size();++i){const auto&t=triples_[pos_+i];const auto D=d[i]^d2[i],E=e[i]^e2[i];out[i]=t.C^(D&t.B)^(E&t.A);if(party_==0)out[i]^=(D&E);}
        pos_+=in.size();return out;
    }
private:int party_;SOCKET peer_;std::vector<BoolTripleBit>&triples_;size_t&pos_;
};

// NIST circuit-complexity AES S-box: 113 gates, 32 AND gates, AND depth 6.
// Source: usnistgov/Circuits, aes-sbox-fwd-g113-a32-d27-ad6.slp.
struct Gate { enum Op { XOR, AND, XNOR }; Op op; int out, a, b; };

inline int wire_id(const std::string& s) {
    if (s.size() >= 2 && s[0] == 'U') return std::stoi(s.substr(1));
    if (s.size() >= 2 && s[0] == 't') return 8 + std::stoi(s.substr(1));
    if (s.size() >= 2 && s[0] == 'S') return 114 + std::stoi(s.substr(1));
    throw std::runtime_error("bad AES S-box wire: " + s);
}

inline std::vector<Gate> make_sbox_gates() {
    static const char* const lines[] = {
"XOR t1 U3 U5","XOR t2 U0 U6","XOR t3 U0 U3","XOR t4 U0 U5","XOR t5 U1 U2","XOR t6 t5 U7","XOR t7 t6 U3","XOR t8 t2 t1","XOR t9 t6 U0","XOR t10 t6 U6","XOR t11 t10 t4","XOR t12 U4 t8","XOR t13 t12 U5","XOR t14 t12 U1","XOR t15 t13 U7","XOR t16 t13 t5","XOR t17 t14 t3","XOR t18 U7 t17","XOR t19 t16 t17","XOR t20 t16 t4","XOR t21 t5 t17","XOR t22 t2 t21","XOR t23 U0 t21",
"AND t24 t8 t13","AND t25 t11 t15","XOR t26 t25 t24","AND t27 t7 U7","XOR t28 t27 t24","AND t29 t2 t21","AND t30 t10 t6","XOR t31 t30 t29","AND t32 t9 t18","XOR t33 t32 t29","AND t34 t3 t17","AND t35 t1 t19","XOR t36 t35 t34","AND t37 t4 t16","XOR t38 t37 t34","XOR t39 t26 t14","XOR t40 t28 t38","XOR t41 t31 t36","XOR t42 t33 t38","XOR t43 t39 t36","XOR t44 t40 t20","XOR t45 t41 t22","XOR t46 t42 t23","XOR t47 t43 t44","AND t48 t43 t45","XOR t49 t46 t48","AND t50 t47 t49","XOR t51 t50 t44","XOR t52 t45 t46","XOR t53 t44 t48","AND t54 t53 t52","XOR t55 t54 t46","XOR t56 t45 t55","XOR t57 t49 t55","AND t58 t46 t57","XOR t59 t58 t56","XOR t60 t49 t58","AND t61 t51 t60","XOR t62 t47 t61","XOR t63 t62 t59","XOR t64 t51 t55","XOR t65 t51 t62","XOR t66 t55 t59","XOR t67 t64 t63",
"AND t68 t66 t13","AND t69 t59 t15","AND t70 t55 U7","AND t71 t65 t21","AND t72 t62 t6","AND t73 t51 t18","AND t74 t64 t17","AND t75 t67 t19","AND t76 t63 t16","AND t77 t66 t8","AND t78 t59 t11","AND t79 t55 t7","AND t80 t65 t2","AND t81 t62 t10","AND t82 t51 t9","AND t83 t64 t3","AND t84 t67 t1","AND t85 t63 t4",
"XOR t86 t83 t84","XOR t87 t78 t86","XOR t88 t77 t87","XOR t89 t68 t70","XOR t90 t69 t68","XOR t91 t71 t72","XOR t92 t80 t89","XOR t93 t75 t91","XOR t94 t76 t92","XOR t95 t93 t94","XOR t96 t91 t90","XOR t97 t71 t73","XOR t98 t81 t86","XOR t99 t89 t97","XOR S3 t88 t96","XOR t100 t74 t93","XOR t101 t82 t95","XOR t102 t98 t99","XNOR S7 t80 t102","XOR t103 t83 t100","XOR t104 t87 t79","XOR S0 t88 t100","XNOR S6 t95 t102","XOR S4 t99 S3","XNOR S1 S3 t100","XOR t105 t101 t103","XNOR S2 t105 t85","XOR S5 t104 t101"
    };
    std::vector<Gate> g;
    for (const char* line : lines) {
        std::string s(line);
        auto p1 = s.find(' '), p2 = s.find(' ', p1+1), p3 = s.find(' ', p2+1);
        const auto opstr = s.substr(0,p1);
        Gate::Op op = opstr=="AND" ? Gate::AND : (opstr=="XNOR" ? Gate::XNOR : Gate::XOR);
        const auto out=s.substr(p1+1,p2-p1-1), a=s.substr(p2+1,p3-p2-1), b=s.substr(p3+1);
        g.push_back({op,wire_id(out),wire_id(a),wire_id(b)});
    }
    return g;
}

struct SBoxPlan {
    std::vector<Gate> gates;
    std::vector<int> level;
    int max_and_depth{};
};

inline const SBoxPlan& sbox_plan() {
    static const SBoxPlan p = [] {
        SBoxPlan p;
        p.gates = make_sbox_gates();
        p.level.assign(122,0);
        for (const auto& g : p.gates) {
            const int l = std::max(p.level[g.a], p.level[g.b]) + (g.op == Gate::AND ? 1 : 0);
            p.level[g.out] = l;
            p.max_and_depth = std::max(p.max_and_depth,l);
        }
        return p;
    }();
    return p;
}

using Wire = std::uint64_t;
using SliceState = std::array<Wire,8>;

inline std::uint64_t rot4(std::uint64_t x, unsigned b) {
    x &= 0xFFFFULL;
    return ((x >> (4*b)) | (x << ((4-b)*4))) & 0xFFFFULL;
}

inline void shift_rows_ctaes(SliceState& s) {
    for (auto& v : s) {
        const auto x=v & 0xFFFFULL;
        v = (x & 0x000FULL) |
            ((x & 0x0010ULL) << 3) | ((x & 0x00E0ULL) >> 1) |
            ((x & 0x0300ULL) << 2) | ((x & 0x0C00ULL) >> 2) |
            ((x & 0x7000ULL) << 1) | ((x & 0x8000ULL) >> 3);
        v &= 0xFFFFULL;
    }
}

inline void mix_columns(SliceState& s) {
    const auto s0=s[0],s1=s[1],s2=s[2],s3=s[3],s4=s[4],s5=s[5],s6=s[6],s7=s[7];
    const auto s0_01=s0^rot4(s0,1), s0_123=rot4(s0_01,1)^rot4(s0,3);
    const auto s1_01=s1^rot4(s1,1), s1_123=rot4(s1_01,1)^rot4(s1,3);
    const auto s2_01=s2^rot4(s2,1), s2_123=rot4(s2_01,1)^rot4(s2,3);
    const auto s3_01=s3^rot4(s3,1), s3_123=rot4(s3_01,1)^rot4(s3,3);
    const auto s4_01=s4^rot4(s4,1), s4_123=rot4(s4_01,1)^rot4(s4,3);
    const auto s5_01=s5^rot4(s5,1), s5_123=rot4(s5_01,1)^rot4(s5,3);
    const auto s6_01=s6^rot4(s6,1), s6_123=rot4(s6_01,1)^rot4(s6,3);
    const auto s7_01=s7^rot4(s7,1), s7_123=rot4(s7_01,1)^rot4(s7,3);
    s[0]=s7_01^s0_123; s[1]=s7_01^s0_01^s1_123; s[2]=s1_01^s2_123; s[3]=s7_01^s2_01^s3_123;
    s[4]=s7_01^s3_01^s4_123; s[5]=s4_01^s5_123; s[6]=s5_01^s6_123; s[7]=s6_01^s7_123;
    for(auto& x:s) x&=0xFFFFULL;
}

inline void sbox16(SliceState& state, BoolMpcBit& mpc) {
    const auto& plan=sbox_plan();
    constexpr int W=122, BYTES=16;
    std::array<std::array<std::uint8_t,W>,BYTES> w{};
    for(int byte=0; byte<BYTES; ++byte)
        for(int b=0;b<8;++b)
            w[byte][b]=((state[7-b]>>((byte%4)*4 + (byte/4)))&1ULL);

    for(int level=0; level<=plan.max_and_depth; ++level){
        std::vector<std::pair<std::uint8_t,std::uint8_t>> pairs;
        std::vector<std::pair<int,int>> refs;
        for(const auto& g:plan.gates) if(g.op==Gate::AND && plan.level[g.out]==level){
            for(int byte=0;byte<BYTES;++byte){ pairs.push_back({w[byte][g.a],w[byte][g.b]}); refs.push_back({byte,g.out}); }
        }
        if(!pairs.empty()){
            auto outs=mpc.and_batch(pairs);
            for(std::size_t i=0;i<outs.size();++i) w[refs[i].first][refs[i].second]=outs[i];
        }
        for(const auto& g:plan.gates) if(g.op!=Gate::AND && plan.level[g.out]==level){
            for(int byte=0;byte<BYTES;++byte){
                Wire x=w[byte][g.a]^w[byte][g.b];
                if(g.op==Gate::XNOR && mpc.party()==0) x ^= 1ULL;
                w[byte][g.out]=x;
            }
        }
    }
    for(int b=0;b<8;++b){
        Wire v=0;
        for(int byte=0;byte<BYTES;++byte) v |= (w[byte][114+b]&1ULL)<<((byte%4)*4 + (byte/4));
        state[7-b]=v;
    }
}

inline std::array<std::array<std::uint8_t,16>,11> aes128_round_keys(const Block& key) {
    static const std::uint8_t sbox[256] = {
#include "aes_sbox_table.inc"
    };
    static const std::uint8_t rcon[10]={1,2,4,8,16,32,64,128,27,54};
    std::array<std::array<std::uint8_t,16>,11> rk{};
    std::copy(key.begin(),key.end(),rk[0].begin());
    for(int r=1;r<=10;++r){
        auto prev=rk[r-1];
        std::uint8_t t[4]={prev[13],prev[14],prev[15],prev[12]};
        for(auto& x:t)x=sbox[x]; t[0]^=rcon[r-1];
        for(int i=0;i<4;++i) rk[r][i]=prev[i]^t[i];
        for(int i=4;i<16;++i) rk[r][i]=prev[i]^rk[r][i-4];
    }
    return rk;
}

inline SliceState load_state_share(const std::array<std::uint8_t,16>& bytes) {
    SliceState s{};
    for(int i=0;i<16;++i){
        const int lane=(i%4)*4 + (i/4);
        for(int b=0;b<8;++b) if((bytes[i]>>b)&1U) s[b]|=(1ULL<<lane);
    }
    return s;
}

inline std::array<std::uint8_t,16> j_share_to_iv(std::uint64_t j_share) {
    std::array<std::uint8_t,16> iv{};
    for(int i=0;i<8;++i) iv[8+i]=static_cast<std::uint8_t>(j_share>>(56-8*i));
    return iv;
}

inline SliceState xor_state(const SliceState&a,const SliceState&b){SliceState r{};for(int i=0;i<8;++i)r[i]=a[i]^b[i];return r;}

inline std::uint64_t state_first8_share(const SliceState& s){
    std::array<std::uint8_t,8> out{};
    for(int byte=0;byte<8;++byte){
        const int lane=(byte%4)*4 + (byte/4);
        for(int b=0;b<8;++b) out[byte]|=static_cast<std::uint8_t>(((s[b]>>lane)&1ULL)<<b);
    }
    std::uint64_t v=0; for(int i=0;i<8;++i)v|=static_cast<std::uint64_t>(out[i])<<(8*i); return v;
}

inline SliceState secure_aes128(
    const std::array<std::array<std::uint8_t,16>,11>& rk_local,
    BoolMpcBit& mpc,
    const std::array<std::uint8_t,16>& iv_local) {
    SliceState s=load_state_share(iv_local);
    auto kr=load_state_share(rk_local[0]);
    for(int b=0;b<8;++b) s[b]^=kr[b];
    for(int round=1;round<=10;++round){
        sbox16(s,mpc);
        shift_rows_ctaes(s);
        if(round!=10) mix_columns(s);
        kr=load_state_share(rk_local[round]);
        for(int b=0;b<8;++b)s[b]^=kr[b];
    }
    return s;
}

inline std::uint64_t secure_mask_share(
    int party, SOCKET peer, std::uint64_t j_additive_share, const Block& local_key,
    std::vector<BoolTripleBit>& triples, std::size_t& triple_pos) {
    BoolMpcBit mpc(party,peer,triples,triple_pos);

    // Secure conversion of j=j0+j1 (mod 2^64) into XOR shares.
    std::array<std::uint8_t,64> sum{};
    std::uint8_t carry=0;
    for(int bit=0;bit<64;++bit){
        const std::uint8_t a=(party==0) ? static_cast<std::uint8_t>((j_additive_share>>bit)&1ULL) : 0U;
        const std::uint8_t b=(party==1) ? static_cast<std::uint8_t>((j_additive_share>>bit)&1ULL) : 0U;
        auto v=mpc.and_batch({{a,b},{carry,a^b}});
        sum[bit]=a^b^carry;
        carry=v[0]^v[1];
    }

    std::array<std::uint8_t,16> iv{};
    for(int bit=0;bit<64;++bit) if(sum[bit]&1ULL){
        const int byte=8+(7-(bit/8)); const int off=bit%8;
        iv[byte]|=static_cast<std::uint8_t>(1U<<off);
    }

    std::array<std::array<std::uint8_t,16>,11> zero_rk{};
    const auto k0 = (party==0) ? aes128_round_keys(local_key) : zero_rk;
    const auto k1 = (party==1) ? aes128_round_keys(local_key) : zero_rk;
    const auto a=secure_aes128(k0,mpc,iv);
    const auto b=secure_aes128(k1,mpc,iv);
    return state_first8_share(xor_state(a,b));
}

} // namespace floram_mpc
