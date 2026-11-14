// Regression tests against the coordinator OS process over framed TCP: source
// authority fencing and requests that used to terminate the coordinator. The
// test only connects; the coordinator (COMPAT_COORDINATOR) listens.
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "testutil.hpp"
#include "compat/compat.hpp"
#include "compat/net.hpp"
#include <winsock2.h>
#include <windows.h>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#pragma comment(lib, "ws2_32.lib")
using namespace compat;

namespace {

std::string coordinator_exe() {
    char* v = nullptr;
    std::size_t n = 0;
    std::string exe;
    if (_dupenv_s(&v, &n, "COMPAT_COORDINATOR") == 0 && v) { exe = v; std::free(v); }
    return exe;
}

// A coordinator process on a fixed loopback port.
struct Coordinator {
    PROCESS_INFORMATION pi{};
    bool start(std::uint16_t port) {
        std::string cmd = "\"" + coordinator_exe() + "\" --port " + std::to_string(port);
        std::vector<char> line(cmd.begin(), cmd.end());
        line.push_back(0);
        STARTUPINFOA si{};
        si.cb = sizeof(si);
        if (!CreateProcessA(nullptr, line.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return false;
        // Wait until it accepts connections (or has exited).
        for (;;) {
            if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) return false;
            SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_port = htons(port);
            a.sin_addr.s_addr = inet_addr("127.0.0.1");
            const bool ok = ::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
            ::closesocket(s);
            if (ok) return true;
            Sleep(10);
        }
    }
    bool alive() const { return pi.hProcess && WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT; }
    void stop(std::uint16_t port) {
        if (!pi.hProcess) return;
        if (alive()) {
            RegistryClient c(port);
            std::string err;
            if (c.connect(err)) c.shutdown(err);
        }
        if (alive()) TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        pi = PROCESS_INFORMATION{};
    }
};

Canon device(const char* cc, const char* arch) {
    Canon::Record r = Canon::rec();
    Canon::put_str(r, devf::Architecture, arch);
    Canon::put_str(r, devf::ComputeCapability, cc);
    return Canon::mk_record(std::move(r));
}

CompatibilityRule device_rule(const char* domain) {
    CompatibilityRule rule;
    rule.rule_id = CompatibilityRuleId::genseed();
    rule.scope = "pair";
    rule.domain = domain;
    rule.left_kind = ProfileKind::Device;
    rule.right_kind = ProfileKind::Device;
    rule.outcome = Outcome::Compatible;
    return rule;
}

std::uint32_t crc32(const std::uint8_t* d, std::size_t n) {
    std::uint32_t c = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < n; ++i) {
        c ^= d[i];
        for (int b = 0; b < 8; ++b) c = (c & 1u) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
    }
    return c ^ 0xFFFFFFFFu;
}

void put_u32be(std::vector<std::uint8_t>& o, std::uint32_t v) {
    o.push_back(static_cast<std::uint8_t>(v >> 24));
    o.push_back(static_cast<std::uint8_t>(v >> 16));
    o.push_back(static_cast<std::uint8_t>(v >> 8));
    o.push_back(static_cast<std::uint8_t>(v));
}

} // namespace

int main() {
    WSADATA wd;
    WSAStartup(MAKEWORD(2, 2), &wd);

    TEST("source generation and domain fence rules, evidence and invalidation");
    {
        const std::uint16_t port = 19747;
        Coordinator coord;
        CHECK(coord.start(port));
        RegistryClient c(port);
        std::string err;
        CHECK(c.connect(err));
        Uuid boot, pid;
        CHECK(c.register_source("dev", "device", boot, err));
        CHECK(c.register_profile("dev", boot, 2, device("12.0", "sm_120"), ProfileKind::Device, "device", pid, err));
        CHECK(!c.invalidate("dev", boot, 1, pid, "stale invalidation", err));
        CompatibilityDecision d;
        CHECK(c.query_pair(pid, pid, d, err) && d.outcome == Outcome::Exact);  // still valid
        CHECK(!c.register_rule("dev", boot, 1, device_rule("device"), err));
        EvidenceRecord ev;
        ev.field = "compute_capability";
        ev.value = Canon::mk_str("9.0");
        CHECK(!c.register_evidence("dev", boot, 1, ev, err));
        CHECK(!c.register_rule("dev", boot, 2, device_rule("model"), err));  // outside its scope
        CHECK(c.register_rule("dev", boot, 2, device_rule("device"), err));
        c.close();
        coord.stop(port);
    }

    TEST("requests that fail to evaluate are rejected without stopping the coordinator");
    {
        const std::uint16_t port = 19748;
        Coordinator coord;
        CHECK(coord.start(port));
        RegistryClient c(port);
        std::string err;
        CHECK(c.connect(err));
        Uuid boot, a, b;
        CHECK(c.register_source("src", "*", boot, err));
        Canon::Record ra = Canon::rec();
        Canon::put_str(ra, devf::TotalMemory, "lots");  // not a number
        Canon::Record rb = ra;
        Canon::put_str(rb, devf::Architecture, "sm_120");
        CHECK(c.register_profile("src", boot, 1, Canon::mk_record(std::move(ra)), ProfileKind::Device, "device", a, err));
        CHECK(c.register_profile("src", boot, 1, Canon::mk_record(std::move(rb)), ProfileKind::Device, "device", b, err));
        CompatibilityRule min = device_rule("device");
        Constraint m;
        m.op = PredOp::Min;
        m.field = "total_memory";
        m.expected = Canon::mk_uint(16);
        min.required.push_back(m);
        CHECK(c.register_rule("src", boot, 1, min, err));
        CompatibilityDecision d;
        CHECK(c.query_pair(a, b, d, err));
        CHECK(d.outcome != Outcome::Compatible);
        CompatibilityRule bad = device_rule("device");
        bad.outcome = static_cast<Outcome>(99);
        CHECK(!c.register_rule("src", boot, 1, bad, err));
        CompatibilityRule bad_op = device_rule("device");
        Constraint bo;
        bo.op = static_cast<PredOp>(99);
        bo.field = "architecture";
        bad_op.required.push_back(bo);
        CHECK(!c.register_rule("src", boot, 1, bad_op, err));
        CompatibilityRule bad_kind = device_rule("device");
        bad_kind.left_kind = static_cast<ProfileKind>(99);
        CHECK(!c.register_rule("src", boot, 1, bad_kind, err));
        Uuid k;
        CHECK(!c.register_profile("src", boot, 1, device("12.0", "sm_120"), static_cast<ProfileKind>(99), "device", k, err));
        // Nothing invalid was stored: the coordinator's snapshot still recovers.
        NetMessage snap;
        CHECK(c.send(MsgType::Snapshot, Canon::mk_record(Canon::rec()), snap, err));
        const Canon* bytes = snap.payload.field(1);
        CHECK(bytes && bytes->kind() == CanonKind::Bytes);
        if (bytes && bytes->kind() == CanonKind::Bytes) {
            const std::string& s = bytes->as_string();
            std::vector<std::uint8_t> raw(s.begin(), s.end());
            std::unique_ptr<CompatibilityRegistry> rec;
            try { rec = CompatibilityRegistry::recover(raw); } catch (const std::exception&) {}
            CHECK(rec && rec->find_profile(a) && rec->find_profile(b));
        }
        CHECK(c.query_pair(a, a, d, err) && d.outcome == Outcome::Exact);
        CHECK(coord.alive());
        c.close();
        coord.stop(port);
    }

    TEST("a deeply nested frame is rejected without stopping the coordinator");
    {
        const std::uint16_t port = 19749;
        Coordinator coord;
        CHECK(coord.start(port));
        const std::size_t depth = 100000;
        std::vector<std::uint8_t> pl = {0x43, 0x52, 0x43, 0x46, 0x01};
        for (std::size_t k = depth; k >= 1; --k) { pl.push_back(0x09); put_u32be(pl, static_cast<std::uint32_t>(5 * k)); }
        for (int i = 0; i < 5; ++i) pl.push_back(0x00);
        std::vector<std::uint8_t> frame;
        put_u32be(frame, 0x43524E57u);
        frame.push_back(1);
        frame.push_back(static_cast<std::uint8_t>(MsgType::QueryPair));
        put_u32be(frame, static_cast<std::uint32_t>(pl.size()));
        frame.insert(frame.end(), pl.begin(), pl.end());
        put_u32be(frame, crc32(pl.data(), pl.size()));
        SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        CHECK(::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
        std::size_t off = 0;
        while (off < frame.size()) {
            const int n = ::send(s, reinterpret_cast<const char*>(frame.data() + off), static_cast<int>(frame.size() - off), 0);
            if (n <= 0) break;
            off += static_cast<std::size_t>(n);
        }
        // The coordinator answers or closes this connection once it has handled the frame.
        char buf[256];
        while (::recv(s, buf, sizeof(buf), 0) > 0) {
        }
        ::closesocket(s);
        RegistryClient c(port);
        std::string err;
        CHECK(c.connect(err));
        Uuid boot;
        CHECK(c.register_source("src", "*", boot, err));
        CHECK(coord.alive());
        c.close();
        coord.stop(port);
    }

    WSACleanup();
    RUN_TESTS();
}
