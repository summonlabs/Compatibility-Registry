// Regression tests: rejected mutations, generation fencing, persistence and
// decoding of untrusted bytes.
#include "testutil.hpp"
#include "compat/compat.hpp"
#include <functional>
#include <span>
#include <stdexcept>
#include <vector>
using namespace compat;

namespace {

Canon device_payload(const char* cc, const char* arch) {
    Canon::Record r = Canon::rec();
    Canon::put_str(r, devf::Architecture, arch);
    Canon::put_str(r, devf::ComputeCapability, cc);
    return Canon::mk_record(std::move(r));
}

std::uint64_t rule_generation(const CompatibilityRegistry& reg, const CompatibilityRuleId& id) {
    for (const auto& r : reg.active_rules()) if (r.rule_id == id) return r.generation.value;
    return 0;
}

// Re-wraps a snapshot after changing its decoded payload (with a valid
// checksum), the way a crafted or damaged snapshot would look.
std::vector<std::uint8_t> rewrap(const std::vector<std::uint8_t>& snap,
                                 const std::function<void(Canon::Record&)>& mutate) {
    Canon doc = canonical_decode(std::span<const std::uint8_t>(snap.data() + 6, snap.size() - 6 - 32));
    Canon::Record root = doc.as_record();
    mutate(root);
    std::vector<std::uint8_t> pl = canonical_encode(Canon::mk_record(std::move(root)));
    Sha256::Digest chk = Sha256::compute(pl.data(), pl.size());
    std::vector<std::uint8_t> out(snap.begin(), snap.begin() + 6);
    out.insert(out.end(), pl.begin(), pl.end());
    out.insert(out.end(), chk.begin(), chk.end());
    return out;
}

// Replaces field `tag` of the first record in sequence field `seq_tag`.
void set_in_first(Canon::Record& root, std::uint32_t seq_tag, std::uint32_t tag, Canon value) {
    for (auto& [t, v] : root) {
        if (t != seq_tag) continue;
        Canon::Seq s = v.as_seq();
        Canon::Record item = s.at(0).as_record();
        for (auto& [it, iv] : item) if (it == tag) iv = value;
        s[0] = Canon::mk_record(std::move(item));
        v = Canon::mk_seq(std::move(s));
    }
}

bool recover_throws(const std::vector<std::uint8_t>& bytes) {
    try { CompatibilityRegistry::recover(bytes); return false; } catch (const std::exception&) { return true; }
}

} // namespace

int main() {
    TEST("a rejected dependency cycle leaves the registry unchanged");
    {
        CompatibilityRegistry reg;
        ProfileId a = reg.register_profile(ProfileKind::Device, device_payload("12.0", "sm_120"));
        ProfileId b = reg.register_profile(ProfileKind::Device, device_payload("12.0", "sm_121"), {a.value});
        bool threw = false;
        try { reg.supersede_profile(ProfileKind::Device, a.value, device_payload("12.1", "sm_120"), {b.value}); }
        catch (const std::runtime_error&) { threw = true; }
        CHECK(threw);
        const ProfileRecord* cur = reg.find_profile(a.value);
        CHECK(cur != nullptr);
        CHECK(cur && cur->generation.value == 1);
        CHECK(reg.history_of(a.value).size() == 1);
        CHECK(reg.dependents_of(a.value).size() == 1);

        ProfileRecord rec;
        rec.kind = ProfileKind::Device;
        rec.id = a.value;
        rec.payload = device_payload("12.1", "sm_120");
        rec.deps = {b.value};
        threw = false;
        try { reg.register_profile(rec); } catch (const std::runtime_error&) { threw = true; }
        CHECK(threw);
        CHECK(reg.find_profile(a.value) != nullptr);
        CHECK(reg.evaluate_pair(a.value, a.value).outcome == Outcome::Exact);
    }

    TEST("evidence at an older source generation is rejected");
    {
        CompatibilityRegistry reg;
        EvidenceRecord fresh;
        fresh.id = EvidenceId::genseed();
        fresh.subject = Uuid::genseed();
        fresh.field = "compute_capability";
        fresh.value = Canon::mk_str("12.0");
        fresh.source = "probe";
        fresh.source_generation = Generation{2};
        reg.register_evidence(fresh);
        EvidenceRecord stale = fresh;
        stale.id = EvidenceId::genseed();
        stale.value = Canon::mk_str("9.0");
        stale.source_generation = Generation{1};
        reg.register_evidence(stale);
        CHECK(reg.find_evidence(fresh.id) != nullptr);
        CHECK(reg.find_evidence(stale.id) == nullptr);
        EvidenceRecord same = fresh;
        same.id = EvidenceId::genseed();
        reg.register_evidence(same);
        CHECK(reg.find_evidence(same.id) != nullptr);
    }

    TEST("evidence values that are not records survive persistence and fingerprinting");
    {
        CompatibilityRegistry reg;
        EvidenceRecord ev;
        ev.id = EvidenceId::genseed();
        ev.subject = Uuid::genseed();
        ev.field = "compute_capability";
        ev.value = Canon::mk_str("12.0");
        EvidenceRecord other = ev;
        other.value = Canon::mk_str("9.0");
        CHECK(ev.fingerprint() != other.fingerprint());
        reg.register_evidence(ev);
        auto back = CompatibilityRegistry::recover(reg.snapshot());
        const EvidenceRecord* got = back->find_evidence(ev.id);
        CHECK(got != nullptr);
        CHECK(got && got->value.kind() == CanonKind::Str && got->value.as_string() == "12.0");
    }

    TEST("a re-registered rule never reuses an earlier generation");
    {
        CompatibilityRegistry reg;
        CompatibilityRule r;
        r.rule_id = CompatibilityRuleId::genseed();
        r.scope = "pair";
        r.outcome = Outcome::Compatible;
        reg.register_rule(r);
        reg.supersede_rule(r.rule_id, r);
        reg.supersede_rule(r.rule_id, r);
        const std::uint64_t before = rule_generation(reg, r.rule_id);
        reg.disable_rule(r.rule_id);
        reg.register_rule(r);
        CHECK(rule_generation(reg, r.rule_id) > before);
    }

    TEST("a profile field of an unexpected type fails the constraint instead of throwing");
    {
        for (PredOp op : {PredOp::Min, PredOp::VersionGe}) {
            CompatibilityRegistry reg;
            Canon::Record ra = Canon::rec();
            Canon::put_bool(ra, devf::ComputeCapability, true);   // not a number or version
            Canon::put_str(ra, devf::TotalMemory, "lots");          // not a number
            Canon::Record rb = ra;
            Canon::put_str(rb, devf::Architecture, "sm_120");
            ProfileId a = reg.register_profile(ProfileKind::Device, Canon::mk_record(std::move(ra)));
            ProfileId b = reg.register_profile(ProfileKind::Device, Canon::mk_record(std::move(rb)));
            CompatibilityRule rule;
            rule.rule_id = CompatibilityRuleId::genseed();
            rule.scope = "pair";
            rule.left_kind = ProfileKind::Device;
            rule.right_kind = ProfileKind::Device;
            rule.outcome = Outcome::Compatible;
            Constraint c;
            c.op = op;
            c.field = op == PredOp::Min ? "total_memory" : "compute_capability";
            c.expected = op == PredOp::Min ? Canon::mk_uint(16) : Canon::mk_str("12.0");
            rule.required.push_back(c);
            reg.register_rule(rule);
            bool threw = false;
            CompatibilityDecision d;
            try { d = reg.evaluate_pair(a.value, b.value); } catch (const std::exception&) { threw = true; }
            CHECK(!threw);
            CHECK(!threw && d.outcome != Outcome::Compatible);
        }
    }

    TEST("recover rejects out-of-range enums and impossible generations");
    {
        CompatibilityRegistry reg;
        reg.register_profile(ProfileKind::Device, device_payload("12.0", "sm_120"));
        CompatibilityRule r;
        r.rule_id = CompatibilityRuleId::genseed();
        r.scope = "pair";
        r.outcome = Outcome::Compatible;
        reg.register_rule(r);
        const std::vector<std::uint8_t> snap = reg.snapshot();
        CHECK(!recover_throws(rewrap(snap, [](Canon::Record&) {})));                     // unchanged: accepted
        CHECK(recover_throws(rewrap(snap, [](Canon::Record& root) { set_in_first(root, 4, 10, Canon::mk_uint(99)); })));  // rule outcome
        CHECK(recover_throws(rewrap(snap, [](Canon::Record& root) { set_in_first(root, 3, 2, Canon::mk_uint(99)); })));   // profile kind
        CHECK(recover_throws(rewrap(snap, [](Canon::Record& root) { set_in_first(root, 3, 3, Canon::mk_uint(0)); })));    // profile generation 0
        CHECK(recover_throws(rewrap(snap, [](Canon::Record& root) { set_in_first(root, 4, 2, Canon::mk_uint(0)); })));    // rule generation 0
    }

    TEST("decoding deeply nested input fails cleanly instead of overflowing the stack");
    {
        const std::size_t depth = 100000;
        std::vector<std::uint8_t> bytes = {0x43, 0x52, 0x43, 0x46, 0x01};
        bytes.reserve(5 + 5 * (depth + 1));
        for (std::size_t k = depth; k >= 1; --k) {
            const std::uint32_t len = static_cast<std::uint32_t>(5 * k);
            bytes.push_back(0x09);  // Sequence
            bytes.push_back(static_cast<std::uint8_t>(len >> 24));
            bytes.push_back(static_cast<std::uint8_t>(len >> 16));
            bytes.push_back(static_cast<std::uint8_t>(len >> 8));
            bytes.push_back(static_cast<std::uint8_t>(len));
        }
        for (int i = 0; i < 5; ++i) bytes.push_back(0x00);  // Null
        bool threw = false;
        try { canonical_decode(bytes); } catch (const CanonError&) { threw = true; }
        CHECK(threw);
    }

    RUN_TESTS();
}
