#include <test/jtx/Account.h>
#include <test/jtx/Env.h>
#include <test/jtx/TestHelpers.h>
#include <test/jtx/amount.h>
#include <test/jtx/balance.h>
#include <test/jtx/delegate.h>
#include <test/jtx/fee.h>
#include <test/jtx/flags.h>
#include <test/jtx/multisign.h>
#include <test/jtx/owners.h>
#include <test/jtx/pay.h>
#include <test/jtx/regkey.h>
#include <test/jtx/seq.h>
#include <test/jtx/sig.h>
#include <test/jtx/ter.h>
#include <test/jtx/ticket.h>
#include <test/jtx/utility.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/basics/chrono.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/HashPrefix.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/SecretKey.h>
#include <xrpl/protocol/Sign.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>

#include <chrono>
#include <cstdint>
#include <string>

namespace xrpl {

class Cosigner_test : public beast::unit_test::Suite
{
    // An expiration `s` seconds after the current network time.
    static std::uint32_t
    expAfter(test::jtx::Env& env, std::chrono::seconds s)
    {
        return (env.now() + s).time_since_epoch().count();
    }

    // The unsigned canonical form of a Payment to be proposed.
    static json::Value
    proposedPayment(
        test::jtx::Account const& target,
        test::jtx::Account const& dest,
        STAmount const& amount,
        std::uint32_t seq,
        std::string const& fee = "100")
    {
        json::Value jv = test::jtx::pay(target, dest, amount);
        jv[jss::Sequence] = seq;
        jv[jss::Fee] = fee;
        jv[jss::SigningPubKey] = "";
        return jv;
    }

    static json::Value
    proposalCreate(
        test::jtx::Account const& proposer,
        json::Value const& inner,
        std::uint32_t expiration)
    {
        json::Value jv;
        jv[jss::TransactionType] = "TransactionProposalCreate";
        jv[jss::Account] = proposer.human();
        jv[sfRawTransaction.getJsonName()] = inner;
        jv[sfExpiration.getJsonName()] = expiration;
        return jv;
    }

    // A standard multi-sign contribution over the proposed transaction,
    // computed exactly as sign_for would: multisign signing data over the
    // unsigned payload, suffixed with the signer's account. `keys` supplies
    // the signing key pair, which need not be the signer's master key.
    static json::Value
    contribution(
        json::Value const& inner,
        test::jtx::Account const& signer,
        test::jtx::Account const& keys)
    {
        STObject const st = test::jtx::parse(inner);
        Serializer const data{buildMultiSigningData(st, signer.id())};
        auto const sig = sign(keys.pk(), keys.sk(), data.slice());

        json::Value sj;
        sj[jss::Account] = signer.human();
        sj[jss::SigningPubKey] = strHex(keys.pk().slice());
        sj[sfTxnSignature.getJsonName()] = strHex(Slice{sig.data(), sig.size()});
        return sj;
    }

    static json::Value
    contribution(json::Value const& inner, test::jtx::Account const& signer)
    {
        return contribution(inner, signer, signer);
    }

    // A single signature over the proposed transaction: standard transaction
    // signing data with SigningPubKey populated to the signer's key, exactly
    // as a directly single-signed submission would compute it. `keys` need
    // not be the signer's master key.
    static json::Value
    singleContribution(
        json::Value const& inner,
        test::jtx::Account const& signer,
        test::jtx::Account const& keys)
    {
        STObject st = test::jtx::parse(inner);
        st.setFieldVL(sfSigningPubKey, keys.pk().slice());
        Serializer data;
        data.add32(HashPrefix::TxSign);
        st.addWithoutSigningFields(data);
        auto const sig = sign(keys.pk(), keys.sk(), data.slice());

        json::Value sj;
        sj[jss::Account] = signer.human();
        sj[jss::SigningPubKey] = strHex(keys.pk().slice());
        sj[sfTxnSignature.getJsonName()] = strHex(Slice{sig.data(), sig.size()});
        return sj;
    }

    static json::Value
    singleContribution(json::Value const& inner, test::jtx::Account const& signer)
    {
        return singleContribution(inner, signer, signer);
    }

    static json::Value
    proposalSign(
        test::jtx::Account const& submitter,
        uint256 const& proposalID,
        test::jtx::Account const& signingFor,
        json::Value const& signerContribution)
    {
        json::Value jv;
        jv[jss::TransactionType] = "TransactionProposalSign";
        jv[jss::Account] = submitter.human();
        jv[sfProposalID.getJsonName()] = to_string(proposalID);
        jv[sfSigningFor.getJsonName()] = signingFor.human();
        jv[sfSigner.getJsonName()] = signerContribution;
        return jv;
    }

    static json::Value
    proposalCancel(test::jtx::Account const& account, uint256 const& proposalID)
    {
        json::Value jv;
        jv[jss::TransactionType] = "TransactionProposalCancel";
        jv[jss::Account] = account.human();
        jv[sfProposalID.getJsonName()] = to_string(proposalID);
        return jv;
    }

    void
    testEnabled()
    {
        testcase("feature gate");
        using namespace test::jtx;
        using namespace std::chrono_literals;

        Env env{*this, testableAmendments() - featureCosigner};
        Account const alice{"alice"};
        Account const corp{"corp"};
        Account const dave{"dave"};
        env.fund(XRP(1000), alice, corp, dave);
        env.close();

        auto const inner = proposedPayment(corp, dave, XRP(10), env.seq(corp));
        env(proposalCreate(alice, inner, expAfter(env, 600s)), Ter(temDISABLED));

        auto const id = keylet::txProposal(alice.id(), corp.id(), env.seq(corp)).key;
        env(proposalSign(alice, id, corp, contribution(inner, alice)), Ter(temDISABLED));
        env(proposalCancel(alice, id), Ter(temDISABLED));
    }

    void
    testCreate()
    {
        testcase("create");
        using namespace test::jtx;
        using namespace std::chrono_literals;

        Env env{*this};
        Account const alice{"alice"};
        Account const corp{"corp"};
        Account const dave{"dave"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        env.fund(XRP(1000), alice, corp, dave, bob, carol);
        env(signers(corp, 2, {{bob, 1}, {carol, 1}}));
        env.close();

        std::uint32_t const innerSeq = env.seq(corp);
        auto const inner = proposedPayment(corp, dave, XRP(100), innerSeq);
        auto const expiration = expAfter(env, 600s);

        env(proposalCreate(alice, inner, expiration));
        env.close();

        auto const proposalKeylet = keylet::txProposal(alice.id(), corp.id(), innerSeq);
        auto const sleProposal = env.le(proposalKeylet);
        if (BEAST_EXPECT(sleProposal))
        {
            BEAST_EXPECT(sleProposal->getAccountID(sfOwner) == alice.id());
            BEAST_EXPECT(sleProposal->getFieldU32(sfExpiration) == expiration);
            auto const raw = sleProposal->getFieldObject(sfRawTransaction);
            BEAST_EXPECT(raw.getAccountID(sfAccount) == corp.id());
            BEAST_EXPECT(raw.getFieldU32(sfSequence) == innerSeq);
            BEAST_EXPECT(!raw.isFieldPresent(sfSigners));
        }
        // An ordinary proposal reserves 5 owner-count increments.
        env.require(Owners(alice, 5));

        // Same (owner, target, seq) again: tecDUPLICATE.
        env(proposalCreate(alice, inner, expiration), Ter(tecDUPLICATE));

        // A different owner may hold a proposal for the same target and seq.
        env(proposalCreate(dave, inner, expiration));
        env.close();
        BEAST_EXPECT(env.le(keylet::txProposal(dave.id(), corp.id(), innerSeq)));
    }

    void
    testCreateInvalid()
    {
        testcase("create invalid");
        using namespace test::jtx;
        using namespace std::chrono_literals;

        Env env{*this};
        Account const alice{"alice"};
        Account const corp{"corp"};
        Account const dave{"dave"};
        env.fund(XRP(1000), alice, corp, dave);
        env.close();

        std::uint32_t const innerSeq = env.seq(corp);
        auto const good = proposedPayment(corp, dave, XRP(100), innerSeq);
        auto const expiration = expAfter(env, 600s);

        // Zero expiration.
        env(proposalCreate(alice, good, 0), Ter(temBAD_EXPIRATION));

        // Expiration already passed.
        env(proposalCreate(alice, good, 1), Ter(tecEXPIRED));

        // Proposed txn carries a signature / signers / non-empty pubkey.
        {
            auto bad = good;
            bad[jss::SigningPubKey] = strHex(alice.pk().slice());
            env(proposalCreate(alice, bad, expiration), Ter(temBAD_SIGNER));
        }
        {
            auto bad = good;
            bad[jss::TxnSignature] = "00";
            env(proposalCreate(alice, bad, expiration), Ter(temBAD_SIGNER));
        }
        {
            auto bad = good;
            json::Value entry;
            entry[jss::Signer] = contribution(good, alice);
            bad[jss::Signers] = json::ValueType::Array;
            bad[jss::Signers].append(entry);
            env(proposalCreate(alice, bad, expiration), Ter(temBAD_SIGNER));
        }

        // Neither or both of Sequence / TicketSequence.
        {
            auto bad = good;
            bad[jss::Sequence] = 0;
            env(proposalCreate(alice, bad, expiration), Ter(temSEQ_AND_TICKET));
        }
        {
            auto bad = good;
            bad[sfTicketSequence.getJsonName()] = innerSeq + 1;
            env(proposalCreate(alice, bad, expiration), Ter(temSEQ_AND_TICKET));
        }

        // No nesting of proposals.
        {
            json::Value bad = proposalCancel(corp, uint256{42});
            bad[jss::Sequence] = innerSeq;
            bad[jss::Fee] = "100";
            bad[jss::SigningPubKey] = "";
            env(proposalCreate(alice, bad, expiration), Ter(temINVALID));
        }

        // No batch inner transactions.
        {
            auto bad = good;
            bad[jss::Flags] = tfInnerBatchTxn;
            env(proposalCreate(alice, bad, expiration), Ter(temINVALID));
        }

        // The proposed transaction must pass its own preflight: a payment to
        // self is statically invalid.
        {
            auto bad = proposedPayment(corp, corp, XRP(100), innerSeq);
            env(proposalCreate(alice, bad, expiration), Ter(temMALFORMED));
        }

        // LastLedgerSequence already passed.
        {
            auto bad = good;
            bad[jss::LastLedgerSequence] = 1;
            env(proposalCreate(alice, bad, expiration), Ter(tecEXPIRED));
        }

        // Target account does not exist.
        {
            Account const ghost{"ghost"};
            auto bad = proposedPayment(ghost, dave, XRP(100), 1);
            env(proposalCreate(alice, bad, expiration), Ter(tecNO_TARGET));
        }

        // Insufficient reserve for 5 owner-count increments.
        {
            Account const poor{"poor"};
            env.fund(env.current()->fees().accountReserve(2, 1), poor);
            env.close();
            env(proposalCreate(poor, good, expiration), Ter(tecINSUFFICIENT_RESERVE));
        }
    }

    void
    testSign()
    {
        testcase("sign");
        using namespace test::jtx;
        using namespace std::chrono_literals;

        Env env{*this};
        Account const alice{"alice"};
        Account const corp{"corp"};
        Account const dave{"dave"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        env.fund(XRP(1000), alice, corp, dave, bob, carol);
        env(signers(corp, 2, {{bob, 1}, {carol, 1}}));
        env.close();

        std::uint32_t const innerSeq = env.seq(corp);
        auto const inner = proposedPayment(corp, dave, XRP(100), innerSeq);
        env(proposalCreate(alice, inner, expAfter(env, 600s)));
        env.close();

        auto const proposalKeylet = keylet::txProposal(alice.id(), corp.id(), innerSeq);
        auto const id = proposalKeylet.key;

        // Unknown proposal.
        env(proposalSign(bob, uint256{7}, corp, contribution(inner, bob)), Ter(tecNO_ENTRY));

        // A non-signer cannot contribute.
        env(proposalSign(dave, id, corp, contribution(inner, dave)), Ter(tecNO_PERMISSION));

        // The submitter must be the contributing signer.
        env(proposalSign(bob, id, corp, contribution(inner, carol)), Ter(temMALFORMED));

        // A signature over different bytes does not verify.
        {
            auto const other = proposedPayment(corp, dave, XRP(999), innerSeq);
            env(proposalSign(bob, id, corp, contribution(other, bob)), Ter(tefBAD_SIGNATURE));
        }

        // Bob's valid contribution is recorded.
        env(proposalSign(bob, id, corp, contribution(inner, bob)));
        env.close();
        {
            auto const raw = env.le(proposalKeylet)->getFieldObject(sfRawTransaction);
            BEAST_EXPECT(raw.isFieldPresent(sfSigners) && raw.getFieldArray(sfSigners).size() == 1);
        }

        // Signing twice is rejected.
        env(proposalSign(bob, id, corp, contribution(inner, bob)), Ter(tecDUPLICATE));

        // Carol completes the quorum; the array is sorted by account.
        env(proposalSign(carol, id, corp, contribution(inner, carol)));
        env.close();
        {
            auto const raw = env.le(proposalKeylet)->getFieldObject(sfRawTransaction);
            auto const& signersArr = raw.getFieldArray(sfSigners);
            BEAST_EXPECT(signersArr.size() == 2);
            BEAST_EXPECT(
                signersArr[0].getAccountID(sfAccount) < signersArr[1].getAccountID(sfAccount));
        }
    }

    void
    testEndToEnd()
    {
        testcase("end to end: collect on-ledger, submit through the normal path");
        using namespace test::jtx;
        using namespace std::chrono_literals;

        Env env{*this};
        Account const alice{"alice"};
        Account const corp{"corp"};
        Account const dave{"dave"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        env.fund(XRP(1000), alice, corp, dave, bob, carol);
        env(signers(corp, 2, {{bob, 1}, {carol, 1}}));
        env.close();

        std::uint32_t const innerSeq = env.seq(corp);
        auto const inner = proposedPayment(corp, dave, XRP(100), innerSeq);
        env(proposalCreate(alice, inner, expAfter(env, 600s)));
        env.close();

        auto const proposalKeylet = keylet::txProposal(alice.id(), corp.id(), innerSeq);
        env(proposalSign(bob, proposalKeylet.key, corp, contribution(inner, bob)));
        env(proposalSign(carol, proposalKeylet.key, corp, contribution(inner, carol)));
        env.close();

        // Quorum reached: the stored transaction is fully signed. Copy it
        // verbatim and submit it through the ordinary transaction path.
        auto const daveBefore = env.balance(dave);
        json::Value const completed = env.le(proposalKeylet)
                                          ->getFieldObject(sfRawTransaction)
                                          .getJson(JsonOptions::Values::None);

        env(completed, Fee(kNone), Seq(kNone), Sig(kNone));
        env.close();

        BEAST_EXPECT(env.balance(dave) == daveBefore + XRP(100));
        BEAST_EXPECT(env.seq(corp) == innerSeq + 1);

        // The consumed sequence makes re-submission impossible.
        env(completed, Fee(kNone), Seq(kNone), Sig(kNone), Ter(tefPAST_SEQ));

        // The proposal object survives execution (no auto-cleanup in v1);
        // the owner cancels it to reclaim the reserve.
        BEAST_EXPECT(env.le(proposalKeylet));
        env(proposalCancel(alice, proposalKeylet.key));
        env.close();
        BEAST_EXPECT(!env.le(proposalKeylet));
        env.require(Owners(alice, 0));
    }

    void
    testTicketProposal()
    {
        testcase("ticket-based proposal");
        using namespace test::jtx;
        using namespace std::chrono_literals;

        Env env{*this};
        Account const alice{"alice"};
        Account const corp{"corp"};
        Account const dave{"dave"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        env.fund(XRP(1000), alice, corp, dave, bob, carol);
        env(signers(corp, 2, {{bob, 1}, {carol, 1}}));
        env.close();

        std::uint32_t const ticketSeq = env.seq(corp) + 1;
        env(ticket::create(corp, 1));
        env.close();

        json::Value inner = proposedPayment(corp, dave, XRP(100), 0);
        inner[sfTicketSequence.getJsonName()] = ticketSeq;

        env(proposalCreate(alice, inner, expAfter(env, 600s)));
        env.close();

        auto const proposalKeylet = keylet::txProposal(alice.id(), corp.id(), ticketSeq);
        BEAST_EXPECT(env.le(proposalKeylet));

        env(proposalSign(bob, proposalKeylet.key, corp, contribution(inner, bob)));
        env(proposalSign(carol, proposalKeylet.key, corp, contribution(inner, carol)));
        env.close();

        auto const daveBefore = env.balance(dave);
        json::Value const completed = env.le(proposalKeylet)
                                          ->getFieldObject(sfRawTransaction)
                                          .getJson(JsonOptions::Values::None);
        env(completed, Fee(kNone), Seq(kNone), Sig(kNone));
        env.close();

        BEAST_EXPECT(env.balance(dave) == daveBefore + XRP(100));
        // The ticket is consumed.
        BEAST_EXPECT(!env.le(keylet::ticket(corp.id(), ticketSeq)));

        env(proposalCancel(alice, proposalKeylet.key));
    }

    void
    testExpiration()
    {
        testcase("expiration");
        using namespace test::jtx;
        using namespace std::chrono_literals;

        Env env{*this};
        Account const alice{"alice"};
        Account const corp{"corp"};
        Account const dave{"dave"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        env.fund(XRP(1000), alice, corp, dave, bob, carol);
        env(signers(corp, 2, {{bob, 1}, {carol, 1}}));
        env.close();

        std::uint32_t const innerSeq = env.seq(corp);
        auto const inner = proposedPayment(corp, dave, XRP(100), innerSeq);
        env(proposalCreate(alice, inner, expAfter(env, 60s)));
        env.close();

        auto const proposalKeylet = keylet::txProposal(alice.id(), corp.id(), innerSeq);

        // While live, a stranger may not cancel.
        env(proposalCancel(dave, proposalKeylet.key), Ter(tecNO_PERMISSION));

        // Let the proposal expire.
        env.close(env.now() + 120s);

        // A terminal proposal no longer accepts signatures, and is not
        // deleted by the failed attempt (no tec-with-cleanup in v1).
        env(proposalSign(bob, proposalKeylet.key, corp, contribution(inner, bob)), Ter(tecEXPIRED));
        env.close();
        BEAST_EXPECT(env.le(proposalKeylet));

        // Anyone may cancel a terminal proposal, releasing the reserve.
        env(proposalCancel(dave, proposalKeylet.key));
        env.close();
        BEAST_EXPECT(!env.le(proposalKeylet));
        env.require(Owners(alice, 0));
    }

    void
    testOwnerCancelLive()
    {
        testcase("owner cancels a live proposal");
        using namespace test::jtx;
        using namespace std::chrono_literals;

        Env env{*this};
        Account const alice{"alice"};
        Account const corp{"corp"};
        Account const dave{"dave"};
        env.fund(XRP(1000), alice, corp, dave);
        env.close();

        std::uint32_t const innerSeq = env.seq(corp);
        auto const inner = proposedPayment(corp, dave, XRP(100), innerSeq);
        env(proposalCreate(alice, inner, expAfter(env, 600s)));
        env.close();
        env.require(Owners(alice, 5));

        auto const proposalKeylet = keylet::txProposal(alice.id(), corp.id(), innerSeq);
        env(proposalCancel(alice, proposalKeylet.key));
        env.close();
        BEAST_EXPECT(!env.le(proposalKeylet));
        env.require(Owners(alice, 0));

        // Cancelling a non-existent proposal.
        env(proposalCancel(alice, proposalKeylet.key), Ter(tecNO_ENTRY));
    }

    void
    testDelegateProposal()
    {
        testcase("delegate-authorized proposal");
        using namespace test::jtx;
        using namespace std::chrono_literals;

        Env env{*this};
        Account const alice{"alice"};
        Account const corp{"corp"};
        Account const del{"del"};
        Account const dave{"dave"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        Account const edgar{"edgar"};
        env.fund(XRP(1000), alice, corp, del, dave, bob, carol, edgar);
        // The delegate's SignerList authorizes the collected signatures; the
        // target's own list must play no part.
        env(signers(del, 2, {{bob, 1}, {carol, 1}}));
        env(signers(corp, 1, {{edgar, 1}}));
        env(delegate::set(corp, del, {"Payment"}));
        env.close();

        // A transaction may not delegate to its own account; the inner
        // preflight at create time rejects the stored form outright.
        {
            auto bad = proposedPayment(corp, dave, XRP(100), env.seq(corp));
            bad[sfDelegate.getJsonName()] = corp.human();
            env(proposalCreate(alice, bad, expAfter(env, 600s)), Ter(temMALFORMED));
        }

        std::uint32_t const innerSeq = env.seq(corp);
        json::Value inner = proposedPayment(corp, dave, XRP(100), innerSeq);
        inner[sfDelegate.getJsonName()] = del.human();
        env(proposalCreate(alice, inner, expAfter(env, 600s)));
        env.close();

        auto const proposalKeylet = keylet::txProposal(alice.id(), corp.id(), innerSeq);
        BEAST_EXPECT(env.le(proposalKeylet));

        // Membership runs against the delegate's SignerList, not the
        // target's: edgar is a signer for corp but not for del.
        env(proposalSign(edgar, proposalKeylet.key, del, contribution(inner, edgar)),
            Ter(tecNO_PERMISSION));

        env(proposalSign(bob, proposalKeylet.key, del, contribution(inner, bob)));
        env(proposalSign(carol, proposalKeylet.key, del, contribution(inner, carol)));
        env.close();

        auto const daveBefore = env.balance(dave);
        auto const corpBefore = env.balance(corp);
        auto const delBefore = env.balance(del);
        json::Value const completed = env.le(proposalKeylet)
                                          ->getFieldObject(sfRawTransaction)
                                          .getJson(JsonOptions::Values::None);
        env(completed, Fee(kNone), Seq(kNone), Sig(kNone));
        env.close();

        BEAST_EXPECT(env.balance(dave) == daveBefore + XRP(100));
        BEAST_EXPECT(env.seq(corp) == innerSeq + 1);
        // The target pays the amount; the delegate pays the fee.
        BEAST_EXPECT(env.balance(corp) == corpBefore - XRP(100));
        BEAST_EXPECT(env.balance(del) == delBefore - drops(100));

        env(proposalCancel(alice, proposalKeylet.key));
    }

    void
    testSignKeyBinding()
    {
        testcase("sign key binding: regular key and disabled master");
        using namespace test::jtx;
        using namespace std::chrono_literals;

        Env env{*this};
        Account const alice{"alice"};
        Account const corp{"corp"};
        Account const dave{"dave"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        Account const bobr{"bobr"};
        Account const mallory{"mallory"};
        env.fund(XRP(1000), alice, corp, dave, bob, carol);
        env(signers(corp, 2, {{bob, 1}, {carol, 1}}));
        env(regkey(bob, bobr));
        env(fset(bob, asfDisableMaster), Sig(bob));
        env.close();

        std::uint32_t const innerSeq = env.seq(corp);
        auto const inner = proposedPayment(corp, dave, XRP(100), innerSeq);
        env(proposalCreate(alice, inner, expAfter(env, 600s)));
        env.close();

        auto const proposalKeylet = keylet::txProposal(alice.id(), corp.id(), innerSeq);
        auto const id = proposalKeylet.key;

        // Bob's master key is disabled: a master-key contribution is
        // rejected even though the outer submission (via regular key) is
        // perfectly valid.
        env(proposalSign(bob, id, corp, contribution(inner, bob, bob)),
            Sig(bobr),
            Ter(tefMASTER_DISABLED));

        // A key unrelated to the signer never binds, with or without a
        // regular key on the account.
        env(proposalSign(bob, id, corp, contribution(inner, bob, mallory)),
            Sig(bobr),
            Ter(tefBAD_SIGNATURE));
        env(proposalSign(carol, id, corp, contribution(inner, carol, mallory)),
            Ter(tefBAD_SIGNATURE));

        // Bob contributes through his regular key; carol through her master.
        env(proposalSign(bob, id, corp, contribution(inner, bob, bobr)), Sig(bobr));
        env(proposalSign(carol, id, corp, contribution(inner, carol)));
        env.close();

        // The mixed-key collection satisfies the ordinary submission path.
        auto const daveBefore = env.balance(dave);
        json::Value const completed = env.le(proposalKeylet)
                                          ->getFieldObject(sfRawTransaction)
                                          .getJson(JsonOptions::Values::None);
        env(completed, Fee(kNone), Seq(kNone), Sig(kNone));
        env.close();
        BEAST_EXPECT(env.balance(dave) == daveBefore + XRP(100));
        BEAST_EXPECT(env.seq(corp) == innerSeq + 1);
    }

public:
    void
    run() override
    {
        testEnabled();
        testCreate();
        testCreateInvalid();
        testSign();
        testEndToEnd();
        testTicketProposal();
        testExpiration();
        testOwnerCancelLive();
        testDelegateProposal();
        testSignKeyBinding();
    }
};

BEAST_DEFINE_TESTSUITE(Cosigner, app, xrpl);

}  // namespace xrpl
