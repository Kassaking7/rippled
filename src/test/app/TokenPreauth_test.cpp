#include <test/jtx/AMM.h>
#include <test/jtx/Account.h>
#include <test/jtx/Env.h>
#include <test/jtx/TestHelpers.h>
#include <test/jtx/acctdelete.h>
#include <test/jtx/amount.h>
#include <test/jtx/check.h>
#include <test/jtx/delegate.h>
#include <test/jtx/escrow.h>
#include <test/jtx/fee.h>
#include <test/jtx/mpt.h>
#include <test/jtx/offer.h>
#include <test/jtx/pay.h>
#include <test/jtx/ter.h>
#include <test/jtx/vault.h>

#include <xrpl/basics/base_uint.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/json/json_value.h>
#include <xrpl/json/to_string.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/Issue.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/UintTypes.h>
#include <xrpl/protocol/jss.h>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

namespace xrpl::test {

class TokenPreauth_test : public beast::unit_test::Suite
{
    static json::Value
    tokenTx(
        json::StaticString const& txType,
        jtx::Account const& issuer,
        jtx::Account const& holder,
        MPTID const& issuanceID,
        std::uint32_t flags)
    {
        json::Value jv;
        jv[jss::TransactionType] = txType;
        jv[jss::Account] = issuer.human();
        jv[sfHolder.jsonName] = holder.human();
        jv[sfMPTokenIssuanceID.jsonName] = to_string(issuanceID);
        jv[jss::Flags] = flags;
        return jv;
    }

    // Pre-authorizes holder, or with tfUnauthorize removes the
    // pre-authorization.
    static json::Value
    tokenPreauth(
        jtx::Account const& issuer,
        jtx::Account const& holder,
        MPTID const& issuanceID,
        std::uint32_t flags = 0)
    {
        return tokenTx(jss::TokenPreauth, issuer, holder, issuanceID, flags);
    }

    // Blocks holder, or with tfUnblock removes the block.
    static json::Value
    tokenBlock(
        jtx::Account const& issuer,
        jtx::Account const& holder,
        MPTID const& issuanceID,
        std::uint32_t flags = 0)
    {
        return tokenTx(jss::TokenBlock, issuer, holder, issuanceID, flags);
    }

    static bool
    isPreauthorized(jtx::Env& env, jtx::Account const& holder, MPTID const& issuanceID)
    {
        return static_cast<bool>(env.le(keylet::tokenPreauth(holder, issuanceID)));
    }

    static bool
    isBlocked(jtx::Env& env, jtx::Account const& holder, MPTID const& issuanceID)
    {
        return static_cast<bool>(env.le(keylet::tokenBlock(holder, issuanceID)));
    }

    static bool
    hasMPToken(jtx::Env& env, jtx::Account const& holder, MPTID const& issuanceID)
    {
        return static_cast<bool>(env.le(keylet::mptoken(issuanceID, holder)));
    }

    static bool
    isLocked(jtx::Env& env, jtx::Account const& holder, MPTID const& issuanceID)
    {
        auto const sle = env.le(keylet::mptoken(issuanceID, holder));
        return sle && sle->isFlag(lsfMPTLocked);
    }

    void
    testDisabled(FeatureBitset features)
    {
        testcase("Amendment disabled");
        using namespace jtx;

        Env env{*this, features - featureTokenPreauth};
        Account const gw{"gw"};
        Account const alice{"alice"};
        MPTTester mpt(env, gw, {.holders = {alice}});
        mpt.create({.flags = tfMPTCanLock});

        env(tokenBlock(gw, alice, mpt.issuanceID()), Ter(temDISABLED));
        env.close();

        // Opting in is unaffected.
        mpt.authorize({.account = alice});
        BEAST_EXPECT(hasMPToken(env, alice, mpt.issuanceID()));
    }

    void
    testPreflight(FeatureBitset features)
    {
        testcase("Preflight");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        MPTTester mpt(env, gw, {.holders = {alice}});
        mpt.create({.flags = tfMPTCanLock});
        auto const id = mpt.issuanceID();

        // Each transaction has a single flag; anything else is unknown.
        env(tokenPreauth(gw, alice, id, 0x00000002), Ter(temINVALID_FLAG));
        env(tokenPreauth(gw, alice, id, tfUnauthorize | 0x00000002), Ter(temINVALID_FLAG));
        env(tokenBlock(gw, alice, id, 0x00000002), Ter(temINVALID_FLAG));
        env(tokenBlock(gw, alice, id, tfUnblock | 0x00000002), Ter(temINVALID_FLAG));

        // Issuer may not name itself.
        env(tokenPreauth(gw, gw, id), Ter(temMALFORMED));
        env(tokenBlock(gw, gw, id), Ter(temMALFORMED));
        env(tokenPreauth(gw, gw, id, tfUnauthorize), Ter(temMALFORMED));
        env(tokenBlock(gw, gw, id, tfUnblock), Ter(temMALFORMED));
    }

    void
    testPreclaim(FeatureBitset features)
    {
        testcase("Preclaim");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const ghost{"ghost"};
        MPTTester mpt(env, gw, {.holders = {alice, bob}});
        mpt.create({.flags = tfMPTCanLock});
        auto const id = mpt.issuanceID();

        // Issuance must exist.
        MPTID const missing = makeMptID(env.seq(gw) + 10, gw);
        env(tokenBlock(gw, alice, missing), Ter(tecOBJECT_NOT_FOUND));
        env(tokenPreauth(gw, alice, missing), Ter(tecOBJECT_NOT_FOUND));

        // Only the issuer may act on its issuance.
        env(tokenBlock(bob, alice, id), Ter(tecNO_PERMISSION));
        env(tokenPreauth(bob, alice, id), Ter(tecNO_PERMISSION));

        // Nothing to remove.
        env(tokenBlock(gw, alice, id, tfUnblock), Ter(tecNO_ENTRY));
        env(tokenPreauth(gw, alice, id, tfUnauthorize), Ter(tecNO_ENTRY));

        // Pre-authorizing needs an existing account; blocking does not.
        env(tokenPreauth(gw, ghost, id), Ter(tecNO_DST));
        env(tokenBlock(gw, ghost, id));
        env.close();
        BEAST_EXPECT(isBlocked(env, ghost, id));

        // The entry's key does not include the issuer (the issuance ID
        // already does), so removal checks it explicitly.
        env(tokenBlock(bob, ghost, id, tfUnblock), Ter(tecNO_PERMISSION));
        env(tokenPreauth(gw, bob, id));
        env(tokenPreauth(alice, bob, id, tfUnauthorize), Ter(tecNO_PERMISSION));
        env.close();
        BEAST_EXPECT(isBlocked(env, ghost, id));
        BEAST_EXPECT(isPreauthorized(env, bob, id));

        // Pseudo-accounts can not be blocked or pre-authorized.
        {
            MPTTester dex(env, gw, {.holders = {alice}, .fund = false});
            dex.create({.flags = tfMPTCanLock | kMptDexFlags});
            dex.authorize({.account = alice});
            dex.pay(gw, alice, 1'000);
            AMM const amm(env, alice, MPT(dex)(100), XRP(100));
            env.close();
            Account const ammAccount{"amm", amm.ammAccount()};
            env(tokenBlock(gw, ammAccount, dex.issuanceID()), Ter(tecPSEUDO_ACCOUNT));
            env(tokenPreauth(gw, ammAccount, dex.issuanceID()), Ter(tecPSEUDO_ACCOUNT));
        }

        // A block does not lock, so it does not need an issuance that allows
        // locking.
        {
            MPTTester noLock(env, gw, {.holders = {alice, bob}, .fund = false});
            noLock.create({.flags = 0});
            noLock.authorize({.account = alice});
            env(tokenBlock(gw, alice, noLock.issuanceID()));
            env(tokenBlock(gw, bob, noLock.issuanceID()));
            env(tokenBlock(gw, ghost, noLock.issuanceID()));
            env.close();
            BEAST_EXPECT(isBlocked(env, alice, noLock.issuanceID()));
            BEAST_EXPECT(isBlocked(env, bob, noLock.issuanceID()));
            BEAST_EXPECT(isBlocked(env, ghost, noLock.issuanceID()));
            BEAST_EXPECT(!isLocked(env, alice, noLock.issuanceID()));
        }
    }

    void
    testStateMachine(FeatureBitset features)
    {
        testcase("State machine");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        MPTTester mpt(env, gw, {.holders = {alice}});
        mpt.create({.flags = tfMPTCanLock});
        auto const id = mpt.issuanceID();
        auto const baseOwners = env.ownerCount(gw);

        // A holder is never both pre-authorized and blocked.
        auto const state = [&] -> std::string {
            bool const preauthorized = isPreauthorized(env, alice, id);
            bool const blocked = isBlocked(env, alice, id);
            BEAST_EXPECT(!(preauthorized && blocked));
            if (blocked)
                return "blocked";
            return preauthorized ? "preauthorized" : "none";
        };

        // none -> Authorized
        env(tokenPreauth(gw, alice, id));
        env.close();
        BEAST_EXPECT(state() == "preauthorized");
        BEAST_EXPECT(env.ownerCount(gw) == baseOwners + 1);

        env(tokenPreauth(gw, alice, id), Ter(tecDUPLICATE));
        env(tokenBlock(gw, alice, id, tfUnblock), Ter(tecNO_ENTRY));

        // Pre-authorized -> blocked: the block replaces the pre-authorization,
        // so the reserve is unchanged.
        env(tokenBlock(gw, alice, id));
        env.close();
        BEAST_EXPECT(state() == "blocked");
        BEAST_EXPECT(env.ownerCount(gw) == baseOwners + 1);

        env(tokenBlock(gw, alice, id), Ter(tecDUPLICATE));
        // An authorize-only action never clears a block.
        env(tokenPreauth(gw, alice, id), Ter(tecNO_PERMISSION));
        env(tokenPreauth(gw, alice, id, tfUnauthorize), Ter(tecNO_ENTRY));
        env.close();
        BEAST_EXPECT(state() == "blocked");

        // Blocked -> none
        env(tokenBlock(gw, alice, id, tfUnblock));
        env.close();
        BEAST_EXPECT(state() == "none");
        BEAST_EXPECT(env.ownerCount(gw) == baseOwners);

        // none -> Blocked -> none, and none -> Authorized -> none
        env(tokenBlock(gw, alice, id));
        env.close();
        BEAST_EXPECT(state() == "blocked");
        env(tokenBlock(gw, alice, id, tfUnblock));
        env(tokenPreauth(gw, alice, id));
        env.close();
        BEAST_EXPECT(state() == "preauthorized");
        env(tokenPreauth(gw, alice, id, tfUnauthorize));
        env.close();
        BEAST_EXPECT(state() == "none");
        BEAST_EXPECT(env.ownerCount(gw) == baseOwners);
    }
    void
    testBlockOptIn(FeatureBitset features)
    {
        testcase("Blocked account can not opt in (PRD R1, R2)");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        Account const bob{"bob"};
        // Permissionless issuance: no RequireAuth.
        MPTTester mpt(env, gw, {.holders = {alice, bob}});
        mpt.create({.flags = tfMPTCanLock | tfMPTCanTransfer});
        auto const id = mpt.issuanceID();

        env(tokenBlock(gw, alice, id));
        env.close();

        // Hard fail with the dedicated code; no MPToken is created.
        mpt.authorize({.account = alice, .err = tecTOKEN_BLOCKED});
        BEAST_EXPECT(!hasMPToken(env, alice, id));

        // Everyone else still opts in freely.
        mpt.authorize({.account = bob});
        mpt.pay(gw, bob, 100);

        // The blocked account can not be paid either: it has no holding.
        mpt.pay(gw, alice, 100, tecTOKEN_BLOCKED);
        mpt.pay(bob, alice, 10, tecTOKEN_BLOCKED);

        // Removing the entry restores the ability to opt in, effective in the
        // next ledger.
        env(tokenBlock(gw, alice, id, tfUnblock));
        env.close();
        mpt.authorize({.account = alice});
        mpt.pay(gw, alice, 100);
        BEAST_EXPECT(mpt.getBalance(alice) == 100);
    }

    void
    testBlockBeforeAccountExists(FeatureBitset features)
    {
        testcase("Block an address before it is funded");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const sanctioned{"sanctioned"};
        MPTTester mpt(env, gw);
        mpt.create({.flags = tfMPTCanLock});
        auto const id = mpt.issuanceID();

        env(tokenBlock(gw, sanctioned, id));
        env.close();

        // Funding the address does not open a window to opt in.
        env.fund(XRP(1'000), sanctioned);
        env.close();
        MPTTester(env, gw, id, {sanctioned}, true)
            .authorize({.account = sanctioned, .err = tecTOKEN_BLOCKED});
        BEAST_EXPECT(!hasMPToken(env, sanctioned, id));
    }

    void
    testBlockExistingHolder(FeatureBitset features)
    {
        testcase("Blocking an existing holder does not freeze it");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        Account const bob{"bob"};
        MPTTester mpt(env, gw, {.holders = {alice, bob}});
        mpt.create({.flags = tfMPTCanLock | tfMPTCanTransfer | tfMPTCanClawback});
        auto const id = mpt.issuanceID();
        mpt.authorize({.account = alice});
        mpt.authorize({.account = bob});
        mpt.pay(gw, alice, 1'000);
        mpt.pay(gw, bob, 1'000);

        // Pre-authorized and holding; blocking flips the entry.
        env(tokenPreauth(gw, alice, id));
        env(tokenBlock(gw, alice, id));
        env.close();
        BEAST_EXPECT(isBlocked(env, alice, id));
        BEAST_EXPECT(!isPreauthorized(env, alice, id));

        // A block only stops a holding from being created: the existing one
        // is not locked, and its balance still moves both ways.
        BEAST_EXPECT(!isLocked(env, alice, id));
        BEAST_EXPECT(mpt.getBalance(alice) == 1'000);
        mpt.pay(alice, bob, 10);
        mpt.pay(bob, alice, 10);

        // Freezing it is Lock, a separate issuer action that the block does
        // not restrict in either direction.
        mpt.set({.holder = alice, .flags = tfMPTLock});
        mpt.pay(alice, bob, 10, tecPATH_DRY);
        mpt.pay(bob, alice, 10, tecPATH_DRY);
        mpt.set({.holder = alice, .flags = tfMPTUnlock});
        mpt.pay(alice, bob, 10);

        // Clawback is unchanged and still seizes the balance.
        mpt.claw(gw, alice, 400);
        BEAST_EXPECT(mpt.getBalance(alice) == 590);

        // Unblocking leaves the holding as it is.
        env(tokenBlock(gw, alice, id, tfUnblock));
        env.close();
        BEAST_EXPECT(!isBlocked(env, alice, id));
        mpt.pay(alice, bob, 10);
    }

    void
    testBlockedHolderCanExit(FeatureBitset features)
    {
        testcase("Blocked holder can delete an empty MPToken, but not re-create it");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        MPTTester mpt(env, gw, {.holders = {alice}});
        mpt.create({.flags = tfMPTCanLock | tfMPTCanClawback});
        auto const id = mpt.issuanceID();
        mpt.authorize({.account = alice});
        mpt.pay(gw, alice, 100);

        // Blocked, and locked by a separate issuer action.
        env(tokenBlock(gw, alice, id));
        mpt.set({.holder = alice, .flags = tfMPTLock});
        env.close();
        BEAST_EXPECT(isLocked(env, alice, id));

        // Non-zero balance: the usual obligation check still applies.
        mpt.authorize({.account = alice, .flags = tfMPTUnauthorize, .err = tecHAS_OBLIGATIONS});

        mpt.claw(gw, alice, 100);
        auto const aliceOwners = env.ownerCount(alice);

        // Zero balance: allowed even though the MPToken is locked, so the
        // holder can recover its reserve.
        mpt.authorize({.account = alice, .flags = tfMPTUnauthorize});
        BEAST_EXPECT(!hasMPToken(env, alice, id));
        BEAST_EXPECT(env.ownerCount(alice) == aliceOwners - 1);

        // Deleting and re-creating is not a way around the lock.
        mpt.authorize({.account = alice, .err = tecTOKEN_BLOCKED});
        BEAST_EXPECT(!hasMPToken(env, alice, id));

        // A locked but *unblocked* holder still can not delete (unchanged).
        Account const bob{"bob"};
        env.fund(XRP(1'000), bob);
        env.close();
        MPTTester m2(env, gw, id, {bob}, true);
        m2.authorize({.account = bob});
        m2.set({.holder = bob, .flags = tfMPTLock});
        m2.authorize({.account = bob, .flags = tfMPTUnauthorize, .err = tecNO_PERMISSION});
    }

    void
    testRequireAuth(FeatureBitset features)
    {
        testcase("RequireAuth issuance: pre-authorization and block");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        MPTTester mpt(env, gw, {.holders = {alice, bob, carol}});
        mpt.create({.flags = tfMPTCanLock | tfMPTRequireAuth});
        auto const id = mpt.issuanceID();

        // Pre-authorized: one holder transaction, no issuer follow-up.
        env(tokenPreauth(gw, alice, id));
        env.close();
        mpt.authorize({.account = alice});
        BEAST_EXPECT(mpt.checkFlags(lsfMPTAuthorized, alice));
        mpt.pay(gw, alice, 100);

        // Not pre-authorized: the classic two-step flow still works.
        mpt.authorize({.account = bob});
        BEAST_EXPECT(mpt.checkFlags(0, bob));
        mpt.pay(gw, bob, 100, tecNO_AUTH);
        mpt.authorize({.account = gw, .holder = bob});
        mpt.pay(gw, bob, 100);

        // The issuer can not approve a blocked holder ...
        mpt.authorize({.account = carol});
        env(tokenBlock(gw, carol, id));
        env.close();
        mpt.authorize({.account = gw, .holder = carol, .err = tecTOKEN_BLOCKED});
        // Blocking an authorized holder revokes its authorization, without
        // locking it, and the issuer can not re-authorize it while blocked.
        env(tokenBlock(gw, alice, id));
        env.close();
        BEAST_EXPECT(mpt.checkFlags(0, alice));
        mpt.pay(gw, alice, 1, tecNO_AUTH);
        mpt.authorize({.account = gw, .holder = alice, .err = tecTOKEN_BLOCKED});
        // Revoking is still allowed (and here a no-op).
        mpt.authorize({.account = gw, .holder = alice, .flags = tfMPTUnauthorize});
        BEAST_EXPECT(mpt.checkFlags(0, alice));

        // Unblocking does not restore the authorization: reinstating the
        // holder is unblock, then re-authorize.
        env(tokenBlock(gw, alice, id, tfUnblock));
        env.close();
        BEAST_EXPECT(mpt.checkFlags(0, alice));
        mpt.pay(gw, alice, 1, tecNO_AUTH);
        mpt.authorize({.account = gw, .holder = alice});
        BEAST_EXPECT(mpt.checkFlags(lsfMPTAuthorized, alice));
        mpt.pay(gw, alice, 1);

        // A block also replaces a pre-authorization and revokes the
        // authorization it granted.
        Account const frank{"frank"};
        env.fund(XRP(1'000), frank);
        env.close();
        MPTTester m4(env, gw, id, {frank}, true);
        env(tokenPreauth(gw, frank, id));
        env.close();
        m4.authorize({.account = frank});
        BEAST_EXPECT(m4.checkFlags(lsfMPTAuthorized, frank));
        env(tokenBlock(gw, frank, id));
        env.close();
        BEAST_EXPECT(!isPreauthorized(env, frank, id));
        BEAST_EXPECT(m4.checkFlags(0, frank));

        // The block check comes first, so it applies even to an address that
        // has no account yet.
        Account const ghost{"ghost"};
        env(tokenBlock(gw, ghost, id));
        env.close();
        mpt.authorize({.account = gw, .holder = ghost, .err = tecTOKEN_BLOCKED});

        // Removing a pre-authorization does not revoke an authorized MPToken.
        Account const dave{"dave"};
        env.fund(XRP(1'000), dave);
        env.close();
        MPTTester m2(env, gw, id, {dave}, true);
        env(tokenPreauth(gw, dave, id));
        env.close();
        m2.authorize({.account = dave});
        env(tokenPreauth(gw, dave, id, tfUnauthorize));
        env.close();
        BEAST_EXPECT(m2.checkFlags(lsfMPTAuthorized, dave));

        // Pre-authorizing a holder who already opted in authorizes them right
        // away: they have no later transaction that would pick it up.
        Account const erin{"erin"};
        env.fund(XRP(1'000), erin);
        env.close();
        MPTTester m3(env, gw, id, {erin}, true);
        m3.authorize({.account = erin});
        BEAST_EXPECT(m3.checkFlags(0, erin));
        m3.pay(gw, erin, 100, tecNO_AUTH);
        env(tokenPreauth(gw, erin, id));
        env.close();
        BEAST_EXPECT(m3.checkFlags(lsfMPTAuthorized, erin));
        m3.pay(gw, erin, 100);
    }

    void
    testPermissionlessPreauthIsNoop(FeatureBitset features)
    {
        testcase("Pre-authorization is a no-op without RequireAuth");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        MPTTester mpt(env, gw, {.holders = {alice}});
        mpt.create({.flags = tfMPTCanLock});
        auto const id = mpt.issuanceID();

        env(tokenPreauth(gw, alice, id));
        env.close();
        mpt.authorize({.account = alice});
        BEAST_EXPECT(mpt.checkFlags(0, alice));
        mpt.pay(gw, alice, 100);

        // Same when the holder opted in first.
        Account const bob{"bob"};
        env.fund(XRP(1'000), bob);
        env.close();
        MPTTester m2(env, gw, id, {bob}, true);
        m2.authorize({.account = bob});
        env(tokenPreauth(gw, bob, id));
        env.close();
        BEAST_EXPECT(m2.checkFlags(0, bob));
    }
    void
    testDexCannotBypass(FeatureBitset features)
    {
        testcase("DEX offer crossing can not create a holding for a blocked account");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        Account const carol{"carol"};
        MPTTester mpt(env, gw, {.holders = {alice, carol}});
        mpt.create({.flags = tfMPTCanLock | kMptDexFlags});
        auto const id = mpt.issuanceID();
        mpt.authorize({.account = alice});
        mpt.pay(gw, alice, 1'000);
        MPT const token = mpt;

        // carol has no MPToken; with MPTokensV2 an offer to buy one is fine
        // and crossing would create the holding.
        env(offer(carol, token(100), XRP(100)));
        env.close();
        BEAST_EXPECT(env.ownerCount(carol) == 1);

        env(tokenBlock(gw, carol, id));
        env.close();

        // alice sells into carol's standing offer: the offer is removed as
        // unfunded-for-auth instead of crossing.
        env(offer(alice, XRP(100), token(100)));
        env.close();
        BEAST_EXPECT(!hasMPToken(env, carol, id));
        BEAST_EXPECT(env.ownerCount(carol) == 0);
        BEAST_EXPECT(mpt.getBalance(alice) == 1'000);

        // carol can not place a new offer to acquire the token either, as
        // maker or as taker against alice's resting offer.
        env(offer(carol, token(100), XRP(100)), Ter(tecTOKEN_BLOCKED));
        env.close();
        BEAST_EXPECT(!hasMPToken(env, carol, id));
    }

    void
    testCheckCannotBypass(FeatureBitset features)
    {
        testcase("CheckCash can not create a holding for a blocked account");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        Account const carol{"carol"};
        MPTTester mpt(env, gw, {.holders = {alice, carol}});
        mpt.create({.flags = tfMPTCanLock | tfMPTCanTransfer});
        auto const id = mpt.issuanceID();
        mpt.authorize({.account = alice});
        mpt.pay(gw, alice, 1'000);
        MPT const token = mpt;

        UInt256 const fromHolder = getCheckIndex(alice, env.seq(alice));
        env(check::create(alice, carol, token(50)));
        UInt256 const fromIssuer = getCheckIndex(gw, env.seq(gw));
        env(check::create(gw, carol, token(50)));
        env.close();

        env(tokenBlock(gw, carol, id));
        env.close();

        env(check::cash(carol, fromHolder, token(50)), Ter(tecTOKEN_BLOCKED));
        env(check::cash(carol, fromIssuer, token(50)), Ter(tecTOKEN_BLOCKED));
        env.close();
        BEAST_EXPECT(!hasMPToken(env, carol, id));

        // Like any account that can not yet hold the token, a blocked one can
        // still be written a check; it just can never cash it.
        UInt256 const later = getCheckIndex(alice, env.seq(alice));
        env(check::create(alice, carol, token(50)));
        env.close();
        env(check::cash(carol, later, token(50)), Ter(tecTOKEN_BLOCKED));
        BEAST_EXPECT(!hasMPToken(env, carol, id));
    }

    void
    testEscrowCannotBypass(FeatureBitset features)
    {
        testcase("EscrowFinish can not create a holding for a blocked account");
        using namespace jtx;
        using namespace std::chrono_literals;

        Env env{*this, features};
        auto const baseFee = env.current()->fees().base;
        Account const gw{"gw"};
        Account const alice{"alice"};
        Account const carol{"carol"};
        MPTTester mpt(env, gw, {.holders = {alice, carol}});
        mpt.create({.flags = tfMPTCanLock | tfMPTCanEscrow | tfMPTCanTransfer});
        auto const id = mpt.issuanceID();
        mpt.authorize({.account = alice});
        mpt.pay(gw, alice, 1'000);
        MPT const token = mpt;

        auto const seq = env.seq(alice);
        env(escrow::create(alice, carol, token(100)),
            escrow::kFinishTime(env.now() + 1s),
            escrow::kCancelTime(env.now() + 10s),
            Fee(baseFee * 150));
        env.close();

        env(tokenBlock(gw, carol, id));
        env.close();

        env(escrow::finish(carol, alice, seq), Fee(baseFee * 150), Ter(tecTOKEN_BLOCKED));
        env.close();
        BEAST_EXPECT(!hasMPToken(env, carol, id));

        // New escrows to the blocked account are rejected up front.
        env(escrow::create(alice, carol, token(100)),
            escrow::kFinishTime(env.now() + 1s),
            Fee(baseFee * 150),
            Ter(tecTOKEN_BLOCKED));

        // The sender recovers the funds when the escrow expires.
        env.close(10s);
        env(escrow::cancel(alice, alice, seq), Fee(baseFee * 150));
        env.close();
        BEAST_EXPECT(mpt.getBalance(alice) == 1'000);
    }

    void
    testAMMWithdrawCannotBypass(FeatureBitset features)
    {
        testcase("AMMWithdraw can not create a holding for a blocked account");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const carol{"carol"};
        MPTTester mpt(env, gw, {.holders = {carol}});
        mpt.create({.flags = tfMPTCanLock | kMptDexFlags});
        auto const id = mpt.issuanceID();
        MPT const token = mpt;

        // carol becomes an LP with XRP only, so she never holds the token.
        AMM amm(env, gw, token(1'000), XRP(1'000));
        amm.deposit(carol, XRP(100));
        env.close();
        BEAST_EXPECT(!hasMPToken(env, carol, id));

        env(tokenBlock(gw, carol, id));
        env.close();

        // Neither a single-asset nor a full withdrawal can pay her the token.
        amm.withdraw(carol, token(10), std::nullopt, std::nullopt, Ter(tecTOKEN_BLOCKED));
        amm.withdrawAll(carol, std::nullopt, Ter(tecTOKEN_BLOCKED));
        BEAST_EXPECT(!hasMPToken(env, carol, id));

        // She can still take her share out in XRP.
        amm.withdrawAll(carol, XRP(0));
        BEAST_EXPECT(!hasMPToken(env, carol, id));
    }

    void
    testVaultWithdrawCannotBypass(FeatureBitset features)
    {
        testcase("VaultWithdraw can not create a holding for a blocked account");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        MPTTester mpt(env, gw, {.holders = {alice, bob, carol}});
        mpt.create({.flags = tfMPTCanLock | kMptDexFlags});
        auto const id = mpt.issuanceID();
        mpt.authorize({.account = alice});
        mpt.authorize({.account = bob});
        mpt.pay(gw, alice, 100);
        MPT const token = mpt;

        Vault const vault{env};
        auto [createTx, keylet] = vault.create({.owner = carol, .asset = token});
        env(createTx);
        env.close();

        // alice moves her whole balance into the vault, is blocked, and
        // deletes her now-empty MPToken.
        env(vault.deposit({.depositor = alice, .id = keylet.key, .amount = token(100)}));
        env.close();
        env(tokenBlock(gw, alice, id));
        env.close();
        mpt.authorize({.account = alice, .flags = tfMPTUnauthorize});
        BEAST_EXPECT(!hasMPToken(env, alice, id));

        // Redeeming her shares to herself would need a new holding.
        env(vault.withdraw({.depositor = alice, .id = keylet.key, .amount = token(10)}),
            Ter(tecTOKEN_BLOCKED));
        BEAST_EXPECT(!hasMPToken(env, alice, id));

        // Redeeming to another account that holds the token is not affected.
        auto tx = vault.withdraw({.depositor = alice, .id = keylet.key, .amount = token(10)});
        tx[sfDestination] = bob.human();
        env(tx);
        env.close();
        BEAST_EXPECT(mpt.getBalance(bob) == 10);
        BEAST_EXPECT(!hasMPToken(env, alice, id));
    }

    void
    testAMMClawbackBlockedHolder(FeatureBitset features)
    {
        testcase("AMMClawback still seizes from a blocked holder with no MPToken");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        MPTTester mpt(env, gw, {.holders = {alice}});
        mpt.create({.flags = tfMPTCanLock | tfMPTCanClawback | kMptDexFlags});
        auto const id = mpt.issuanceID();
        mpt.authorize({.account = alice});
        mpt.pay(gw, alice, 100);
        MPT const token = mpt;

        // alice moves her whole balance into an AMM pool ...
        AMM const amm(env, alice, token(100), XRP(100));
        env.close();
        BEAST_EXPECT(mpt.getBalance(alice) == 0);

        // ... is blocked, and deletes her now-empty, locked MPToken.
        env(tokenBlock(gw, alice, id));
        env.close();
        mpt.authorize({.account = alice, .flags = tfMPTUnauthorize});
        BEAST_EXPECT(!hasMPToken(env, alice, id));

        // The issuer can still claw back its token from the pool. The holding
        // recreated for that purpose is locked and, unlike for a holder that
        // is not blocked, not authorized.
        env(amm::ammClawback(gw, alice, MPTIssue{id}, xrpIssue(), std::nullopt));
        env.close();
        BEAST_EXPECT(isLocked(env, alice, id));
        BEAST_EXPECT(mpt.checkFlags(lsfMPTLocked, alice));
        BEAST_EXPECT(mpt.getBalance(alice) == 0);
    }

    void
    testDestroyedIssuanceCleanup(FeatureBitset features)
    {
        testcase("Entries of a destroyed issuance can still be removed");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        MPTTester mpt(env, gw, {.holders = {alice}});
        mpt.create({.flags = tfMPTCanLock});
        auto const id = mpt.issuanceID();

        env(tokenBlock(gw, alice, id));
        env.close();
        auto const owners = env.ownerCount(gw);

        mpt.destroy();
        BEAST_EXPECT(env.ownerCount(gw) == owners - 1);

        env(tokenPreauth(gw, alice, id), Ter(tecOBJECT_NOT_FOUND));
        env(tokenBlock(gw, alice, id, tfUnblock));
        env.close();
        BEAST_EXPECT(!isBlocked(env, alice, id));
        BEAST_EXPECT(env.ownerCount(gw) == owners - 2);
    }

    void
    testAccountDelete(FeatureBitset features)
    {
        testcase("TokenPreauth entries do not block account deletion");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        Account const bob{"bob"};
        MPTTester mpt(env, gw, {.holders = {alice, bob}});
        mpt.create({.flags = tfMPTCanLock});
        auto const id = mpt.issuanceID();

        env(tokenBlock(gw, alice, id));
        env(tokenPreauth(gw, bob, id));
        env.close();

        // While the issuance exists the issuer can not be deleted anyway.
        auto const acctDelFee = drops(env.current()->fees().increment);
        incLgrSeqForAccDel(env, gw);
        env(acctdelete(gw, alice), Fee(acctDelFee), Ter(tecHAS_OBLIGATIONS));
        env.close();

        // Once it is destroyed, the entries are cleaned up with the account.
        mpt.destroy();
        incLgrSeqForAccDel(env, gw);
        env(acctdelete(gw, alice), Fee(acctDelFee));
        env.close();
        BEAST_EXPECT(!env.le(keylet::account(gw)));
        BEAST_EXPECT(!isBlocked(env, alice, id));
        BEAST_EXPECT(!isPreauthorized(env, bob, id));

        // The holder never owned the entry, so it can be deleted regardless.
        Account const carol{"carol"};
        env.fund(XRP(1'000), carol);
        env.close();
        MPTTester m2(env, carol, {.holders = {bob}, .fund = false});
        m2.create({.flags = tfMPTCanLock});
        env(tokenBlock(carol, bob, m2.issuanceID()));
        env.close();
        // (bob's account is already old enough to delete.)
        env(acctdelete(bob, alice), Fee(acctDelFee));
        env.close();
        BEAST_EXPECT(!env.le(keylet::account(bob)));
        BEAST_EXPECT(isBlocked(env, bob, m2.issuanceID()));
    }

    void
    testReserve(FeatureBitset features)
    {
        testcase("Reserve");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        MPTTester mpt(env, gw, {.holders = {alice}, .xrp = XRP(10'000)});
        mpt.create({.flags = tfMPTCanLock});
        auto const id = mpt.issuanceID();

        // Leave gw just enough for its current reserve plus fees.
        auto const reserve = env.current()->fees().accountReserve(env.ownerCount(gw), 1);
        auto const baseFee = env.current()->fees().base;
        env(pay(gw, alice, env.balance(gw) - reserve - baseFee * 2));
        env.close();

        env(tokenBlock(gw, alice, id), Ter(tecINSUFFICIENT_RESERVE));
        env.close();
        BEAST_EXPECT(!isBlocked(env, alice, id));
    }

    void
    testDelegation(FeatureBitset features)
    {
        testcase("Delegation");
        using namespace jtx;

        // Transaction-level permissions: the delegate can perform every action
        // of the transactions it holds on the issuer's behalf; the issuer pays
        // the reserve, the delegate the fee.
        {
            Env env{*this, features};
            Account const gw{"gw"};
            Account const alice{"alice"};
            Account const ops{"ops"};
            MPTTester mpt(env, gw, {.holders = {alice}});
            mpt.create({.flags = tfMPTCanLock});
            auto const id = mpt.issuanceID();
            env.fund(XRP(1'000), ops);
            env.close();
            mpt.authorize({.account = alice});

            // No Delegate entry yet.
            env(tokenBlock(gw, alice, id), delegate::As(ops), Ter(terNO_DELEGATE_PERMISSION));
            env.close();

            // Permission over one transaction does not cover the other.
            env(delegate::set(gw, ops, {"TokenPreauth"}));
            env.close();
            env(tokenBlock(gw, alice, id), delegate::As(ops), Ter(terNO_DELEGATE_PERMISSION));
            env.close();

            env(delegate::set(gw, ops, {"TokenPreauth", "TokenBlock"}));
            env.close();

            auto const gwBalance = env.balance(gw);
            auto const opsBalance = env.balance(ops);
            auto const gwOwners = env.ownerCount(gw);
            auto const fee = env.current()->fees().base;

            env(tokenBlock(gw, alice, id), delegate::As(ops));
            env.close();
            BEAST_EXPECT(isBlocked(env, alice, id));
            BEAST_EXPECT(env.ownerCount(gw) == gwOwners + 1);
            BEAST_EXPECT(env.balance(gw) == gwBalance);
            BEAST_EXPECT(env.balance(ops) == opsBalance - fee);

            env(tokenBlock(gw, alice, id, tfUnblock), delegate::As(ops));
            env(tokenPreauth(gw, alice, id), delegate::As(ops));
            env.close();
            BEAST_EXPECT(!isBlocked(env, alice, id));
            BEAST_EXPECT(isPreauthorized(env, alice, id));

            env(tokenPreauth(gw, alice, id, tfUnauthorize), delegate::As(ops));
            env.close();
            BEAST_EXPECT(!isPreauthorized(env, alice, id));
            BEAST_EXPECT(env.ownerCount(gw) == gwOwners);
        }

        // The TokenBlockCreate granular permission lets an issuer hand
        // blocking to a compliance account without also letting it remove
        // blocks. It does not cover TokenPreauth.
        {
            Env env{*this, features};
            Account const gw{"gw"};
            Account const alice{"alice"};
            Account const ops{"ops"};
            MPTTester mpt(env, gw, {.holders = {alice}});
            mpt.create({.flags = tfMPTCanLock});
            auto const id = mpt.issuanceID();
            env.fund(XRP(1'000), ops);
            env.close();

            env(delegate::set(gw, ops, {"TokenBlockCreate"}));
            env.close();

            env(tokenBlock(gw, alice, id), delegate::As(ops));
            env.close();
            BEAST_EXPECT(isBlocked(env, alice, id));

            env(tokenBlock(gw, alice, id, tfUnblock),
                delegate::As(ops),
                Ter(terNO_DELEGATE_PERMISSION));
            env(tokenPreauth(gw, alice, id), delegate::As(ops), Ter(terNO_DELEGATE_PERMISSION));
            env(tokenPreauth(gw, alice, id, tfUnauthorize),
                delegate::As(ops),
                Ter(terNO_DELEGATE_PERMISSION));
            env.close();
            BEAST_EXPECT(isBlocked(env, alice, id));

            // Removing the block takes the issuer, or the transaction-level
            // TokenBlock permission.
            env(tokenBlock(gw, alice, id, tfUnblock));
            env.close();
            BEAST_EXPECT(!isBlocked(env, alice, id));
            env(delegate::set(gw, ops, {"TokenBlockCreate", "TokenBlock"}));
            env.close();
            env(tokenBlock(gw, alice, id), delegate::As(ops));
            env(tokenBlock(gw, alice, id, tfUnblock), delegate::As(ops));
            env.close();
            BEAST_EXPECT(!isBlocked(env, alice, id));
        }

        // A delegate acts only for the account that granted it: it can not
        // act for an issuer it holds no permission from.
        {
            Env env{*this, features};
            Account const gw{"gw"};
            Account const gw2{"gw2"};
            Account const alice{"alice"};
            Account const ops{"ops"};
            MPTTester mpt(env, gw2, {.holders = {alice}});
            mpt.create({.flags = tfMPTCanLock});
            env.fund(XRP(1'000), gw, ops);
            env.close();

            env(delegate::set(gw, ops, {"TokenPreauth", "TokenBlock"}));
            env.close();

            env(tokenBlock(gw2, alice, mpt.issuanceID()),
                delegate::As(ops),
                Ter(terNO_DELEGATE_PERMISSION));
            env.close();
            BEAST_EXPECT(!isBlocked(env, alice, mpt.issuanceID()));
        }
    }

    void
    testRPC(FeatureBitset features)
    {
        testcase("ledger_entry and account_objects");
        using namespace jtx;

        Env env{*this, features};
        Account const gw{"gw"};
        Account const alice{"alice"};
        MPTTester mpt(env, gw, {.holders = {alice}});
        mpt.create({.flags = tfMPTCanLock});
        auto const id = mpt.issuanceID();

        Account const bob{"bob"};
        env.fund(XRP(1'000), bob);
        env(tokenBlock(gw, alice, id));
        env(tokenPreauth(gw, bob, id));
        env.close();
        auto const blockIndex = to_string(keylet::tokenBlock(alice, id).key);
        auto const preauthIndex = to_string(keylet::tokenPreauth(bob, id).key);

        auto const byKey = [&](json::StaticString const& type, Account const& holder) {
            json::Value params;
            params[jss::ledger_index] = jss::validated;
            params[type][jss::holder] = holder.human();
            params[type][jss::mpt_issuance_id] = to_string(id);
            return env.rpc("json", "ledger_entry", to_string(params))[jss::result];
        };

        // By business key: {holder, mpt_issuance_id}.
        {
            auto const jrr = byKey(jss::token_block, alice);
            BEAST_EXPECT(jrr[jss::index].asString() == blockIndex);
            BEAST_EXPECT(jrr[jss::node][sfLedgerEntryType.jsonName] == jss::TokenBlock);
            BEAST_EXPECT(jrr[jss::node][sfHolder.jsonName] == alice.human());
        }
        {
            auto const jrr = byKey(jss::token_preauth, bob);
            BEAST_EXPECT(jrr[jss::index].asString() == preauthIndex);
            BEAST_EXPECT(jrr[jss::node][sfLedgerEntryType.jsonName] == jss::TokenPreauth);
            BEAST_EXPECT(jrr[jss::node][sfHolder.jsonName] == bob.human());
        }

        // By index.
        {
            json::Value params;
            params[jss::ledger_index] = jss::validated;
            params[jss::token_block] = blockIndex;
            auto const jrr = env.rpc("json", "ledger_entry", to_string(params))[jss::result];
            BEAST_EXPECT(jrr[jss::node][sfLedgerEntryType.jsonName] == jss::TokenBlock);
        }

        // Wrong type, or the issuer as holder -> entryNotFound.
        BEAST_EXPECT(byKey(jss::token_preauth, alice)[jss::error] == "entryNotFound");
        BEAST_EXPECT(byKey(jss::token_block, bob)[jss::error] == "entryNotFound");
        BEAST_EXPECT(byKey(jss::token_block, gw)[jss::error] == "entryNotFound");

        // Missing holder -> malformed.
        {
            json::Value params;
            params[jss::ledger_index] = jss::validated;
            params[jss::token_block][jss::mpt_issuance_id] = to_string(id);
            auto const jrr = env.rpc("json", "ledger_entry", to_string(params))[jss::result];
            BEAST_EXPECT(jrr[jss::error] == "malformedRequest");
        }

        // The issuer's block list and pre-authorization list via
        // account_objects.
        for (auto const& [type, index] :
             {std::pair{jss::token_block, blockIndex}, std::pair{jss::token_preauth, preauthIndex}})
        {
            json::Value params;
            params[jss::account] = gw.human();
            params[jss::type] = type;
            auto const jrr = env.rpc("json", "account_objects", to_string(params))[jss::result];
            BEAST_EXPECT(jrr[jss::account_objects].size() == 1);
            BEAST_EXPECT(jrr[jss::account_objects][0u][jss::index].asString() == index);
        }
    }

public:
    void
    run() override
    {
        FeatureBitset const all{jtx::testableAmendments()};
        testDisabled(all);
        testPreflight(all);
        testPreclaim(all);
        testStateMachine(all);
        testBlockOptIn(all);
        testBlockBeforeAccountExists(all);
        testBlockExistingHolder(all);
        testBlockedHolderCanExit(all);
        testRequireAuth(all);
        testPermissionlessPreauthIsNoop(all);
        testDexCannotBypass(all);
        testCheckCannotBypass(all);
        testEscrowCannotBypass(all);
        testAMMWithdrawCannotBypass(all);
        testVaultWithdrawCannotBypass(all);
        testAMMClawbackBlockedHolder(all);
        testDestroyedIssuanceCleanup(all);
        testAccountDelete(all);
        testReserve(all);
        testDelegation(all);
        testRPC(all);
    }
};

BEAST_DEFINE_TESTSUITE(TokenPreauth, app, xrpl);

}  // namespace xrpl::test
