#include <xrpl/tx/transactors/proposal/TransactionProposalSign.h>

#include <xrpl/basics/Log.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/beast/utility/Zero.h>
#include <xrpl/ledger/ApplyView.h>
#include <xrpl/ledger/View.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/PublicKey.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STArray.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STObject.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/Sign.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/SignerEntries.h>
#include <xrpl/tx/Transactor.h>
#include <xrpl/tx/transactors/proposal/ProposalHelpers.h>

#include <algorithm>
#include <cstdint>

namespace xrpl {

// The maximum number of entries in a SignerList, and therefore the most
// signatures a proposal can ever usefully collect for one account.
static constexpr std::size_t kMaxProposalSigners = 32;

NotTEC
TransactionProposalSign::preflight(PreflightContext const& ctx)
{
    if (ctx.tx[sfProposalID] == beast::kZero)
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: zero ProposalID.";
        return temMALFORMED;
    }

    auto const signerObj = ctx.tx.getFieldObject(sfSigner);
    if (!signerObj.isFieldPresent(sfAccount) || !signerObj.isFieldPresent(sfSigningPubKey) ||
        !signerObj.isFieldPresent(sfTxnSignature))
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: malformed Signer.";
        return temMALFORMED;
    }

    if (signerObj.getFieldVL(sfSigningPubKey).empty() ||
        signerObj.getFieldVL(sfTxnSignature).empty())
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: empty key or signature.";
        return temMALFORMED;
    }

    // Each collected signature is tied to a deliberate on-ledger act by the
    // signer itself: the signer must submit (and pay for) this transaction.
    if (signerObj.getAccountID(sfAccount) != ctx.tx[sfAccount])
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: submitter is not "
                               "the contributing signer.";
        return temMALFORMED;
    }

    return tesSUCCESS;
}

TER
TransactionProposalSign::preclaim(PreclaimContext const& ctx)
{
    auto const sleProposal = ctx.view.read(keylet::txProposal(ctx.tx[sfProposalID]));
    if (!sleProposal)
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: no such proposal.";
        return tecNO_ENTRY;
    }

    // A terminal proposal no longer accepts signatures. (It stays in ledger
    // state until cancelled; anyone may cancel a terminal proposal.)
    if (isProposalTerminal(ctx.view, sleProposal))
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: proposal is terminal.";
        return tecEXPIRED;
    }

    auto const raw = sleProposal->getFieldObject(sfRawTransaction);
    auto const signerObj = ctx.tx.getFieldObject(sfSigner);
    AccountID const signerID = signerObj.getAccountID(sfAccount);

    // The account whose signing authority the collected signatures express:
    // the Delegate for a delegated transaction, else the target account.
    AccountID const authorized =
        raw.isFieldPresent(sfDelegate) ? raw.getAccountID(sfDelegate) : raw.getAccountID(sfAccount);

    // Membership: the signer must be on the authorized account's SignerList.
    auto const sleList = ctx.view.read(keylet::signerList(authorized));
    if (!sleList)
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: authorized account "
                               "has no SignerList.";
        return tecNO_PERMISSION;
    }
    auto const entries = SignerEntries::deserialize(*sleList, ctx.j, "ledger");
    if (!entries)
        return tefBAD_LEDGER;  // LCOV_EXCL_LINE
    if (std::ranges::none_of(
            *entries, [&signerID](auto const& entry) { return entry.account == signerID; }))
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: signer is not on "
                               "the SignerList.";
        return tecNO_PERMISSION;
    }

    // Key binding, mirroring Transactor::checkMultiSign: the public key must
    // be the signer's master key (unless disabled) or its regular key;
    // phantom accounts sign with their master key.
    auto const spk = signerObj.getFieldVL(sfSigningPubKey);
    if (!publicKeyType(makeSlice(spk)))
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: unknown key type.";
        return tefBAD_SIGNATURE;
    }
    AccountID const signingAcctIDFromPubKey = calcAccountID(PublicKey(makeSlice(spk)));
    auto const sleSignerRoot = ctx.view.read(keylet::account(signerID));
    if (signingAcctIDFromPubKey == signerID)
    {
        if (sleSignerRoot && ((sleSignerRoot->getFieldU32(sfFlags) & lsfDisableMaster) != 0u))
        {
            JLOG(ctx.j.debug()) << "TransactionProposalSign: master key disabled.";
            return tefMASTER_DISABLED;
        }
    }
    else
    {
        if (!sleSignerRoot || !sleSignerRoot->isFieldPresent(sfRegularKey) ||
            signingAcctIDFromPubKey != sleSignerRoot->getAccountID(sfRegularKey))
        {
            JLOG(ctx.j.debug()) << "TransactionProposalSign: key does not "
                                   "match master or regular key.";
            return tefBAD_SIGNATURE;
        }
    }

    // The signature must be valid over the stored transaction's standard
    // multi-sign signing data for this signer, exactly as it would be
    // validated on a directly-submitted multi-signed transaction.
    Serializer const signingData = buildMultiSigningData(raw, signerID);
    if (!verify(
            PublicKey(makeSlice(spk)),
            signingData.slice(),
            makeSlice(signerObj.getFieldVL(sfTxnSignature))))
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: invalid signature "
                               "over the proposed transaction.";
        return tefBAD_SIGNATURE;
    }

    if (raw.isFieldPresent(sfSigners))
    {
        auto const& signers = raw.getFieldArray(sfSigners);
        for (auto const& entry : signers)
        {
            if (entry.getAccountID(sfAccount) == signerID)
            {
                JLOG(ctx.j.debug()) << "TransactionProposalSign: signer "
                                       "already recorded.";
                return tecDUPLICATE;
            }
        }
        if (signers.size() >= kMaxProposalSigners)
            return tecOVERSIZE;
    }

    return tesSUCCESS;
}

TER
TransactionProposalSign::doApply()
{
    auto const sleProposal = view().peek(keylet::txProposal(ctx_.tx[sfProposalID]));
    if (!sleProposal)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    auto raw = sleProposal->getFieldObject(sfRawTransaction);
    auto const signerObj = ctx_.tx.getFieldObject(sfSigner);

    STArray signers =
        raw.isFieldPresent(sfSigners) ? raw.getFieldArray(sfSigners) : STArray{sfSigners};

    STObject entry{sfSigner};
    entry.setAccountID(sfAccount, signerObj.getAccountID(sfAccount));
    entry.setFieldVL(sfSigningPubKey, signerObj.getFieldVL(sfSigningPubKey));
    entry.setFieldVL(sfTxnSignature, signerObj.getFieldVL(sfTxnSignature));
    signers.push_back(std::move(entry));

    // The Signers array of a multi-signed transaction must be sorted by
    // account, so the stored transaction stays submittable verbatim.
    std::sort(signers.begin(), signers.end(), [](STObject const& lhs, STObject const& rhs) {
        return lhs.getAccountID(sfAccount) < rhs.getAccountID(sfAccount);
    });

    raw.setFieldArray(sfSigners, signers);
    sleProposal->setFieldObject(sfRawTransaction, raw);
    view().update(sleProposal);

    return tesSUCCESS;
}

void
TransactionProposalSign::visitInvariantEntry(
    bool isDelete,
    SLE::const_ref before,
    SLE::const_ref after)
{
    auto const& entry = after ? after : before;
    if (!entry || entry->getType() != ltTRANSACTION_PROPOSAL)
        return;

    if (!isDelete && before && after)
    {
        ++modifiedProposals_;
        proposalBefore_ = before;
        proposalAfter_ = after;
    }
    else
    {
        ++otherProposalTouches_;
    }
}

bool
TransactionProposalSign::finalizeInvariants(
    STTx const& tx,
    TER result,
    XRPAmount,
    ReadView const&,
    beast::Journal const& j)
{
    if (!isTesSuccess(result))
    {
        // A failed sign claims a fee and nothing else.
        if (modifiedProposals_ != 0 || otherProposalTouches_ != 0)
        {
            JLOG(j.fatal()) << "Invariant failed: failed TransactionProposalSign "
                               "touched a proposal.";  // LCOV_EXCL_LINE
            return false;                              // LCOV_EXCL_LINE
        }
        return true;
    }

    if (modifiedProposals_ != 1 || otherProposalTouches_ != 0 || !proposalBefore_ ||
        !proposalAfter_)
    {
        JLOG(j.fatal()) << "Invariant failed: TransactionProposalSign must "
                           "modify exactly one proposal.";  // LCOV_EXCL_LINE
        return false;                                       // LCOV_EXCL_LINE
    }

    // Everything outside the stored transaction's Signers array is immutable.
    if ((*proposalBefore_)[sfOwner] != (*proposalAfter_)[sfOwner] ||
        (*proposalBefore_)[sfExpiration] != (*proposalAfter_)[sfExpiration] ||
        (*proposalBefore_)[sfOwnerNode] != (*proposalAfter_)[sfOwnerNode])
    {
        JLOG(j.fatal()) << "Invariant failed: TransactionProposalSign changed "
                           "an immutable proposal field.";  // LCOV_EXCL_LINE
        return false;                                       // LCOV_EXCL_LINE
    }

    STObject rawBefore = proposalBefore_->getFieldObject(sfRawTransaction);
    STObject rawAfter = proposalAfter_->getFieldObject(sfRawTransaction);

    STArray const beforeSigners = rawBefore.isFieldPresent(sfSigners)
        ? rawBefore.getFieldArray(sfSigners)
        : STArray{sfSigners};
    STArray const afterSigners =
        rawAfter.isFieldPresent(sfSigners) ? rawAfter.getFieldArray(sfSigners) : STArray{sfSigners};

    if (rawBefore.isFieldPresent(sfSigners))
        rawBefore.makeFieldAbsent(sfSigners);
    if (rawAfter.isFieldPresent(sfSigners))
        rawAfter.makeFieldAbsent(sfSigners);
    Serializer sb, sa;
    rawBefore.add(sb);
    rawAfter.add(sa);
    if (sb.peekData() != sa.peekData())
    {
        JLOG(j.fatal()) << "Invariant failed: TransactionProposalSign changed "
                           "the stored transaction outside Signers.";  // LCOV_EXCL_LINE
        return false;                                                  // LCOV_EXCL_LINE
    }

    // Exactly the submitted contribution was appended; the array stays
    // strictly sorted (thus duplicate-free) and within the size cap.
    if (afterSigners.size() != beforeSigners.size() + 1 ||
        afterSigners.size() > kMaxProposalSigners)
    {
        JLOG(j.fatal()) << "Invariant failed: Signers array did not grow by "
                           "exactly one entry.";  // LCOV_EXCL_LINE
        return false;                             // LCOV_EXCL_LINE
    }

    AccountID const contributed = tx.getFieldObject(sfSigner).getAccountID(sfAccount);
    bool foundContributed = false;
    for (std::size_t i = 0; i < afterSigners.size(); ++i)
    {
        if (i > 0 &&
            !(afterSigners[i - 1].getAccountID(sfAccount) <
              afterSigners[i].getAccountID(sfAccount)))
        {
            JLOG(j.fatal()) << "Invariant failed: Signers array is not "
                               "strictly sorted by account.";  // LCOV_EXCL_LINE
            return false;                                      // LCOV_EXCL_LINE
        }
        if (afterSigners[i].getAccountID(sfAccount) == contributed)
            foundContributed = true;
    }
    if (!foundContributed)
    {
        JLOG(j.fatal()) << "Invariant failed: submitted contribution is not "
                           "in the Signers array.";  // LCOV_EXCL_LINE
        return false;                                // LCOV_EXCL_LINE
    }

    // Every previously collected contribution survives byte-for-byte.
    for (auto const& b : beforeSigners)
    {
        bool const survives = std::ranges::any_of(afterSigners, [&b](STObject const& a) {
            Serializer s1, s2;
            b.add(s1);
            a.add(s2);
            return s1.peekData() == s2.peekData();
        });
        if (!survives)
        {
            JLOG(j.fatal()) << "Invariant failed: a collected signature was "
                               "dropped or altered.";  // LCOV_EXCL_LINE
            return false;                              // LCOV_EXCL_LINE
        }
    }

    return true;
}

}  // namespace xrpl
