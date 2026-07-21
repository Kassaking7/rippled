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
TransactionProposalSign::visitInvariantEntry(bool, SLE::const_ref, SLE::const_ref)
{
    // No transaction-specific invariants yet (future work).
}

bool
TransactionProposalSign::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    // No transaction-specific invariants yet (future work).
    return true;
}

}  // namespace xrpl
