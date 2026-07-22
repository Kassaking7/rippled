#include <xrpl/tx/transactors/proposal/TransactionProposalSign.h>

#include <xrpl/basics/Log.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/beast/utility/Zero.h>
#include <xrpl/ledger/ApplyView.h>
#include <xrpl/ledger/View.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/HashPrefix.h>
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

// The single account that authorizes the proposed transaction's main slot:
// the Delegate for a delegated transaction, else the transaction's Account.
// v1 supported only this slot; the Counterparty/Sponsor/Batch-participant
// slots of the XLS SigningFor model are deferred (see class docs).
static AccountID
authorizedAccount(STObject const& raw)
{
    return raw.isFieldPresent(sfDelegate) ? raw.getAccountID(sfDelegate)
                                          : raw.getAccountID(sfAccount);
}

// Build the signing data a single-signature contribution must cover: the
// standard transaction signing data over the proposed transaction with its
// SigningPubKey populated to the contributed key, exactly as a directly
// single-signed submission would compute it.
static Serializer
buildSingleSigningData(STObject const& raw, Blob const& spk)
{
    STObject signable = raw;
    signable.setFieldVL(sfSigningPubKey, spk);
    Serializer s;
    s.add32(HashPrefix::TxSign);
    signable.addWithoutSigningFields(s);
    return s;
}

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
    // The submitting Account and SigningFor together decide single- vs
    // multi-signature (§6.1.2), so the contribution names its own signer.
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
    AccountID const signingFor = ctx.tx[sfSigningFor];

    // SigningFor must name an account the proposed transaction requires a
    // signature from. v1 recognizes the main authorization slot only.
    AccountID const authorized = authorizedAccount(raw);
    if (signingFor != authorized)
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: SigningFor is not the "
                               "authorized account for this proposal.";
        return tecNO_PERMISSION;
    }

    auto const spk = signerObj.getFieldVL(sfSigningPubKey);
    if (!publicKeyType(makeSlice(spk)))
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: unknown key type.";
        return tefBAD_SIGNATURE;
    }

    // Mode is derived, not flagged: signing for oneself is a single
    // signature; signing for another account is a multi-signature share.
    bool const singleSign = (signerID == signingFor);

    // A single-signature entry and multi-signature shares are mutually
    // exclusive for one slot: the presence of one bars the other.
    bool const haveSingle = !raw.getFieldVL(sfSigningPubKey).empty();
    bool const haveShares = raw.isFieldPresent(sfSigners);

    if (singleSign)
    {
        if (haveShares)
        {
            JLOG(ctx.j.debug()) << "TransactionProposalSign: single-signature "
                                   "conflicts with recorded shares.";
            return tecNO_PERMISSION;
        }
        if (haveSingle)
        {
            JLOG(ctx.j.debug()) << "TransactionProposalSign: single-signature "
                                   "already recorded.";
            return tecDUPLICATE;
        }

        // Key binding: the key must be SigningFor's master key (unless
        // disabled) or its regular key, mirroring Transactor::checkSingleSign.
        AccountID const fromPubKey = calcAccountID(PublicKey(makeSlice(spk)));
        auto const sleRoot = ctx.view.read(keylet::account(signingFor));
        if (fromPubKey == signingFor)
        {
            if (sleRoot && ((sleRoot->getFieldU32(sfFlags) & lsfDisableMaster) != 0u))
            {
                JLOG(ctx.j.debug()) << "TransactionProposalSign: master key disabled.";
                return tefMASTER_DISABLED;
            }
        }
        else if (
            !sleRoot || !sleRoot->isFieldPresent(sfRegularKey) ||
            fromPubKey != sleRoot->getAccountID(sfRegularKey))
        {
            JLOG(ctx.j.debug()) << "TransactionProposalSign: key does not match "
                                   "SigningFor's master or regular key.";
            return tefBAD_SIGNATURE;
        }

        Serializer const data = buildSingleSigningData(raw, spk);
        if (!verify(
                PublicKey(makeSlice(spk)),
                data.slice(),
                makeSlice(signerObj.getFieldVL(sfTxnSignature))))
        {
            JLOG(ctx.j.debug()) << "TransactionProposalSign: invalid single "
                                   "signature over the proposed transaction.";
            return tefBAD_SIGNATURE;
        }

        return tesSUCCESS;
    }

    // Multi-signature share for signingFor.
    if (haveSingle)
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: multi-signature share "
                               "conflicts with a recorded single signature.";
        return tecNO_PERMISSION;
    }

    // Membership: the submitter must be on SigningFor's SignerList.
    auto const sleList = ctx.view.read(keylet::signerList(signingFor));
    if (!sleList)
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: SigningFor has no "
                               "SignerList.";
        return tecNO_PERMISSION;
    }
    auto const entries = SignerEntries::deserialize(*sleList, ctx.j, "ledger");
    if (!entries)
        return tefBAD_LEDGER;  // LCOV_EXCL_LINE
    if (std::ranges::none_of(
            *entries, [&signerID](auto const& entry) { return entry.account == signerID; }))
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: signer is not on "
                               "SigningFor's SignerList.";
        return tecNO_PERMISSION;
    }

    // Key binding for the share, mirroring Transactor::checkMultiSign.
    AccountID const fromPubKey = calcAccountID(PublicKey(makeSlice(spk)));
    auto const sleSignerRoot = ctx.view.read(keylet::account(signerID));
    if (fromPubKey == signerID)
    {
        if (sleSignerRoot && ((sleSignerRoot->getFieldU32(sfFlags) & lsfDisableMaster) != 0u))
        {
            JLOG(ctx.j.debug()) << "TransactionProposalSign: master key disabled.";
            return tefMASTER_DISABLED;
        }
    }
    else if (
        !sleSignerRoot || !sleSignerRoot->isFieldPresent(sfRegularKey) ||
        fromPubKey != sleSignerRoot->getAccountID(sfRegularKey))
    {
        JLOG(ctx.j.debug()) << "TransactionProposalSign: key does not match "
                               "master or regular key.";
        return tefBAD_SIGNATURE;
    }

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

    if (haveShares)
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
    bool const singleSign = (signerObj.getAccountID(sfAccount) == ctx_.tx[sfSigningFor]);

    if (singleSign)
    {
        // The single signature authorizes the slot directly: it fills the
        // stored transaction's top-level SigningPubKey/TxnSignature, leaving
        // it a fully single-signed transaction.
        raw.setFieldVL(sfSigningPubKey, signerObj.getFieldVL(sfSigningPubKey));
        raw.setFieldVL(sfTxnSignature, signerObj.getFieldVL(sfTxnSignature));
    }
    else
    {
        STArray signers =
            raw.isFieldPresent(sfSigners) ? raw.getFieldArray(sfSigners) : STArray{sfSigners};

        STObject entry{sfSigner};
        entry.setAccountID(sfAccount, signerObj.getAccountID(sfAccount));
        entry.setFieldVL(sfSigningPubKey, signerObj.getFieldVL(sfSigningPubKey));
        entry.setFieldVL(sfTxnSignature, signerObj.getFieldVL(sfTxnSignature));
        signers.push_back(std::move(entry));

        // The Signers array of a multi-signed transaction must be sorted by
        // account, so the stored transaction stays submittable verbatim.
        std::ranges::sort(signers, [](STObject const& lhs, STObject const& rhs) {
            return lhs.getAccountID(sfAccount) < rhs.getAccountID(sfAccount);
        });

        raw.setFieldArray(sfSigners, signers);
    }

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

    // Everything outside the stored transaction's signature slots is
    // immutable.
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

    Blob const spkBefore = rawBefore.getFieldVL(sfSigningPubKey);
    Blob const spkAfter = rawAfter.getFieldVL(sfSigningPubKey);
    STArray const beforeSigners = rawBefore.isFieldPresent(sfSigners)
        ? rawBefore.getFieldArray(sfSigners)
        : STArray{sfSigners};
    STArray const afterSigners =
        rawAfter.isFieldPresent(sfSigners) ? rawAfter.getFieldArray(sfSigners) : STArray{sfSigners};

    // Compare the stored transaction with all three signature-bearing fields
    // stripped; only these may change, and only in the ways checked below.
    auto stripSignatureFields = [](STObject& obj) {
        obj.setFieldVL(sfSigningPubKey, Blob{});
        if (obj.isFieldPresent(sfTxnSignature))
            obj.makeFieldAbsent(sfTxnSignature);
        if (obj.isFieldPresent(sfSigners))
            obj.makeFieldAbsent(sfSigners);
    };
    STObject restBefore = rawBefore;
    STObject restAfter = rawAfter;
    stripSignatureFields(restBefore);
    stripSignatureFields(restAfter);
    Serializer sb, sa;
    restBefore.add(sb);
    restAfter.add(sa);
    if (sb.peekData() != sa.peekData())
    {
        JLOG(j.fatal()) << "Invariant failed: TransactionProposalSign changed "
                           "the stored transaction outside its signature "
                           "fields.";  // LCOV_EXCL_LINE
        return false;                  // LCOV_EXCL_LINE
    }

    STObject const contribution = tx.getFieldObject(sfSigner);
    bool const singleSign = contribution.getAccountID(sfAccount) == tx[sfSigningFor];

    if (singleSign)
    {
        // A single signature fills the previously empty top-level slot with
        // exactly the submitted key and signature, and touches no Signers
        // array (the mode conflict is barred in preclaim).
        bool const filledSlot = spkBefore.empty() && !rawBefore.isFieldPresent(sfTxnSignature) &&
            !spkAfter.empty() && spkAfter == contribution.getFieldVL(sfSigningPubKey) &&
            rawAfter.isFieldPresent(sfTxnSignature) &&
            rawAfter.getFieldVL(sfTxnSignature) == contribution.getFieldVL(sfTxnSignature);
        if (!filledSlot || !beforeSigners.empty() || !afterSigners.empty())
        {
            JLOG(j.fatal()) << "Invariant failed: single signature did not "
                               "fill the top-level slot cleanly.";  // LCOV_EXCL_LINE
            return false;                                           // LCOV_EXCL_LINE
        }
        return true;
    }

    // A multi-signature share leaves the top-level slot empty and appends
    // exactly the submitted contribution, keeping the array strictly sorted
    // (thus duplicate-free) and within the size cap.
    if (!spkAfter.empty() || rawAfter.isFieldPresent(sfTxnSignature))
    {
        JLOG(j.fatal()) << "Invariant failed: multi-signature share set the "
                           "top-level signature slot.";  // LCOV_EXCL_LINE
        return false;                                    // LCOV_EXCL_LINE
    }
    if (afterSigners.size() != beforeSigners.size() + 1 ||
        afterSigners.size() > kMaxProposalSigners)
    {
        JLOG(j.fatal()) << "Invariant failed: Signers array did not grow by "
                           "exactly one entry.";  // LCOV_EXCL_LINE
        return false;                             // LCOV_EXCL_LINE
    }

    AccountID const contributed = contribution.getAccountID(sfAccount);
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
