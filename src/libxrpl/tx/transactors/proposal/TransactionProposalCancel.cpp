#include <xrpl/tx/transactors/proposal/TransactionProposalCancel.h>

#include <xrpl/basics/Log.h>
#include <xrpl/beast/utility/Zero.h>
#include <xrpl/core/ServiceRegistry.h>
#include <xrpl/ledger/ApplyView.h>
#include <xrpl/ledger/View.h>
#include <xrpl/ledger/helpers/AccountRootHelpers.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/Transactor.h>
#include <xrpl/tx/transactors/proposal/ProposalHelpers.h>

#include <cstdint>

namespace xrpl {

NotTEC
TransactionProposalCancel::preflight(PreflightContext const& ctx)
{
    if (ctx.tx[sfProposalID] == beast::kZero)
    {
        JLOG(ctx.j.debug()) << "TransactionProposalCancel: zero ProposalID.";
        return temMALFORMED;
    }

    return tesSUCCESS;
}

TER
TransactionProposalCancel::preclaim(PreclaimContext const& ctx)
{
    auto const sleProposal = ctx.view.read(keylet::txProposal(ctx.tx[sfProposalID]));
    if (!sleProposal)
    {
        JLOG(ctx.j.debug()) << "TransactionProposalCancel: no such proposal.";
        return tecNO_ENTRY;
    }

    // While the proposal is live only the owner may cancel it; once it is
    // terminal anyone may clean it up and release the owner's reserve.
    if (!isProposalTerminal(ctx.view, sleProposal) && ctx.tx[sfAccount] != (*sleProposal)[sfOwner])
    {
        JLOG(ctx.j.debug()) << "TransactionProposalCancel: proposal is live "
                               "and canceler is not the owner.";
        return tecNO_PERMISSION;
    }

    return tesSUCCESS;
}

TER
TransactionProposalCancel::doApply()
{
    auto const sleProposal = view().peek(keylet::txProposal(ctx_.tx[sfProposalID]));
    if (!sleProposal)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    AccountID const owner = sleProposal->getAccountID(sfOwner);
    auto viewJ = ctx_.registry.get().getJournal("View");

    {
        std::uint64_t const page{(*sleProposal)[sfOwnerNode]};
        if (!view().dirRemove(keylet::ownerDir(owner), page, sleProposal->key(), true))
        {
            // LCOV_EXCL_START
            JLOG(j_.fatal()) << "Unable to delete proposal from owner directory.";
            return tefBAD_LEDGER;
            // LCOV_EXCL_STOP
        }
    }

    auto const raw = sleProposal->getFieldObject(sfRawTransaction);
    decreaseOwnerCountForObject(view(), owner, sleProposal, proposalOwnerCount(raw), viewJ);

    view().erase(sleProposal);
    return tesSUCCESS;
}

void
TransactionProposalCancel::visitInvariantEntry(
    bool isDelete,
    SLE::const_ref before,
    SLE::const_ref after)
{
    auto const& entry = after ? after : before;
    if (!entry || entry->getType() != ltTRANSACTION_PROPOSAL)
        return;

    if (isDelete)
        ++deletedProposals_;
    else
        ++otherProposalTouches_;
}

bool
TransactionProposalCancel::finalizeInvariants(
    STTx const&,
    TER result,
    XRPAmount,
    ReadView const&,
    beast::Journal const& j)
{
    if (!isTesSuccess(result))
    {
        // A failed cancel claims a fee and nothing else.
        if (deletedProposals_ != 0 || otherProposalTouches_ != 0)
        {
            JLOG(j.fatal()) << "Invariant failed: failed TransactionProposalCancel "
                               "touched a proposal.";  // LCOV_EXCL_LINE
            return false;                              // LCOV_EXCL_LINE
        }
        return true;
    }

    if (deletedProposals_ != 1 || otherProposalTouches_ != 0)
    {
        JLOG(j.fatal()) << "Invariant failed: TransactionProposalCancel must "
                           "delete exactly one proposal.";  // LCOV_EXCL_LINE
        return false;                                       // LCOV_EXCL_LINE
    }

    return true;
}

}  // namespace xrpl
